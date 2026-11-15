package http

import (
	"context"
	"net"
	"net/http"
	"os"
	"strings"

	"github.com/sagernet/sing-box/adapter"
	"github.com/sagernet/sing-box/adapter/outbound"
	"github.com/sagernet/sing-box/common/dialer"
	"github.com/sagernet/sing-box/common/tls"
	C "github.com/sagernet/sing-box/constant"
	"github.com/sagernet/sing-box/log"
	"github.com/sagernet/sing-box/option"
	"github.com/sagernet/sing/common"
	E "github.com/sagernet/sing/common/exceptions"
	"github.com/sagernet/sing/common/logger"
	M "github.com/sagernet/sing/common/metadata"
	N "github.com/sagernet/sing/common/network"
	sHTTP "github.com/sagernet/sing/protocol/http"
)

func RegisterOutbound(registry *outbound.Registry) {
	outbound.Register[option.HTTPOutboundOptions](registry, C.TypeHTTP, NewOutbound)
}

type Outbound struct {
	outbound.Adapter
	logger                  logger.ContextLogger
	client                  *sHTTP.Client
	clientOptions           sHTTP.Options
	sendOriginalDestination bool
}

const originalDestinationHeader = "X-Infra-Original-Destination"

func NewOutbound(ctx context.Context, router adapter.Router, logger log.ContextLogger, tag string, options option.HTTPOutboundOptions) (adapter.Outbound, error) {
	outboundDialer, err := dialer.New(ctx, options.DialerOptions, options.ServerIsDomain())
	if err != nil {
		return nil, err
	}
	detour, err := tls.NewDialerFromOptions(ctx, logger, outboundDialer, options.Server, common.PtrValueOrDefault(options.TLS))
	if err != nil {
		return nil, err
	}
	if options.SendOriginalDestination {
		for key := range options.Headers {
			if strings.EqualFold(key, originalDestinationHeader) {
				return nil, E.New("reserved HTTP outbound header: ", key)
			}
		}
	}
	clientOptions := sHTTP.Options{
		Dialer:   detour,
		Server:   options.ServerOptions.Build(),
		Username: options.Username,
		Password: options.Password,
		Path:     options.Path,
		Headers:  options.Headers.Build(),
	}
	// NewClient removes Host from the supplied header map. Preserve the
	// original options for independently constructed CONNECT clients.
	stockOptions := clientOptions
	stockOptions.Headers = clientOptions.Headers.Clone()
	return &Outbound{
		Adapter:                 outbound.NewAdapterWithDialerOptions(C.TypeHTTP, tag, []string{N.NetworkTCP}, options.DialerOptions),
		logger:                  logger,
		client:                  sHTTP.NewClient(stockOptions),
		clientOptions:           clientOptions,
		sendOriginalDestination: options.SendOriginalDestination,
	}, nil
}

func (h *Outbound) DialContext(ctx context.Context, network string, destination M.Socksaddr) (net.Conn, error) {
	client := h.client
	if h.sendOriginalDestination {
		metadata := adapter.ContextFrom(ctx)
		if network != N.NetworkTCP || metadata == nil || !metadata.OriginDestination.Addr.Is4() || metadata.OriginDestination.Addr.IsUnspecified() || metadata.OriginDestination.Addr.IsMulticast() || metadata.OriginDestination.Addr.String() == "255.255.255.255" || metadata.OriginDestination.Port != 443 || metadata.OriginDestination.Fqdn != "" {
			return nil, E.New("HTTP CONNECT requires an original IPv4:443 destination")
		}
		// The dependency's constructor removes Host from its headers. Clone all
		// headers before constructing a request-scoped client; never mutate the
		// shared client or caller's option map across concurrent connections.
		clientOptions := h.clientOptions
		clientOptions.Headers = http.Header(h.clientOptions.Headers).Clone()
		clientOptions.Headers.Set(originalDestinationHeader, metadata.OriginDestination.String())
		client = sHTTP.NewClient(clientOptions)
	}
	ctx, metadata := adapter.ExtendContext(ctx)
	metadata.Outbound = h.Tag()
	metadata.Destination = destination
	h.logger.InfoContext(ctx, "outbound connection to ", destination)
	return client.DialContext(ctx, network, destination)
}

func (h *Outbound) ListenPacket(ctx context.Context, destination M.Socksaddr) (net.PacketConn, error) {
	return nil, os.ErrInvalid
}
