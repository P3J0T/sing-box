package sniff

import (
	"context"
	"crypto/tls"
	"errors"
	"io"
	"slices"

	"github.com/sagernet/sing-box/adapter"
	C "github.com/sagernet/sing-box/constant"
	"github.com/sagernet/sing/common/bufio"
	E "github.com/sagernet/sing/common/exceptions"
	M "github.com/sagernet/sing/common/metadata"
)

func TLSClientHello(ctx context.Context, metadata *adapter.InboundContext, reader io.Reader) error {
	metadata.TLSECH = false
	var clientHello *tls.ClientHelloInfo
	err := tls.Server(bufio.NewReadOnlyConn(reader), &tls.Config{
		GetConfigForClient: func(argHello *tls.ClientHelloInfo) (*tls.Config, error) {
			clientHello = argHello
			return nil, nil
		},
	}).HandshakeContext(ctx)
	if clientHello != nil {
		metadata.Protocol = C.ProtocolTLS
		metadata.Domain = M.ParseSocksaddrHostPort(clientHello.ServerName, 0).Fqdn
		// Extension presence includes GREASE; it cannot reveal the inner name.
		metadata.TLSECH = slices.Contains(clientHello.Extensions, uint16(0xfe0d))
		return nil
	}
	if errors.Is(err, io.EOF) || errors.Is(err, io.ErrUnexpectedEOF) {
		return E.Cause1(ErrNeedMoreData, err)
	} else {
		return err
	}
}
