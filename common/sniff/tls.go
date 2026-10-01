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
		metadata.Domain = clientHello.ServerName
		// Match extension presence, including ECH GREASE, without changing the
		// existing TLS classification or attempting to decrypt the inner hello.
		metadata.TLSECH = slices.Contains(clientHello.Extensions, uint16(0xfe0d))
		return nil
	}
	// A buffered prefix may end exactly between TLS records while the
	// ClientHello continues in a later record. crypto/tls returns EOF there.
	// PeekStream owns the connection deadline and bounds further reads.
	if errors.Is(err, io.EOF) || errors.Is(err, io.ErrUnexpectedEOF) {
		return E.Cause1(ErrNeedMoreData, err)
	} else {
		return err
	}
}
