package http

import (
	"bufio"
	"context"
	"fmt"
	"net"
	"strings"
	"testing"
	"time"

	"github.com/sagernet/sing-box/adapter"
	"github.com/sagernet/sing-box/option"
	"github.com/sagernet/sing/common/json/badoption"
	M "github.com/sagernet/sing/common/metadata"
	"github.com/stretchr/testify/require"
)

// net/http.ReadRequest derives Host from the CONNECT authority, so inspect the wire.
func TestOriginalDestinationStaticHostWire(t *testing.T) {
	listener, err := net.Listen("tcp4", "127.0.0.1:0")
	require.NoError(t, err)
	t.Cleanup(func() { _ = listener.Close() })
	lines := make(chan []string, 2)
	for range 2 {
		go func() {
			conn, err := listener.Accept()
			if err != nil {
				return
			}
			defer conn.Close()
			_ = conn.SetDeadline(time.Now().Add(5 * time.Second))
			reader := bufio.NewReader(conn)
			var headers []string
			for {
				line, err := reader.ReadString('\n')
				if err != nil {
					return
				}
				if line == "\r\n" {
					break
				}
				headers = append(headers, strings.TrimSpace(line))
			}
			lines <- headers
			_, _ = fmt.Fprint(conn, "HTTP/1.1 200 Connection established\r\n\r\n")
		}()
	}
	server := M.SocksaddrFromNet(listener.Addr())
	for _, enabled := range []bool{false, true} {
		h := testHTTPOutbound(t, option.HTTPOutboundOptions{
			ServerOptions:           option.ServerOptions{Server: server.Addr.String(), ServerPort: server.Port},
			SendOriginalDestination: enabled,
			Headers:                 badoption.HTTPHeader{"Host": {"central.example"}},
		})
		ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		conn, err := h.DialContext(adapter.WithContext(ctx, &adapter.InboundContext{OriginDestination: M.ParseSocksaddr("192.0.2.11:443")}), "tcp", M.ParseSocksaddr("routed.example:443"))
		cancel()
		require.NoError(t, err)
		_ = conn.Close()
		select {
		case headers := <-lines:
			require.Contains(t, headers, "CONNECT routed.example:443 HTTP/1.1")
			require.Contains(t, headers, "Host: central.example")
		case <-time.After(5 * time.Second):
			t.Fatal("no CONNECT wire headers")
		}
	}
}
