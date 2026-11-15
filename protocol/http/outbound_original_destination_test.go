package http

import (
	"bufio"
	"context"
	"fmt"
	"io"
	"net"
	stdhttp "net/http"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/sagernet/sing-box/adapter"
	"github.com/sagernet/sing-box/log"
	"github.com/sagernet/sing-box/option"
	"github.com/sagernet/sing/common/json"
	"github.com/sagernet/sing/common/json/badoption"
	M "github.com/sagernet/sing/common/metadata"
	"github.com/stretchr/testify/require"
)

func testHTTPProxy(t *testing.T) (M.Socksaddr, <-chan *stdhttp.Request, *atomic.Int32) {
	t.Helper()
	listener, err := net.Listen("tcp4", "127.0.0.1:0")
	require.NoError(t, err)
	requests := make(chan *stdhttp.Request, 64)
	count := &atomic.Int32{}
	done := make(chan struct{})
	var handlers sync.WaitGroup
	go func() {
		defer close(done)
		for {
			conn, err := listener.Accept()
			if err != nil {
				return
			}
			count.Add(1)
			handlers.Add(1)
			go func() {
				defer handlers.Done()
				defer conn.Close()
				_ = conn.SetDeadline(time.Now().Add(5 * time.Second))
				request, err := stdhttp.ReadRequest(bufio.NewReader(conn))
				if err != nil {
					return
				}
				requests <- request
				_, _ = fmt.Fprint(conn, "HTTP/1.1 200 Connection established\r\n\r\n")
			}()
		}
	}()
	t.Cleanup(func() {
		_ = listener.Close()
		select {
		case <-done:
		case <-time.After(5 * time.Second):
			t.Error("proxy accept loop stalled")
			return
		}
		finished := make(chan struct{})
		go func() { handlers.Wait(); close(finished) }()
		select {
		case <-finished:
		case <-time.After(6 * time.Second):
			t.Error("proxy handlers stalled")
		}
	})
	return M.SocksaddrFromNet(listener.Addr()), requests, count
}

func receiveProxyRequest(t *testing.T, requests <-chan *stdhttp.Request) *stdhttp.Request {
	t.Helper()
	select {
	case request := <-requests:
		return request
	case <-time.After(5 * time.Second):
		t.Fatal("missing proxy CONNECT request")
		return nil
	}
}

func testHTTPOutbound(t *testing.T, options option.HTTPOutboundOptions) *Outbound {
	t.Helper()
	outbound, err := NewOutbound(context.Background(), nil, log.NewNOPFactory().Logger(), "test", options)
	require.NoError(t, err)
	return outbound.(*Outbound)
}

func TestOriginalDestinationJSONOption(t *testing.T) {
	for _, tc := range []struct {
		input string
		want  bool
	}{
		{`{}`, false},
		{`{"send_original_destination":false}`, false},
		{`{"send_original_destination":true}`, true},
	} {
		var options option.HTTPOutboundOptions
		require.NoError(t, json.Unmarshal([]byte(tc.input), &options))
		require.Equal(t, tc.want, options.SendOriginalDestination)
	}
}

func TestOriginalDestinationCONNECT(t *testing.T) {
	server, requests, _ := testHTTPProxy(t)
	cases := []struct {
		name     string
		enabled  bool
		original M.Socksaddr
		want     string
	}{
		{"default", false, M.ParseSocksaddr("192.0.2.4:443"), ""},
		{"enabled", true, M.ParseSocksaddr("192.0.2.4:443"), "192.0.2.4:443"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			options := option.HTTPOutboundOptions{ServerOptions: option.ServerOptions{Server: server.Addr.String(), ServerPort: server.Port}, SendOriginalDestination: tc.enabled}
			h := testHTTPOutbound(t, options)
			metadata := &adapter.InboundContext{OriginDestination: tc.original, Destination: M.ParseSocksaddr("203.0.113.8:443")}
			ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
			defer cancel()
			conn, err := h.DialContext(adapter.WithContext(ctx, metadata), "tcp", M.ParseSocksaddr("routed.example:443"))
			require.NoError(t, err)
			conn.Close()
			request := receiveProxyRequest(t, requests)
			require.Equal(t, stdhttp.MethodConnect, request.Method)
			require.Equal(t, "routed.example:443", request.Host)
			if !tc.enabled {
				require.Empty(t, request.Header.Values("X-Infra-Original-Destination"))
			}
			if tc.enabled {
				require.Equal(t, []string{tc.want}, request.Header.Values("X-Infra-Original-Destination"))
			}
			require.Equal(t, tc.original, metadata.OriginDestination)
		})
	}
}

func TestOriginalDestinationPreservesStaticHost(t *testing.T) {
	server, requests, _ := testHTTPProxy(t)
	var stockHost string
	for _, enabled := range []bool{false, true} {
		options := option.HTTPOutboundOptions{
			ServerOptions:           option.ServerOptions{Server: server.Addr.String(), ServerPort: server.Port},
			SendOriginalDestination: enabled,
			Headers:                 badoption.HTTPHeader{"Host": {"central.example"}},
		}
		h := testHTTPOutbound(t, options)
		ctx := adapter.WithContext(context.Background(), &adapter.InboundContext{OriginDestination: M.ParseSocksaddr("192.0.2.11:443")})
		dialCtx, cancel := context.WithTimeout(ctx, 5*time.Second)
		conn, err := h.DialContext(dialCtx, "tcp", M.ParseSocksaddr("routed.example:443"))
		cancel()
		require.NoError(t, err)
		conn.Close()
		request := receiveProxyRequest(t, requests)
		if enabled {
			require.Equal(t, stockHost, request.Host, "enabled mode must preserve stock Host handling")
		} else {
			stockHost = request.Host
		}
		if enabled {
			require.Equal(t, []string{"192.0.2.11:443"}, request.Header.Values(originalDestinationHeader))
		} else {
			require.Empty(t, request.Header.Values(originalDestinationHeader))
		}
	}
}

func TestOriginalDestinationRefusesBeforeDial(t *testing.T) {
	server, _, count := testHTTPProxy(t)
	for _, tc := range []struct {
		name, network string
		original      M.Socksaddr
	}{
		{"missing", "tcp", M.Socksaddr{}},
		{"fqdn", "tcp", M.ParseSocksaddr("example.org:443")},
		{"unspecified", "tcp", M.ParseSocksaddr("0.0.0.0:443")},
		{"multicast", "tcp", M.ParseSocksaddr("224.0.0.1:443")},
		{"broadcast", "tcp", M.ParseSocksaddr("255.255.255.255:443")},
		{"ipv6", "tcp", M.ParseSocksaddr("[2001:db8::1]:443")},
		{"wrong_port", "tcp", M.ParseSocksaddr("192.0.2.1:80")},
		{"udp", "udp", M.ParseSocksaddr("192.0.2.1:443")},
	} {
		t.Run(tc.name, func(t *testing.T) {
			h := testHTTPOutbound(t, option.HTTPOutboundOptions{ServerOptions: option.ServerOptions{Server: server.Addr.String(), ServerPort: server.Port}, SendOriginalDestination: true})
			_, err := h.DialContext(adapter.WithContext(context.Background(), &adapter.InboundContext{OriginDestination: tc.original}), tc.network, M.ParseSocksaddr("approved.example:443"))
			require.Error(t, err)
			require.EqualValues(t, 0, count.Load())
		})
	}
}

func TestOriginalDestinationRejectsHeaderCollision(t *testing.T) {
	server, _, _ := testHTTPProxy(t)
	for _, key := range []string{"X-Infra-Original-Destination", "x-infra-original-destination"} {
		opts := option.HTTPOutboundOptions{ServerOptions: option.ServerOptions{Server: server.Addr.String(), ServerPort: server.Port}, SendOriginalDestination: true}
		opts.Headers = badoption.HTTPHeader{key: {"192.0.2.5:443"}}
		_, err := NewOutbound(context.Background(), nil, log.NewNOPFactory().Logger(), "test", opts)
		require.Error(t, err)
	}
}

func TestOriginalDestinationConcurrentCONNECT(t *testing.T) {
	server, requests, _ := testHTTPProxy(t)
	h := testHTTPOutbound(t, option.HTTPOutboundOptions{ServerOptions: option.ServerOptions{Server: server.Addr.String(), ServerPort: server.Port}, SendOriginalDestination: true})
	var wg sync.WaitGroup
	const n = 24
	for i := range n {
		wg.Add(1)
		go func() {
			defer wg.Done()
			original := M.ParseSocksaddr(fmt.Sprintf("192.0.2.%d:443", i+1))
			ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
			defer cancel()
			conn, err := h.DialContext(adapter.WithContext(ctx, &adapter.InboundContext{OriginDestination: original}), "tcp", M.ParseSocksaddr("approved.example:443"))
			if err != nil {
				t.Error(err)
				return
			}
			conn.Close()
		}()
	}
	done := make(chan struct{})
	go func() { wg.Wait(); close(done) }()
	select {
	case <-done:
	case <-time.After(5 * time.Second):
		t.Fatal("concurrent CONNECT requests stalled")
	}
	seen := make(map[string]bool)
	for range n {
		request := receiveProxyRequest(t, requests)
		values := request.Header.Values("X-Infra-Original-Destination")
		require.Len(t, values, 1)
		require.False(t, seen[values[0]])
		seen[values[0]] = true
		require.True(t, strings.HasPrefix(values[0], "192.0.2."))
	}
	require.Len(t, seen, n)
}

func TestOriginalDestinationBufferedBidirectionalTunnel(t *testing.T) {
	listener, err := net.Listen("tcp4", "127.0.0.1:0")
	require.NoError(t, err)
	t.Cleanup(func() { _ = listener.Close() })
	received := make(chan []byte, 1)
	serverDone := make(chan struct{})
	go func() {
		defer close(serverDone)
		conn, err := listener.Accept()
		if err != nil {
			return
		}
		defer conn.Close()
		_ = conn.SetDeadline(time.Now().Add(5 * time.Second))
		request, err := stdhttp.ReadRequest(bufio.NewReader(conn))
		if err != nil {
			return
		}
		if request.Method != stdhttp.MethodConnect {
			return
		}
		// Response and first server payload in one write exercise buffered bytes.
		_, _ = conn.Write([]byte("HTTP/1.1 200 Connection established\r\n\r\nserver-payload"))
		payload := make([]byte, len("client-payload"))
		if _, err := io.ReadFull(conn, payload); err == nil {
			received <- payload
		}
	}()
	server := M.SocksaddrFromNet(listener.Addr())
	h := testHTTPOutbound(t, option.HTTPOutboundOptions{ServerOptions: option.ServerOptions{Server: server.Addr.String(), ServerPort: server.Port}, SendOriginalDestination: true})
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	conn, err := h.DialContext(adapter.WithContext(ctx, &adapter.InboundContext{OriginDestination: M.ParseSocksaddr("192.0.2.9:443")}), "tcp", M.ParseSocksaddr("approved.example:443"))
	require.NoError(t, err)
	defer conn.Close()
	_ = conn.SetDeadline(time.Now().Add(5 * time.Second))
	actual := make([]byte, len("server-payload"))
	_, err = io.ReadFull(conn, actual)
	require.NoError(t, err)
	require.Equal(t, "server-payload", string(actual))
	_, err = conn.Write([]byte("client-payload"))
	require.NoError(t, err)
	select {
	case payload := <-received:
		require.Equal(t, "client-payload", string(payload))
	case <-time.After(5 * time.Second):
		t.Fatal("proxy did not receive tunnel bytes")
	}
	select {
	case <-serverDone:
	case <-time.After(5 * time.Second):
		t.Fatal("proxy tunnel handler did not finish")
	}
}

func TestOriginalDestinationCanceledStalledCONNECT(t *testing.T) {
	listener, err := net.Listen("tcp4", "127.0.0.1:0")
	require.NoError(t, err)
	t.Cleanup(func() { _ = listener.Close() })
	accepted := make(chan struct{})
	serverDone := make(chan struct{})
	go func() {
		defer close(serverDone)
		conn, err := listener.Accept()
		if err != nil {
			return
		}
		defer conn.Close()
		_ = conn.SetDeadline(time.Now().Add(5 * time.Second))
		if _, err := stdhttp.ReadRequest(bufio.NewReader(conn)); err != nil {
			return
		}
		close(accepted)
		// Deliberately withhold 200; cancellation should close this connection.
		_, _ = io.Copy(io.Discard, conn)
	}()
	server := M.SocksaddrFromNet(listener.Addr())
	h := testHTTPOutbound(t, option.HTTPOutboundOptions{ServerOptions: option.ServerOptions{Server: server.Addr.String(), ServerPort: server.Port}, SendOriginalDestination: true})
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	result := make(chan error, 1)
	go func() {
		conn, err := h.DialContext(adapter.WithContext(ctx, &adapter.InboundContext{OriginDestination: M.ParseSocksaddr("192.0.2.9:443")}), "tcp", M.ParseSocksaddr("approved.example:443"))
		if conn != nil {
			_ = conn.Close()
		}
		result <- err
	}()
	select {
	case <-accepted:
	case <-time.After(5 * time.Second):
		t.Fatal("CONNECT was not sent")
	}
	cancel()
	select {
	case err := <-result:
		require.Error(t, err)
	case <-time.After(5 * time.Second):
		t.Fatal("canceled CONNECT remained blocked")
	}
	select {
	case <-serverDone:
	case <-time.After(5 * time.Second):
		t.Fatal("canceled CONNECT did not close proxy connection")
	}
}
