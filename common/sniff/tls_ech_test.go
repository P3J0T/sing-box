package sniff_test

import (
	"bytes"
	"context"
	"crypto/tls"
	"encoding/binary"
	"io"
	"net"
	"testing"
	"time"

	"github.com/sagernet/sing-box/adapter"
	"github.com/sagernet/sing-box/common/sniff"
	C "github.com/sagernet/sing-box/constant"
	"github.com/sagernet/sing/common/buf"
	"github.com/stretchr/testify/require"
)

type helloCapture struct{ bytes.Buffer }

func (*helloCapture) Read([]byte) (int, error)         { return 0, io.EOF }
func (*helloCapture) Close() error                     { return nil }
func (*helloCapture) LocalAddr() net.Addr              { return &net.TCPAddr{} }
func (*helloCapture) RemoteAddr() net.Addr             { return &net.TCPAddr{} }
func (*helloCapture) SetDeadline(time.Time) error      { return nil }
func (*helloCapture) SetReadDeadline(time.Time) error  { return nil }
func (*helloCapture) SetWriteDeadline(time.Time) error { return nil }

func hello(t *testing.T, name string, ech bool) []byte {
	t.Helper()
	capture := &helloCapture{}
	_ = tls.Client(capture, &tls.Config{ServerName: name, MinVersion: tls.VersionTLS12}).Handshake()
	data := bytes.Clone(capture.Bytes())
	require.Greater(t, len(data), 50)
	if ech {
		// Insert a syntactically valid ECH GREASE extension into the existing TLS
		// ClientHello. Only the extension type is material to presence matching.
		offset := 43
		offset += 1 + int(data[offset])
		offset += 2 + int(binary.BigEndian.Uint16(data[offset:]))
		offset += 1 + int(data[offset])
		require.Equal(t, len(data), offset+2+int(binary.BigEndian.Uint16(data[offset:])))
		value := []byte{0, 0, 1, 0, 1, 7, 0, 32}
		value = append(value, bytes.Repeat([]byte{0x42}, 32)...)
		value = append(value, 0, 64)
		value = append(value, bytes.Repeat([]byte{0x24}, 64)...)
		extension := binary.BigEndian.AppendUint16(nil, 0xfe0d)
		extension = binary.BigEndian.AppendUint16(extension, uint16(len(value)))
		extension = append(extension, value...)
		data = append(data, extension...)
		binary.BigEndian.PutUint16(data[offset:], uint16(len(data)-offset-2))
		size := len(data) - 9
		data[6], data[7], data[8] = byte(size>>16), byte(size>>8), byte(size)
		binary.BigEndian.PutUint16(data[3:5], uint16(len(data)-5))
	}
	return data
}

// crypto/tls omits SNI for IP literals; inject one into an actual ClientHello.
func literalSNIHello(t *testing.T, ip string) []byte {
	t.Helper()
	data := hello(t, "approved.example", true)
	offset := 43
	offset += 1 + int(data[offset])
	offset += 2 + int(binary.BigEndian.Uint16(data[offset:]))
	offset += 1 + int(data[offset])
	end := offset + 2 + int(binary.BigEndian.Uint16(data[offset:]))
	for pos := offset + 2; pos < end; {
		length := int(binary.BigEndian.Uint16(data[pos+2:]))
		if binary.BigEndian.Uint16(data[pos:]) == 0 {
			name := []byte(ip)
			ext := binary.BigEndian.AppendUint16(nil, uint16(len(name)+3))
			ext = append(ext, 0)
			ext = binary.BigEndian.AppendUint16(ext, uint16(len(name)))
			ext = append(ext, name...)
			replacement := binary.BigEndian.AppendUint16(nil, 0)
			replacement = binary.BigEndian.AppendUint16(replacement, uint16(len(ext)))
			replacement = append(replacement, ext...)
			data = append(append(bytes.Clone(data[:pos]), replacement...), data[pos+4+length:]...)
			binary.BigEndian.PutUint16(data[offset:], uint16(end-(4+length)+len(replacement)-offset-2))
			size := len(data) - 9
			data[6], data[7], data[8] = byte(size>>16), byte(size>>8), byte(size)
			binary.BigEndian.PutUint16(data[3:5], uint16(len(data)-5))
			require.Equal(t, name, data[pos+9:pos+9+len(name)], "literal SNI must be on the wire")
			return data
		}
		pos += 4 + length
	}
	t.Fatal("captured hello had no SNI extension")
	return nil
}

func fragmentHello(data []byte, end int) [][]byte {
	body := data[5:]
	parts := [][]byte{body[:end], body[end:]}
	records := make([][]byte, 0, 2)
	for _, part := range parts {
		record := append([]byte{22, data[1], data[2]}, byte(len(part)>>8), byte(len(part)))
		record = append(record, part...)
		records = append(records, record)
	}
	return records
}

func TestTLSECHPresenceAndIPLiteral(t *testing.T) {
	for _, tc := range []struct {
		name       string
		ech        bool
		wantDomain string
	}{
		{"approved.example", false, "approved.example"},
		{"approved.example", true, "approved.example"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			data := hello(t, tc.name, tc.ech)
			for _, input := range [][]byte{data, bytes.Join(fragmentHello(data, 2), nil)} {
				metadata := &adapter.InboundContext{TLSECH: true}
				require.NoError(t, sniff.TLSClientHello(context.Background(), metadata, bytes.NewReader(input)))
				require.Equal(t, C.ProtocolTLS, metadata.Protocol)
				require.Equal(t, tc.wantDomain, metadata.Domain)
				require.Equal(t, tc.ech, metadata.TLSECH)
			}
		})
	}
	t.Run("literal SNI on wire", func(t *testing.T) {
		data := literalSNIHello(t, "192.0.2.9")
		for _, input := range [][]byte{data, bytes.Join(fragmentHello(data, 2), nil)} {
			metadata := &adapter.InboundContext{TLSECH: true}
			require.NoError(t, sniff.TLSClientHello(context.Background(), metadata, bytes.NewReader(input)))
			require.Equal(t, C.ProtocolTLS, metadata.Protocol)
			require.Empty(t, metadata.Domain)
			require.True(t, metadata.TLSECH)
		}
	})
}

func TestTLSECHIncompleteAndRecordBoundary(t *testing.T) {
	data := hello(t, "approved.example", true)
	parts := fragmentHello(data, 2)
	metadata := &adapter.InboundContext{TLSECH: true}
	err := sniff.TLSClientHello(context.Background(), metadata, bytes.NewReader(parts[0]))
	require.ErrorIs(t, err, sniff.ErrNeedMoreData)
	require.False(t, metadata.TLSECH)
	client, server := net.Pipe()
	defer client.Close()
	defer server.Close()
	done := make(chan struct{})
	go func() {
		defer close(done)
		for _, part := range parts {
			_, _ = client.Write(part)
		}
	}()
	payload := buf.NewPacket()
	defer payload.Release()
	require.NoError(t, sniff.PeekStream(context.Background(), metadata, server, nil, payload, time.Second, sniff.TLSClientHello))
	<-done
	require.Equal(t, data[5:], bytes.Join([][]byte{parts[0][5:], parts[1][5:]}, nil))
	require.Equal(t, bytes.Join(parts, nil), payload.Bytes())
	require.True(t, metadata.TLSECH)
}
