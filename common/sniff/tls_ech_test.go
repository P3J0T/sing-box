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

// These helpers only construct test inputs. Production parsing remains in Go's
// crypto/tls; no packet offsets or synthetic parser are added to the sniffer.
type clientHelloCapture struct {
	bytes.Buffer
}

func (c *clientHelloCapture) Read([]byte) (int, error)         { return 0, io.EOF }
func (c *clientHelloCapture) Close() error                     { return nil }
func (c *clientHelloCapture) LocalAddr() net.Addr              { return &net.TCPAddr{} }
func (c *clientHelloCapture) RemoteAddr() net.Addr             { return &net.TCPAddr{} }
func (c *clientHelloCapture) SetDeadline(time.Time) error      { return nil }
func (c *clientHelloCapture) SetReadDeadline(time.Time) error  { return nil }
func (c *clientHelloCapture) SetWriteDeadline(time.Time) error { return nil }

func makeTLSClientHello(t testing.TB) []byte {
	t.Helper()
	capture := &clientHelloCapture{}
	client := tls.Client(capture, &tls.Config{
		ServerName:       "approved.example",
		MinVersion:       tls.VersionTLS12,
		CurvePreferences: []tls.CurveID{tls.X25519},
	})
	require.Error(t, client.HandshakeContext(context.Background()))
	record := bytes.Clone(capture.Bytes())
	require.Greater(t, len(record), 48)
	require.Equal(t, byte(22), record[0])
	require.Equal(t, len(record)-5, int(binary.BigEndian.Uint16(record[3:5])))
	require.Equal(t, byte(1), record[5])
	return record
}

func tlsExtensionsOffset(t testing.TB, record []byte) int {
	t.Helper()
	offset := 43 // record + handshake headers, legacy version and random
	offset += 1 + int(record[offset])
	offset += 2 + int(binary.BigEndian.Uint16(record[offset:]))
	offset += 1 + int(record[offset])
	require.Equal(t, len(record), offset+2+int(binary.BigEndian.Uint16(record[offset:])))
	return offset
}

func addTLSClientHelloExtension(t testing.TB, record []byte, kind uint16, value []byte, first bool) []byte {
	t.Helper()
	offset := tlsExtensionsOffset(t, record)
	extension := binary.BigEndian.AppendUint16(nil, kind)
	extension = binary.BigEndian.AppendUint16(extension, uint16(len(value)))
	extension = append(extension, value...)
	result := bytes.Clone(record[:offset+2])
	if first {
		result = append(result, extension...)
	}
	result = append(result, record[offset+2:]...)
	if !first {
		result = append(result, extension...)
	}
	binary.BigEndian.PutUint16(result[offset:], uint16(len(result)-offset-2))
	size := len(result) - 9
	result[6], result[7], result[8] = byte(size>>16), byte(size>>8), byte(size)
	binary.BigEndian.PutUint16(result[3:5], uint16(len(result)-5))
	return result
}

func echGREASEExtension() []byte {
	// outer, HKDF-SHA256, AES-128-GCM, config_id, enc<32>, payload<64>.
	// This is syntactically formed GREASE, not a decrypted ECH exchange.
	value := []byte{0, 0, 1, 0, 1, 7, 0, 32}
	value = append(value, bytes.Repeat([]byte{0x42}, 32)...)
	value = append(value, 0, 64)
	return append(value, bytes.Repeat([]byte{0x24}, 64)...)
}

func splitTLSClientHelloRecords(t *testing.T, record []byte) []byte {
	t.Helper()
	body := record[5:]
	var result []byte
	for _, part := range [][]byte{body[:2], body[2:17], body[17:]} {
		result = append(result, 22, record[1], record[2])
		result = binary.BigEndian.AppendUint16(result, uint16(len(part)))
		result = append(result, part...)
	}
	return result
}

func TestTLSClientHelloECHPresence(t *testing.T) {
	t.Parallel()
	plain := makeTLSClientHello(t)
	for _, test := range []struct {
		name   string
		record []byte
		ech    bool
	}{
		{"plain", plain, false},
		{"ech_first", addTLSClientHelloExtension(t, plain, 0xfe0d, echGREASEExtension(), true), true},
		{"ech_last", addTLSClientHelloExtension(t, plain, 0xfe0d, echGREASEExtension(), false), true},
		{"marker_in_other_extension", addTLSClientHelloExtension(t, plain, 0x1234, []byte{0xfe, 0x0d}, false), false},
	} {
		t.Run(test.name, func(t *testing.T) {
			t.Parallel()
			for _, records := range [][]byte{test.record, splitTLSClientHelloRecords(t, test.record)} {
				var metadata adapter.InboundContext
				require.NoError(t, sniff.TLSClientHello(context.Background(), &metadata, bytes.NewReader(records)))
				require.Equal(t, C.ProtocolTLS, metadata.Protocol)
				require.Equal(t, "approved.example", metadata.Domain)
				require.Equal(t, test.ech, metadata.TLSECH)
			}
		})
	}
}

func TestTLSClientHelloECHInvalidOrIncomplete(t *testing.T) {
	t.Parallel()
	plain := makeTLSClientHello(t)
	ech := addTLSClientHelloExtension(t, plain, 0xfe0d, echGREASEExtension(), false)
	for _, test := range []struct {
		name     string
		record   []byte
		needMore bool
	}{
		{"truncated_record", ech[:len(ech)-1], true},
		{"empty_prefix", nil, true},
		{"record_boundary", splitTLSClientHelloRecords(t, ech)[:7], true},
		{"malformed_ech", addTLSClientHelloExtension(t, plain, 0xfe0d, []byte{0, 0}, false), false},
		{"duplicate_ech", addTLSClientHelloExtension(t, ech, 0xfe0d, echGREASEExtension(), false), false},
		{"not_tls", []byte("GET / HTTP/1.1\r\nHost: approved.example\r\n\r\n"), false},
	} {
		t.Run(test.name, func(t *testing.T) {
			metadata := adapter.InboundContext{TLSECH: true}
			err := sniff.TLSClientHello(context.Background(), &metadata, bytes.NewReader(test.record))
			require.Error(t, err)
			if test.needMore {
				require.ErrorIs(t, err, sniff.ErrNeedMoreData)
			} else {
				require.NotErrorIs(t, err, sniff.ErrNeedMoreData)
			}
			require.Empty(t, metadata.Protocol)
			require.Empty(t, metadata.Domain)
			require.False(t, metadata.TLSECH)
		})
	}
}

func TestPeekStreamTLSClientHelloECHFragments(t *testing.T) {
	t.Parallel()
	ech := addTLSClientHelloExtension(t, makeTLSClientHello(t), 0xfe0d, echGREASEExtension(), false)
	for _, record := range [][]byte{ech, splitTLSClientHelloRecords(t, ech)} {
		client, server := net.Pipe()
		payload := buf.NewPacket()
		done := make(chan error, 1)
		go func() {
			defer client.Close()
			for _, part := range [][]byte{record[:3], record[3:11], record[11 : len(record)-2], record[len(record)-2:]} {
				if _, err := client.Write(part); err != nil {
					done <- err
					return
				}
			}
			done <- nil
		}()
		var metadata adapter.InboundContext
		err := sniff.PeekStream(context.Background(), &metadata, server, nil, payload, time.Second, sniff.TLSClientHello)
		server.Close()
		payload.Release()
		require.NoError(t, err)
		require.NoError(t, <-done)
		require.True(t, metadata.TLSECH)
		require.Equal(t, C.ProtocolTLS, metadata.Protocol)
		require.Equal(t, "approved.example", metadata.Domain)
	}
}

func TestTLSClientHelloECHDoesNotPersistAcrossSuccessfulSniffs(t *testing.T) {
	t.Parallel()
	plain := makeTLSClientHello(t)
	ech := addTLSClientHelloExtension(t, plain, 0xfe0d, echGREASEExtension(), false)
	var metadata adapter.InboundContext
	require.NoError(t, sniff.TLSClientHello(context.Background(), &metadata, bytes.NewReader(ech)))
	require.True(t, metadata.TLSECH)
	require.NoError(t, sniff.TLSClientHello(context.Background(), &metadata, bytes.NewReader(plain)))
	require.False(t, metadata.TLSECH)
}

// net.Pipe delivers each write separately, so PeekStream must parse each
// complete TLS record before it can read the next one. No timing assumption
// or TCP write coalescing can hide a record-boundary EOF in these tests.
func clientHelloRecordParts(record []byte, ends ...int) [][]byte {
	var records [][]byte
	start := 0
	for _, end := range append(ends, len(record)-5) {
		part := []byte{22, record[1], record[2]}
		part = binary.BigEndian.AppendUint16(part, uint16(end-start))
		records = append(records, append(part, record[5+start:5+end]...))
		start = end
	}
	return records
}

type readDeadlineRecorder struct {
	net.Conn
	deadlines []time.Time
	cleared   bool
	reads     int
	eofAtRead int
}

func (c *readDeadlineRecorder) Read(data []byte) (int, error) {
	c.reads++
	if c.reads == c.eofAtRead {
		return 0, io.EOF
	}
	return c.Conn.Read(data)
}

func (c *readDeadlineRecorder) SetReadDeadline(deadline time.Time) error {
	c.cleared = deadline.IsZero()
	if !c.cleared {
		c.deadlines = append(c.deadlines, deadline)
	}
	return c.Conn.SetReadDeadline(deadline)
}

func requireFixedReadDeadline(t *testing.T, conn *readDeadlineRecorder) {
	t.Helper()
	require.NotEmpty(t, conn.deadlines)
	for _, deadline := range conn.deadlines {
		require.Equal(t, conn.deadlines[0], deadline, "fragment arrival must not extend the sniff timeout")
	}
	require.True(t, conn.cleared, "sniffing must clear its read deadline")
}

func peekRecordParts(t *testing.T, parts [][]byte, wantECH bool) {
	t.Helper()
	client, server := net.Pipe()
	defer server.Close()
	defer client.Close()
	conn := &readDeadlineRecorder{Conn: server}
	payload := buf.NewPacket()
	defer payload.Release()
	done := make(chan error, 1)
	go func() {
		defer client.Close()
		for _, part := range parts {
			if _, err := client.Write(part); err != nil {
				done <- err
				return
			}
		}
		done <- nil
	}()
	metadata := adapter.InboundContext{TLSECH: true}
	calls := 0
	sniffer := func(ctx context.Context, metadata *adapter.InboundContext, reader io.Reader) error {
		calls++
		err := sniff.TLSClientHello(ctx, metadata, reader)
		if calls < len(parts) {
			require.ErrorIs(t, err, sniff.ErrNeedMoreData)
			require.Empty(t, metadata.Protocol)
			require.Empty(t, metadata.Domain)
			require.False(t, metadata.TLSECH)
		}
		return err
	}
	require.NoError(t, sniff.PeekStream(context.Background(), &metadata, conn, nil, payload, time.Second, sniffer))
	require.NoError(t, <-done)
	require.Equal(t, len(parts), calls)
	require.Equal(t, bytes.Join(parts, nil), payload.Bytes(), "all bytes must remain available for forwarding")
	require.Equal(t, C.ProtocolTLS, metadata.Protocol)
	require.Equal(t, "approved.example", metadata.Domain)
	require.Equal(t, wantECH, metadata.TLSECH)
	requireFixedReadDeadline(t, conn)
}

func TestPeekStreamTLSClientHelloExactRecordBoundaries(t *testing.T) {
	t.Parallel()
	plain := makeTLSClientHello(t)
	for _, wantECH := range []bool{false, true} {
		record := plain
		if wantECH {
			record = addTLSClientHelloExtension(t, plain, 0xfe0d, echGREASEExtension(), false)
		}
		// Inside the handshake header, after it, and one byte before completion.
		for _, end := range []int{2, 4, len(record) - 6} {
			peekRecordParts(t, clientHelloRecordParts(record, end), wantECH)
		}
	}
}

func TestPeekStreamTLSClientHelloIncompleteRecordBoundary(t *testing.T) {
	t.Parallel()
	ech := addTLSClientHelloExtension(t, makeTLSClientHello(t), 0xfe0d, echGREASEExtension(), false)
	parts := clientHelloRecordParts(ech, 2, 17)
	for _, readEOF := range []bool{false, true} {
		client, server := net.Pipe()
		conn := &readDeadlineRecorder{Conn: server}
		if readEOF {
			// Inject EOF after two records, keeping the pipe open so setting
			// the read deadline cannot race a peer's Close.
			conn.eofAtRead = 3
		}
		payload := buf.NewPacket()
		done := make(chan struct{})
		go func() {
			defer close(done)
			defer client.Close()
			for _, part := range parts[:2] {
				if _, err := client.Write(part); err != nil {
					return
				}
			}
			// Wait for the test's close, leaving a silent peer at the boundary.
			_, _ = client.Read(make([]byte, 1))
		}()
		metadata := adapter.InboundContext{TLSECH: true}
		err := sniff.PeekStream(context.Background(), &metadata, conn, nil, payload, 50*time.Millisecond, sniff.TLSClientHello)
		server.Close()
		client.Close()
		<-done
		payload.Release()
		require.ErrorIs(t, err, sniff.ErrNeedMoreData)
		require.Empty(t, metadata.Protocol)
		require.Empty(t, metadata.Domain)
		require.False(t, metadata.TLSECH)
		require.Len(t, conn.deadlines, 3)
		requireFixedReadDeadline(t, conn)
	}
}

func TestPeekStreamTLSClientHelloLarge(t *testing.T) {
	t.Parallel()
	base := makeTLSClientHello(t)
	// Respect the existing packet capacity, including record headers and ECH.
	plain := addTLSClientHelloExtension(t, base, 0x1234, bytes.Repeat([]byte{0x42}, buf.UDPBufferSize-len(base)-512), false)
	oversized := addTLSClientHelloExtension(t, base, 0x1234, bytes.Repeat([]byte{0x42}, buf.UDPBufferSize+512), false)
	for _, wantECH := range []bool{false, true} {
		record, overCapacity := plain, oversized
		if wantECH {
			record = addTLSClientHelloExtension(t, plain, 0xfe0d, echGREASEExtension(), false)
			overCapacity = addTLSClientHelloExtension(t, oversized, 0xfe0d, echGREASEExtension(), false)
		}
		ends := []int{buf.UDPBufferSize / 4, buf.UDPBufferSize / 2, 3 * buf.UDPBufferSize / 4}
		peekRecordParts(t, clientHelloRecordParts(record, ends...), wantECH)
		wire := bytes.Join(clientHelloRecordParts(overCapacity, append(ends, buf.UDPBufferSize)...), nil)
		var complete adapter.InboundContext
		require.NoError(t, sniff.TLSClientHello(context.Background(), &complete, bytes.NewReader(wire)))
		require.Equal(t, wantECH, complete.TLSECH, "the oversized control must be a valid ClientHello")

		client, server := net.Pipe()
		conn := &readDeadlineRecorder{Conn: server}
		payload := buf.NewPacket()
		done := make(chan error, 1)
		go func() {
			_, err := client.Write(wire)
			done <- err
		}()
		metadata := adapter.InboundContext{TLSECH: true}
		err := sniff.PeekStream(context.Background(), &metadata, conn, nil, payload, time.Second, sniff.TLSClientHello)
		server.Close()
		client.Close()
		require.ErrorIs(t, <-done, io.ErrClosedPipe)
		require.ErrorIs(t, err, sniff.ErrNeedMoreData)
		require.Empty(t, metadata.Protocol)
		require.Empty(t, metadata.Domain)
		require.False(t, metadata.TLSECH)
		require.Equal(t, buf.UDPBufferSize, payload.Len())
		require.Equal(t, wire[:buf.UDPBufferSize], payload.Bytes())
		payload.Release()
		requireFixedReadDeadline(t, conn)
	}
}

func FuzzTLSClientHelloECHState(f *testing.F) {
	plain := makeTLSClientHello(f)
	ech := addTLSClientHelloExtension(f, plain, 0xfe0d, echGREASEExtension(), false)
	for _, seed := range [][]byte{nil, plain, ech, ech[:len(ech)-1], clientHelloRecordParts(ech, 2)[0],
		addTLSClientHelloExtension(f, plain, 0xfe0d, []byte{0, 0}, false), []byte("GET / HTTP/1.1\r\n\r\n")} {
		f.Add(seed)
	}
	f.Fuzz(func(t *testing.T, wire []byte) {
		if len(wire) > 65535 {
			t.Skip()
		}
		metadata := adapter.InboundContext{TLSECH: true}
		err := sniff.TLSClientHello(context.Background(), &metadata, bytes.NewReader(wire))
		if err != nil {
			require.Empty(t, metadata.Protocol)
			require.Empty(t, metadata.Domain)
			require.False(t, metadata.TLSECH)
		} else {
			require.Equal(t, C.ProtocolTLS, metadata.Protocol)
			var fresh adapter.InboundContext
			require.NoError(t, sniff.TLSClientHello(context.Background(), &fresh, bytes.NewReader(wire)))
			require.Equal(t, fresh.TLSECH, metadata.TLSECH)
			require.Equal(t, fresh.Domain, metadata.Domain)
		}
	})
}
