package client

import (
	"bytes"
	"encoding/binary"
	"errors"
	"io"
	"math/rand/v2"
	"net"
	"strconv"
	"sync/atomic"
	"testing"
	"testing/iotest"
	"time"

	"github.com/deploymenttheory/go-sdk-activedirectory/3rd_party/gokrb5/v8/config"
	"github.com/deploymenttheory/go-sdk-activedirectory/3rd_party/gokrb5/v8/iana/errorcode"
	"github.com/deploymenttheory/go-sdk-activedirectory/3rd_party/gokrb5/v8/messages"
	"github.com/deploymenttheory/go-sdk-activedirectory/3rd_party/gokrb5/v8/types"
)

type vendorKDCConn struct {
	reader     io.Reader
	shortWrite bool
	closed     bool
}

func (c *vendorKDCConn) Read(b []byte) (int, error) { return c.reader.Read(b) }
func (c *vendorKDCConn) Write(b []byte) (int, error) {
	if c.shortWrite {
		return len(b) - 1, nil
	}
	return len(b), nil
}
func (c *vendorKDCConn) Close() error                   { c.closed = true; return nil }
func (*vendorKDCConn) LocalAddr() net.Addr              { return &net.TCPAddr{} }
func (*vendorKDCConn) RemoteAddr() net.Addr             { return &net.TCPAddr{} }
func (*vendorKDCConn) SetDeadline(time.Time) error      { return nil }
func (*vendorKDCConn) SetReadDeadline(time.Time) error  { return nil }
func (*vendorKDCConn) SetWriteDeadline(time.Time) error { return nil }

func TestVendorTCPFragmentedReply(t *testing.T) {
	c := &vendorKDCConn{reader: iotest.OneByteReader(bytes.NewReader([]byte{0, 0, 0, 3, 1, 2, 3}))}
	got, err := sendTCP(c, []byte{5})
	if err != nil || !bytes.Equal(got, []byte{1, 2, 3}) || !c.closed {
		t.Fatalf("fragmented reply: got=%x err=%v closed=%v", got, err, c.closed)
	}
}

func TestVendorTCPShortWrite(t *testing.T) {
	c := &vendorKDCConn{reader: bytes.NewReader([]byte{0, 0, 0, 1, 9}), shortWrite: true}
	got, err := sendTCP(c, []byte{5})
	if !errors.Is(err, io.ErrShortWrite) || len(got) != 0 || !c.closed {
		t.Fatalf("short write accepted: got=%x err=%v closed=%v", got, err, c.closed)
	}
}

func TestVendorTCPReplyBounds(t *testing.T) {
	for _, size := range []uint32{0, 16*1024*1024 + 1} {
		header := make([]byte, 4)
		binary.BigEndian.PutUint32(header, size)
		c := &vendorKDCConn{reader: bytes.NewReader(header)}
		_, err := sendTCP(c, []byte{5})
		if err == nil || errors.Is(err, io.EOF) || !c.closed {
			t.Fatalf("size %d was not rejected before reading payload: %v", size, err)
		}
	}
}

func TestVendorTCPTruncatedReplyPreservesCause(t *testing.T) {
	for _, reply := range [][]byte{{0, 0}, {0, 0, 0, 3, 1}} {
		c := &vendorKDCConn{reader: bytes.NewReader(reply)}
		_, err := sendTCP(c, []byte{5})
		if !errors.Is(err, io.ErrUnexpectedEOF) || !c.closed {
			t.Fatalf("truncated response lost transport cause: %v", err)
		}
	}
}

func TestVendorKDCUDPRefusalsAndResponseTooBig(t *testing.T) {
	for _, code := range []int32{errorcode.KRB_ERR_RESPONSE_TOO_BIG, errorcode.KDC_ERR_PREAUTH_REQUIRED} {
		t.Run(strconv.Itoa(int(code)), func(t *testing.T) {
			listener, udp := vendorListenKDCPair(t)
			t.Cleanup(func() { _ = udp.Close() })
			t.Cleanup(func() { _ = listener.Close() })
			if err := udp.SetDeadline(time.Now().Add(5 * time.Second)); err != nil {
				t.Fatal(err)
			}
			response := func(status int32) []byte {
				kdc := messages.NewKRBError(types.PrincipalName{}, "EXAMPLE.COM", status, "fixture response")
				b, marshalErr := kdc.Marshal()
				if marshalErr != nil {
					t.Fatal(marshalErr)
				}
				return b
			}
			udpReply, tcpReply := response(code), response(errorcode.KDC_ERR_PREAUTH_REQUIRED)
			udpDone, tcpDone := make(chan struct{}), make(chan struct{})
			var tcpUsed atomic.Bool
			go func() {
				defer close(udpDone)
				_, peer, readErr := udp.ReadFrom(make([]byte, 4096))
				if readErr == nil {
					_, _ = udp.WriteTo(udpReply, peer)
				}
			}()
			go func() {
				defer close(tcpDone)
				conn, acceptErr := listener.Accept()
				if acceptErr != nil {
					return
				}
				defer conn.Close()
				tcpUsed.Store(true)
				if conn.SetDeadline(time.Now().Add(5*time.Second)) != nil {
					return
				}
				header := make([]byte, 4)
				if _, readErr := io.ReadFull(conn, header); readErr != nil {
					return
				}
				if _, copyErr := io.CopyN(io.Discard, conn, int64(binary.BigEndian.Uint32(header))); copyErr != nil {
					return
				}
				binary.BigEndian.PutUint32(header, uint32(len(tcpReply)))
				_, _ = conn.Write(append(header, tcpReply...))
			}()
			t.Cleanup(func() {
				_ = udp.Close()
				_ = listener.Close()
				<-udpDone
				<-tcpDone
			})
			cfg := config.New()
			cfg.LibDefaults.UDPPreferenceLimit = 1465
			cfg.Realms = []config.Realm{{Realm: "EXAMPLE.COM", KDC: []string{listener.Addr().String()}}}
			_, err := (&Client{Config: cfg}).sendToKDC([]byte{1, 2, 3}, "EXAMPLE.COM")
			var kdcError messages.KRBError
			if !errors.As(err, &kdcError) || kdcError.ErrorCode != errorcode.KDC_ERR_PREAUTH_REQUIRED {
				t.Fatalf("incorrect KDC status after transport selection: %v", err)
			}
			if tcpUsed.Load() != (code == errorcode.KRB_ERR_RESPONSE_TOO_BIG) {
				t.Fatalf("TCP attempted after UDP status %d: %v", code, tcpUsed.Load())
			}
		})
	}
}

func vendorListenKDCPair(t *testing.T) (net.Listener, net.PacketConn) {
	t.Helper()
	var lastErr error
	// Windows reserves TCP and UDP ports independently. An OS-selected port for
	// one protocol need not be bindable by the other; acquire both before using it.
	for attempt := 0; attempt < 128; attempt++ {
		address := net.JoinHostPort("127.0.0.1", strconv.Itoa(1024+rand.IntN(65536-1024)))
		listener, err := net.Listen("tcp", address)
		if err != nil {
			lastErr = err
			continue
		}
		udp, err := net.ListenPacket("udp", address)
		if err == nil {
			return listener, udp
		}
		lastErr = err
		_ = listener.Close()
	}
	t.Fatalf("could not reserve a shared loopback TCP/UDP test endpoint: %v", lastErr)
	return nil, nil
}
