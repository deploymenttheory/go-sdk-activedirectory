package ldap

import (
	"bytes"
	"errors"
	"net"
	"sync/atomic"
	"testing"
	"time"

	ber "github.com/go-asn1-ber/asn1-ber"

	"github.com/deploymenttheory/go-sdk-activedirectory/3rd_party/ldap/v3/gssapi"
)

type handoffMechanism struct {
	*bindResultMechanism
	entered chan struct{}
	release chan struct{}
}

func (m *handoffMechanism) AuthenticationContext() (gssapi.AuthenticationContext, error) {
	close(m.entered)
	<-m.release
	return m.bindResultMechanism.AuthenticationContext()
}

type handoffWriteObserver struct {
	net.Conn
	writes atomic.Int32
}

func (c *handoffWriteObserver) Write(p []byte) (int, error) {
	c.writes.Add(1)
	return c.Conn.Write(p)
}

func TestSASLHandoffRejectsConcurrentUnprotectedRequest(t *testing.T) {
	client, server := net.Pipe()
	t.Cleanup(func() { _ = server.Close() })
	observed := &handoffWriteObserver{Conn: client}
	connection := NewConn(observed, false)
	connection.Start()
	t.Cleanup(func() { _ = connection.Close() })
	mechanism := &handoffMechanism{
		bindResultMechanism: &bindResultMechanism{key: bytes.Repeat([]byte{0x41}, 16)},
		entered:             make(chan struct{}), release: make(chan struct{}),
	}
	go func() { _ = runBindResultPeer(server, LDAPResultSaslBindInProgress, LDAPResultSuccess) }()
	bound := make(chan error, 1)
	go func() {
		_, err := connection.GSSAPIBindRequestWithResult(mechanism, &GSSAPIBindRequest{SASLSecurity: SASLSecuritySeal}, nil)
		bound <- err
	}()
	select {
	case <-mechanism.entered:
	case <-time.After(2 * time.Second):
		t.Fatal("bind never reached the paused transport handoff")
	}
	rejected := make(chan error, 1)
	go func() {
		_, err := connection.SimpleBind(&SimpleBindRequest{Username: "must-not-submit", Password: "fixture"})
		rejected <- err
	}()
	select {
	case err := <-rejected:
		if err == nil || observed.writes.Load() != 2 {
			t.Fatal("concurrent operation reached the unprotected transport")
		}
	case <-time.After(time.Second):
		_ = connection.Close()
		close(mechanism.release)
		t.Fatal("concurrent request blocked in an unprotected network write")
	}
	close(mechanism.release)
	if err := <-bound; err != nil {
		t.Fatal(err)
	}
}

func TestSASLHandoffPreservesFollowingProtectedOctets(t *testing.T) {
	client, server := net.Pipe()
	t.Cleanup(func() { _ = server.Close() })
	connection := NewConn(client, false)
	connection.Start()
	t.Cleanup(func() { _ = connection.Close() })
	go func() {
		for index := range 2 {
			request, err := ber.ReadPacket(server)
			if err != nil {
				return
			}
			id, err := packetInt64At(request, 0)
			if err != nil {
				return
			}
			code := int64(LDAPResultSaslBindInProgress)
			if index == 1 {
				code = LDAPResultSuccess
			}
			response := newResultProtocolOp(ApplicationBindResponse, code)
			if index == 0 {
				response.AppendChild(ber.NewString(ber.ClassContext, ber.TypePrimitive, 7, "offer", "Server SASL credentials"))
			}
			wire := newDecodeEnvelope(id, response).Bytes()
			if index == 1 {
				// Coalesce the final cleartext response with an invalid protected
				// prefix. The new decoder must see and retire it, never discard it
				// in an abandoned buffered cleartext reader and wait indefinitely.
				wire = append(wire, 0, 1, 0, 0)
			}
			if _, err := server.Write(wire); err != nil {
				return
			}
		}
	}()
	mechanism := &bindResultMechanism{key: bytes.Repeat([]byte{0x41}, 16)}
	_, err := connection.GSSAPIBindRequestWithResult(mechanism, &GSSAPIBindRequest{SASLSecurity: SASLSecuritySeal}, nil)
	if err != nil && !connection.IsClosing() {
		t.Fatal(err)
	}
	deadline := time.After(2 * time.Second)
	for !connection.IsClosing() {
		select {
		case <-deadline:
			t.Fatal("protected bytes following final BindResponse were discarded")
		default:
			time.Sleep(time.Millisecond)
		}
	}
	if connection.GetLastError() == nil {
		t.Fatal("protected framing violation was not retained")
	}
}

func TestCloseInterruptsBlockedBindWrite(t *testing.T) {
	client, server := net.Pipe()
	t.Cleanup(func() { _ = server.Close() })
	observed := &handoffWriteObserver{Conn: client}
	connection := NewConn(observed, false)
	connection.Start()
	bound := make(chan error, 1)
	go func() {
		_, err := connection.GSSAPIBindRequestWithResult(&bindResultMechanism{key: bytes.Repeat([]byte{0x41}, 16)},
			&GSSAPIBindRequest{SASLSecurity: SASLSecuritySeal}, nil)
		bound <- err
	}()
	deadline := time.After(time.Second)
	for observed.writes.Load() == 0 {
		select {
		case <-deadline:
			t.Fatal("bind did not start its write")
		default:
			time.Sleep(time.Millisecond)
		}
	}
	closed := make(chan error, 1)
	go func() { closed <- connection.Close() }()
	select {
	case err := <-closed:
		if err != nil && !errors.Is(err, net.ErrClosed) {
			t.Fatal(err)
		}
	case <-time.After(time.Second):
		t.Fatal("Close waited for the dispatcher before interrupting its network write")
	}
	if err := <-bound; err == nil {
		t.Fatal("blocked bind succeeded after connection retirement")
	}
}
