package acceptance

import (
	"bytes"
	"context"
	"crypto/tls"
	"errors"
	"io"
	"net"
	"sync/atomic"
	"testing"
	"time"

	ber "github.com/go-asn1-ber/asn1-ber"

	krbgss "github.com/deploymenttheory/go-sdk-activedirectory/3rd_party/gokrb5/v8/gssapi"
	"github.com/deploymenttheory/go-sdk-activedirectory/3rd_party/gokrb5/v8/iana/keyusage"
	ldap "github.com/deploymenttheory/go-sdk-activedirectory/3rd_party/ldap/v3"
	admodel "github.com/deploymenttheory/go-sdk-activedirectory/activedirectory/internal/model"
)

type portableSASLWire struct {
	listener    net.Listener
	transport   admodel.Transport
	certificate tls.Certificate
	acceptor    *portableKerberosAcceptor
	mode        ldap.SASLSecurityMode
	offerMask   byte
	corrupt     string
	steps       []portableLDAPStep
	done        chan error
	peer        *portableSASLPeer
	attempts    atomic.Int32
	closes      atomic.Int32
	requests    atomic.Int32
}

func newPortableSASLWire(t *testing.T, transport admodel.Transport, certificate tls.Certificate, kdc *portableKerberosKDC,
	mode ldap.SASLSecurityMode, offerMask byte, corrupt string, steps ...portableLDAPStep,
) *portableSASLWire {
	t.Helper()
	listener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	acceptor := newPortableKerberosAcceptor(t, kdc, certificate.Leaf)
	if transport == admodel.TransportLDAP {
		acceptor.binding = [16]byte{}
	}
	wire := &portableSASLWire{
		listener: listener, transport: transport, certificate: certificate,
		acceptor: acceptor, mode: mode, offerMask: offerMask, corrupt: corrupt, steps: steps, done: make(chan error, 1),
	}
	t.Cleanup(func() { _ = listener.Close() })
	go func() { wire.done <- wire.serve(t.Context()) }()
	return wire
}

func (w *portableSASLWire) serve(ctx context.Context) error {
	raw, err := w.listener.Accept()
	if err != nil {
		return err
	}
	defer func() { _ = raw.Close() }()
	stop := context.AfterFunc(ctx, func() { _ = raw.Close() })
	defer stop()
	if err := raw.SetDeadline(time.Now().Add(10 * time.Second)); err != nil {
		return err
	}
	var conn net.Conn = raw
	if w.transport == admodel.TransportStartTLS {
		request, err := ber.ReadPacket(raw)
		if err != nil {
			return err
		}
		if len(request.Children) != 2 || request.Children[1].Tag != ldap.ApplicationExtendedRequest {
			return errors.New("SASL fixture received credentials before StartTLS")
		}
		if _, err := raw.Write(portableLDAPResult(request, ldap.ApplicationExtendedResponse, 0).Bytes()); err != nil {
			return err
		}
	}
	if w.transport != admodel.TransportLDAP {
		secured := tls.Server(raw, &tls.Config{Certificates: []tls.Certificate{w.certificate}, MinVersion: tls.VersionTLS12})
		if err := secured.HandshakeContext(ctx); err != nil {
			return err
		}
		conn = secured
	}
	for _, step := range []portableLDAPStep{w.acceptor.authenticate, w.offer, w.accept} {
		request, err := ber.ReadPacket(conn)
		if err != nil {
			return err
		}
		w.requests.Add(1)
		if err := step(conn, request); err != nil {
			return err
		}
	}
	peer := &portableSASLPeer{
		Conn: conn, key: w.acceptor.key, mode: w.mode,
		sendSequence: 713, recvSequence: uint64(w.acceptor.authenticator.SeqNumber) + 1, corrupt: w.corrupt,
	}
	w.peer = peer
	for _, step := range w.steps {
		request, err := ber.ReadPacket(peer)
		if err != nil {
			return err
		}
		w.requests.Add(1)
		if err := step(peer, request); err != nil {
			return err
		}
	}
	var extra [1]byte
	_, err = peer.Read(extra[:])
	return err
}

func (w *portableSASLWire) offer(conn net.Conn, request *ber.Packet) error {
	input, err := portableKerberosRequestToken(request)
	if err != nil || len(input) != 0 {
		return errors.New("SASL fixture received an unexpected mechanism token")
	}
	token := &krbgss.WrapToken{Flags: 5, EC: 12, SndSeqNum: 712, Payload: []byte{w.offerMask, 0, 0, 100}}
	if err := token.SetCheckSum(w.acceptor.key, keyusage.GSSAPI_ACCEPTOR_SEAL); err != nil {
		return err
	}
	wire, err := token.Marshal()
	if err != nil {
		return err
	}
	return portableKerberosBindReply(conn, request, 14, wire)
}

func (w *portableSASLWire) accept(conn net.Conn, request *ber.Packet) error {
	wire, err := portableKerberosRequestToken(request)
	if err != nil {
		return err
	}
	var token krbgss.WrapToken
	if err := token.Unmarshal(wire, false); err != nil {
		return err
	}
	if ok, err := token.Verify(w.acceptor.key, keyusage.GSSAPI_INITIATOR_SEAL); err != nil || !ok {
		return errors.New("SASL fixture could not authenticate the client's layer selection")
	}
	if token.SndSeqNum != uint64(w.acceptor.authenticator.SeqNumber) || token.Flags != 4 ||
		!bytes.Equal(token.Payload, []byte{byte(w.mode), 0, 255, 255}) {
		return errors.New("SASL fixture received a different layer, limit or sequence")
	}
	return portableKerberosBindReply(conn, request, 0, nil)
}

func (w *portableSASLWire) DialContext(ctx context.Context, network, address string) (net.Conn, error) {
	host, port, err := net.SplitHostPort(address)
	if err != nil || host != portableTLSHost || network != "tcp" {
		return nil, errors.New("SASL fixture endpoint was not pinned")
	}
	if port == "88" {
		return (&net.Dialer{}).DialContext(ctx, network, w.acceptor.kdc.listener.Addr().String())
	}
	w.attempts.Add(1)
	conn, err := (&net.Dialer{}).DialContext(ctx, network, w.listener.Addr().String())
	if err != nil {
		return nil, err
	}
	return &portableTLSCountedConn{Conn: conn, closes: &w.closes}, nil
}

func (w *portableSASLWire) wait(t *testing.T) {
	t.Helper()
	select {
	case err := <-w.done:
		if err != nil && !errors.Is(err, io.EOF) && !errors.Is(err, net.ErrClosed) {
			t.Fatal(err)
		}
	case <-time.After(12 * time.Second):
		t.Fatal("SASL fixture did not retire")
	}
	if w.attempts.Load() != 1 || w.closes.Load() != 1 {
		t.Fatalf("SASL fixture ownership or fallback violation: connections=%d closes=%d", w.attempts.Load(), w.closes.Load())
	}
}
