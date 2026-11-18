package acceptance

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"errors"
	"fmt"
	"io"
	"math/big"
	"net"
	"sync/atomic"
	"testing"
	"time"

	admodel "github.com/deploymenttheory/go-sdk-activedirectory/activedirectory/internal/model"
)

const portableTLSHost = "dc.ad.sdk.test"

const portableTLSApplicationMarker = "only-after-verified-tls"

func portableTLSCertificate(t *testing.T, name string, expired, wrongUsage bool) (tls.Certificate, *x509.CertPool) {
	t.Helper()
	caPublic, caPrivate, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	now := time.Now()
	caTemplate := &x509.Certificate{
		SerialNumber: big.NewInt(1), Subject: pkix.Name{CommonName: "owned portable TLS fixture"},
		NotBefore: now.Add(-24 * time.Hour), NotAfter: now.Add(24 * time.Hour),
		IsCA: true, BasicConstraintsValid: true, KeyUsage: x509.KeyUsageCertSign,
	}
	caDER, err := x509.CreateCertificate(rand.Reader, caTemplate, caTemplate, caPublic, caPrivate)
	if err != nil {
		t.Fatal(err)
	}
	ca, err := x509.ParseCertificate(caDER)
	if err != nil {
		t.Fatal(err)
	}
	leafPublic, leafPrivate, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	leaf := &x509.Certificate{
		SerialNumber: big.NewInt(2), DNSNames: []string{name},
		NotBefore: now.Add(-2 * time.Hour), NotAfter: now.Add(time.Hour),
		KeyUsage: x509.KeyUsageDigitalSignature, ExtKeyUsage: []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
	}
	if expired {
		leaf.NotAfter = now.Add(-time.Hour)
	}
	if wrongUsage {
		leaf.ExtKeyUsage = []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth}
	}
	leafDER, err := x509.CreateCertificate(rand.Reader, leaf, ca, leafPublic, caPrivate)
	if err != nil {
		t.Fatal(err)
	}
	roots := x509.NewCertPool()
	roots.AddCert(ca)
	return tls.Certificate{Certificate: [][]byte{leafDER, caDER}, PrivateKey: leafPrivate}, roots
}

type portableTLSWire struct {
	listener      net.Listener
	tlsConfig     *tls.Config
	transport     admodel.Transport
	reply         []byte
	upgrade       bool
	stall         bool
	stallStartTLS bool
	drop          bool
	stalled       chan struct{}
	done          chan error
	attempts      atomic.Int32
	closes        atomic.Int32
	application   atomic.Int32
	extra         atomic.Int32
}

func newPortableTLSWire(t *testing.T, transport admodel.Transport, server *tls.Config) *portableTLSWire {
	t.Helper()
	listener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	wire := &portableTLSWire{
		listener: listener, tlsConfig: server, transport: transport,
		reply:   []byte{0x30, 0x0c, 0x02, 0x01, 0x01, 0x78, 0x07, 0x0a, 0x01, 0x00, 0x04, 0x00, 0x04, 0x00},
		upgrade: true, stalled: make(chan struct{}), done: make(chan error, 1),
	}
	t.Cleanup(func() { _ = wire.listener.Close() })
	return wire
}

func (w *portableTLSWire) start(t *testing.T) {
	t.Helper()
	go func() { w.done <- w.serve(t.Context()) }()
}

func (w *portableTLSWire) serve(ctx context.Context) error {
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
	if w.transport == admodel.TransportStartTLS {
		request := make([]byte, 31)
		if _, err := io.ReadFull(raw, request); err != nil {
			return err
		}
		expected := append([]byte{0x30, 0x1d, 0x02, 0x01, 0x01, 0x77, 0x18, 0x80, 0x16}, "1.3.6.1.4.1.1466.20037"...)
		if !bytes.Equal(request, expected) {
			return errors.New("received authentication or a wrong PDU before StartTLS")
		}
		if w.stallStartTLS {
			close(w.stalled)
			n, err := io.Copy(io.Discard, raw)
			w.extra.Add(int32(n))
			return err
		}
		// Fragment the result independently of TLS to exercise bounded framing.
		for _, value := range w.reply {
			if _, err := raw.Write([]byte{value}); err != nil {
				return err
			}
		}
		if !w.upgrade {
			var extra [1]byte
			n, err := raw.Read(extra[:])
			w.extra.Add(int32(n))
			if n != 0 {
				return errors.New("client continued after StartTLS refusal")
			}
			if errors.Is(err, io.EOF) {
				return nil
			}
			return err
		}
	}
	if w.drop {
		return nil
	}
	if w.stall {
		var first [1]byte
		if _, err := io.ReadFull(raw, first[:]); err != nil {
			return err
		}
		if first[0] != 0x16 {
			return errors.New("non-TLS bytes before handshake")
		}
		close(w.stalled)
		_, err := io.Copy(io.Discard, raw)
		return err
	}
	secured := tls.Server(raw, w.tlsConfig)
	if err := secured.HandshakeContext(ctx); err != nil {
		return err
	}
	marker := make([]byte, len(portableTLSApplicationMarker))
	n, err := io.ReadFull(secured, marker)
	w.application.Add(int32(n))
	if err != nil {
		return err
	}
	if string(marker) != portableTLSApplicationMarker {
		return errors.New("unexpected application bytes")
	}
	if _, err := secured.Write([]byte{1}); err != nil {
		return err
	}
	var end [1]byte
	_, err = secured.Read(end[:])
	if errors.Is(err, io.EOF) {
		return nil
	}
	return err
}

type portableTLSCountedConn struct {
	net.Conn
	closes *atomic.Int32
}

func (c *portableTLSCountedConn) Close() error {
	c.closes.Add(1)
	return c.Conn.Close()
}

func (w *portableTLSWire) DialContext(ctx context.Context, network, address string) (net.Conn, error) {
	w.attempts.Add(1)
	host, _, err := net.SplitHostPort(address)
	if err != nil || host != portableTLSHost || network != "tcp" {
		return nil, errors.New("transport did not pin the configured DNS endpoint")
	}
	conn, err := (&net.Dialer{}).DialContext(ctx, network, w.listener.Addr().String())
	if err != nil {
		return nil, err
	}
	return &portableTLSCountedConn{Conn: conn, closes: &w.closes}, nil
}

func (w *portableTLSWire) wait(t *testing.T) error {
	t.Helper()
	select {
	case err := <-w.done:
		return err
	case <-time.After(12 * time.Second):
		t.Fatal("owned TLS fixture did not terminate")
		return nil
	}
}

func portableTLSConfig(transport admodel.Transport, roots *x509.CertPool) admodel.Config {
	return admodel.Config{
		Backend: admodel.BackendPortable, Endpoint: admodel.Endpoint{Host: portableTLSHost},
		Transport: transport, Authentication: admodel.AuthenticationSimple,
		Credentials: &admodel.Credentials{Username: "fixture-user", Password: []byte("fixture-only-not-a-lab-secret")},
		TLS:         &admodel.TLSOptions{RootCAs: roots}, Timeout: 5 * time.Second,
	}
}

func portableTLSFixtureDescription(transport admodel.Transport, version uint16) string {
	return fmt.Sprintf("transport-%d/TLS-%x", transport, version)
}
