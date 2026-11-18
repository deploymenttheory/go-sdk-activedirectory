package acceptance

import (
	"bytes"
	"context"
	"crypto/tls"
	"crypto/x509"
	"errors"
	"io"
	"net"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	adengine "github.com/deploymenttheory/go-sdk-activedirectory/activedirectory/internal/engine"
	admodel "github.com/deploymenttheory/go-sdk-activedirectory/activedirectory/internal/model"
)

func TestPortableTLSVerifiesPrivateCAAndMeasuresBeforeApplicationTraffic(t *testing.T) {
	certificate, roots := portableTLSCertificate(t, portableTLSHost, false, false)
	for _, transport := range []admodel.Transport{admodel.TransportLDAPS, admodel.TransportStartTLS} {
		for _, version := range []uint16{tls.VersionTLS12, tls.VersionTLS13} {
			t.Run(portableTLSFixtureDescription(transport, version), func(t *testing.T) {
				wire := newPortableTLSWire(t, transport, &tls.Config{Certificates: []tls.Certificate{certificate}, MinVersion: version, MaxVersion: version})
				wire.start(t)
				connection, err := adengine.InternalOpenPortableTransportWithDial(t.Context(), portableTLSConfig(transport, roots), wire)
				if err != nil {
					t.Fatal(err)
				}
				observed := connection.InternalProtection
				if !observed.TLSVerified || observed.TLSVersion != version || observed.TLSCipherSuite == 0 || observed.CipherBits < 128 ||
					observed.Complete || observed.ChannelBound || observed.MutualAuthentication || connection.InternalTLSState.PeerCertificates == nil {
					t.Fatalf("unmeasured or invented protection: %+v", observed)
				}
				if observed.Authentication == admodel.AuthenticationSimple {
					t.Fatal("transport asserted successful authentication before bind")
				}
				if _, err := connection.InternalConn.Write([]byte(portableTLSApplicationMarker)); err != nil {
					t.Fatal(err)
				}
				var ack [1]byte
				if _, err := io.ReadFull(connection.InternalConn, ack[:]); err != nil || ack[0] != 1 {
					t.Fatalf("protected application traffic failed: %v", err)
				}
				_ = connection.InternalConn.Close()
				_ = connection.InternalConn.Close()
				if err := wire.wait(t); err != nil || wire.attempts.Load() != 1 || wire.closes.Load() != 1 ||
					wire.application.Load() != int32(len(portableTLSApplicationMarker)) {
					t.Fatalf("ownership or TLS traffic: server=%v attempts=%d closes=%d app=%d",
						err, wire.attempts.Load(), wire.closes.Load(), wire.application.Load())
				}
			})
		}
	}
}

func TestPortableTLSRefusesInvalidPeersBeforeAuthenticationOrMutation(t *testing.T) {
	for _, transport := range []admodel.Transport{admodel.TransportLDAPS, admodel.TransportStartTLS} {
		for _, name := range []string{"wrong-host", "expired", "untrusted", "wrong-usage", "TLS-1.1", "connection-loss"} {
			t.Run(portableTLSFixtureDescription(transport, 0)+"/"+name, func(t *testing.T) {
				serverName := portableTLSHost
				if name == "wrong-host" {
					serverName = "other.ad.sdk.test"
				}
				certificate, roots := portableTLSCertificate(t, serverName, name == "expired", name == "wrong-usage")
				server := &tls.Config{Certificates: []tls.Certificate{certificate}, MinVersion: tls.VersionTLS12}
				if name == "TLS-1.1" {
					server.MinVersion, server.MaxVersion = tls.VersionTLS11, tls.VersionTLS11
				}
				if name == "untrusted" {
					roots = x509.NewCertPool()
				}
				wire := newPortableTLSWire(t, transport, server)
				wire.drop = name == "connection-loss"
				wire.start(t)
				connection, err := adengine.InternalOpenPortableTransportWithDial(t.Context(), portableTLSConfig(transport, roots), wire)
				if connection != nil || !errors.Is(err, admodel.ErrTLSNegotiation) || !errors.Is(err, admodel.ErrConnection) ||
					admodel.Classify(err) != admodel.ClassTransport {
					t.Fatalf("invalid peer became a usable connection: %+v, %v", connection, err)
				}
				_ = wire.wait(t)
				if wire.attempts.Load() != 1 || wire.closes.Load() != 1 || wire.application.Load() != 0 {
					t.Fatalf("authentication/mutation, fallback or leak: attempts=%d closes=%d app=%d",
						wire.attempts.Load(), wire.closes.Load(), wire.application.Load())
				}
			})
		}
	}
}

func TestPortableStartTLSRefusalAndWrongResponseCannotContinue(t *testing.T) {
	for _, name := range []string{"server-refusal", "wrong-message-id", "wrong-operation"} {
		t.Run(name, func(t *testing.T) {
			wire := newPortableTLSWire(t, admodel.TransportStartTLS, nil)
			wire.upgrade = false
			switch name {
			case "server-refusal":
				wire.reply[9] = 52
			case "wrong-message-id":
				wire.reply[4] = 2
			case "wrong-operation":
				wire.reply[5] = 0x61 // BindResponse must not be accepted as StartTLS.
			}
			wire.start(t)
			connection, err := adengine.InternalOpenPortableTransportWithDial(t.Context(), portableTLSConfig(admodel.TransportStartTLS, nil), wire)
			if connection != nil || !errors.Is(err, admodel.ErrTLSNegotiation) {
				t.Fatalf("StartTLS refusal became a usable plaintext connection: %v", err)
			}
			if name == "server-refusal" {
				var ldapErr *admodel.LDAPError
				if !errors.As(err, &ldapErr) || ldapErr.Code != 52 {
					t.Fatalf("lost actual server status: %v", err)
				}
			}
			if err := wire.wait(t); err != nil || wire.extra.Load() != 0 || wire.closes.Load() != 1 || wire.attempts.Load() != 1 {
				t.Fatalf("continued/retried/leaked after refusal: server=%v extra=%d closes=%d attempts=%d",
					err, wire.extra.Load(), wire.closes.Load(), wire.attempts.Load())
			}
		})
	}
}

func TestPortableTLSCancellationRetiresStalledHandshake(t *testing.T) {
	for _, transport := range []admodel.Transport{admodel.TransportLDAPS, admodel.TransportStartTLS} {
		t.Run(portableTLSFixtureDescription(transport, 0), func(t *testing.T) {
			wire := newPortableTLSWire(t, transport, nil)
			wire.stall = true
			wire.start(t)
			ctx, cancel := context.WithCancel(t.Context())
			defer cancel()
			result := make(chan error, 1)
			go func() {
				connection, err := adengine.InternalOpenPortableTransportWithDial(ctx, portableTLSConfig(transport, nil), wire)
				if connection != nil {
					_ = connection.InternalConn.Close()
					result <- errors.New("cancelled handshake returned a connection")
					return
				}
				result <- err
			}()
			select {
			case <-wire.stalled:
			case <-time.After(3 * time.Second):
				t.Fatal("fixture did not reach the TLS handshake")
			}
			cancel()
			select {
			case err := <-result:
				if !errors.Is(err, context.Canceled) || !errors.Is(err, admodel.ErrConnection) {
					t.Fatalf("lost cancellation cause: %v", err)
				}
			case <-time.After(3 * time.Second):
				t.Fatal("handshake cancellation did not retire the socket")
			}
			_ = wire.wait(t)
			if wire.closes.Load() != 1 || wire.attempts.Load() != 1 || wire.application.Load() != 0 {
				t.Fatalf("cancelled handshake leaked/replayed: closes=%d attempts=%d", wire.closes.Load(), wire.attempts.Load())
			}
		})
	}
}

func TestPortableStartTLSCancellationRetiresUnansweredRequest(t *testing.T) {
	wire := newPortableTLSWire(t, admodel.TransportStartTLS, nil)
	wire.stallStartTLS = true
	wire.start(t)
	ctx, cancel := context.WithCancel(t.Context())
	defer cancel()
	result := make(chan error, 1)
	go func() {
		connection, err := adengine.InternalOpenPortableTransportWithDial(ctx, portableTLSConfig(admodel.TransportStartTLS, nil), wire)
		if connection != nil {
			_ = connection.InternalConn.Close()
			result <- errors.New("unanswered StartTLS returned a connection")
			return
		}
		result <- err
	}()
	select {
	case <-wire.stalled:
	case <-time.After(3 * time.Second):
		t.Fatal("fixture did not receive the StartTLS request")
	}
	cancel()
	select {
	case err := <-result:
		if !errors.Is(err, context.Canceled) || !errors.Is(err, admodel.ErrConnection) {
			t.Fatalf("lost StartTLS cancellation: %v", err)
		}
	case <-time.After(3 * time.Second):
		t.Fatal("unanswered StartTLS ignored cancellation")
	}
	if err := wire.wait(t); err != nil || wire.extra.Load() != 0 || wire.closes.Load() != 1 {
		t.Fatalf("continued or leaked during StartTLS: server=%v extra=%d closes=%d", err, wire.extra.Load(), wire.closes.Load())
	}
}

func TestPortableTLSConfiguredTimeoutClosesStalledConnection(t *testing.T) {
	wire := newPortableTLSWire(t, admodel.TransportLDAPS, nil)
	wire.stall = true
	wire.start(t)
	options := portableTLSConfig(admodel.TransportLDAPS, nil)
	options.Timeout = 100 * time.Millisecond
	connection, err := adengine.InternalOpenPortableTransportWithDial(t.Context(), options, wire)
	if connection != nil || !errors.Is(err, context.DeadlineExceeded) || !errors.Is(err, admodel.ErrConnection) {
		t.Fatalf("configured timeout did not bound establishment: %v", err)
	}
	_ = wire.wait(t)
	if wire.attempts.Load() != 1 || wire.closes.Load() != 1 || wire.application.Load() != 0 {
		t.Fatalf("timed out connection retained or replayed: attempts=%d closes=%d app=%d",
			wire.attempts.Load(), wire.closes.Load(), wire.application.Load())
	}
}

func TestPortableTLSOwnershipTransferRemovesEstablishmentCancellation(t *testing.T) {
	certificate, roots := portableTLSCertificate(t, portableTLSHost, false, false)
	wire := newPortableTLSWire(t, admodel.TransportLDAPS, &tls.Config{Certificates: []tls.Certificate{certificate}, MinVersion: tls.VersionTLS12})
	wire.start(t)
	ctx, cancel := context.WithCancel(t.Context())
	defer cancel()
	connection, err := adengine.InternalOpenPortableTransportWithDial(ctx, portableTLSConfig(admodel.TransportLDAPS, roots), wire)
	if err != nil {
		t.Fatal(err)
	}
	cancel()
	// Once returned, the session owns operation cancellation and deadlines.
	// The completed establishment must not close the transferred connection.
	if _, err := connection.InternalConn.Write([]byte(portableTLSApplicationMarker)); err != nil {
		t.Fatal(err)
	}
	var ack [1]byte
	if _, err := io.ReadFull(connection.InternalConn, ack[:]); err != nil {
		t.Fatal(err)
	}
	_ = connection.InternalConn.Close()
	if err := wire.wait(t); err != nil || wire.closes.Load() != 1 {
		t.Fatalf("transferred connection lifetime: server=%v closes=%d", err, wire.closes.Load())
	}
}

type portableRejectDialer struct {
	calls int
}

func (d *portableRejectDialer) DialContext(context.Context, string, string) (net.Conn, error) {
	d.calls++
	return nil, nil
}

func TestPortableTLSRejectsAnonymousAndInsecureSimpleBindBeforeConnecting(t *testing.T) {
	for _, name := range []string{"empty-password", "anonymous", "plaintext"} {
		options := portableTLSConfig(admodel.TransportLDAPS, nil)
		switch name {
		case "empty-password":
			options.Credentials.Password = nil
		case "anonymous":
			options.Credentials.Username = ""
		case "plaintext":
			options.Transport, options.TLS = admodel.TransportLDAP, nil
		}
		dialer := &portableRejectDialer{}
		connection, err := adengine.InternalOpenPortableTransportWithDial(t.Context(), options, dialer)
		if connection != nil || !errors.Is(err, admodel.ErrInvalidConfig) || dialer.calls != 0 {
			t.Fatalf("unsafe simple bind reached a connection: %s, calls=%d, err=%v", name, dialer.calls, err)
		}
	}
}

func TestPortableStartTLSResponseRejectsMalformedAndUnboundedBER(t *testing.T) {
	valid := []byte{0x30, 0x0c, 0x02, 0x01, 0x01, 0x78, 0x07, 0x0a, 0x01, 0x00, 0x04, 0x00, 0x04, 0x00}
	for _, bad := range [][]byte{
		nil,
		{0x30, 0x80},
		{0x30, 0x85},
		{0x30, 0x84, 0x7f, 0xff, 0xff, 0xff},
		{0x30, 0x81},
		{0x31, 0},
		valid[:len(valid)-1],
		{0x30, 0x0c, 0x02, 0x01, 0xff, 0x78, 0x07, 0x0a, 0x01, 0, 0x04, 0, 0x04, 0},
	} {
		if err := adengine.InternalReadPortableStartTLSResponse(bytes.NewReader(bad)); err == nil {
			t.Fatalf("malformed/unbounded response accepted: %x", bad)
		}
	}
	if err := adengine.InternalReadPortableStartTLSResponse(bytes.NewReader(valid)); err != nil {
		t.Fatal(err)
	}
	// LDAP BER permits definite long-form framing; do not accidentally require DER.
	longForm := append([]byte{0x30, 0x84, 0, 0, 0, 12}, valid[2:]...)
	if err := adengine.InternalReadPortableStartTLSResponse(bytes.NewReader(longForm)); err != nil {
		t.Fatalf("valid definite long-form LDAP BER rejected: %v", err)
	}
}

func TestPortableStartTLSResponseNameAndValueAreStrict(t *testing.T) {
	// Independent fixture framing for the optional responseName. The StartTLS
	// responseValue is forbidden even when empty; an unrelated OID is not TLS.
	for _, name := range []string{"1.3.6.1.4.1.1466.20037", "1.3.6.1.4.1.1466.20036"} {
		result := append([]byte{0x0a, 0x01, 0, 0x04, 0, 0x04, 0, 0x8a, byte(len(name))}, name...)
		op := append([]byte{0x78, byte(len(result))}, result...)
		body := append([]byte{0x02, 0x01, 1}, op...)
		response := append([]byte{0x30, byte(len(body))}, body...)
		err := adengine.InternalReadPortableStartTLSResponse(bytes.NewReader(response))
		if (err == nil) != (name == "1.3.6.1.4.1.1466.20037") {
			t.Fatalf("wrong StartTLS responseName decision: %v", err)
		}
	}
	valueResponse := []byte{0x30, 0x0e, 0x02, 0x01, 1, 0x78, 0x09, 0x0a, 0x01, 0, 0x04, 0, 0x04, 0, 0x8b, 0}
	if err := adengine.InternalReadPortableStartTLSResponse(bytes.NewReader(valueResponse)); err == nil {
		t.Fatal("forbidden StartTLS responseValue accepted")
	}
}

func TestPortableStartTLSKeepsStatusAndRedactsServerDiagnostics(t *testing.T) {
	matchedDN, diagnostic := "CN=private-result", "private-server-diagnostic"
	result := []byte{0x0a, 0x01, 52, 0x04, byte(len(matchedDN))}
	result = append(result, matchedDN...)
	result = append(result, 0x04, byte(len(diagnostic)))
	result = append(result, diagnostic...)
	op := append([]byte{0x78, byte(len(result))}, result...)
	body := append([]byte{0x02, 0x01, 1}, op...)
	response := append([]byte{0x30, byte(len(body))}, body...)
	err := adengine.InternalReadPortableStartTLSResponse(bytes.NewReader(response))
	var ldapErr *admodel.LDAPError
	if !errors.As(err, &ldapErr) || ldapErr.Code != 52 || ldapErr.MatchedDN != matchedDN || ldapErr.Diagnostic != diagnostic {
		t.Fatalf("lost structured server refusal: %v", err)
	}
	if strings.Contains(err.Error(), matchedDN) || strings.Contains(err.Error(), diagnostic) {
		t.Fatal("ordinary error logging exposed server diagnostics")
	}
}

type portableDialResult struct {
	connection net.Conn
	err        error
}

func (d portableDialResult) DialContext(context.Context, string, string) (net.Conn, error) {
	return d.connection, d.err
}

func TestPortableTransportRetiresDialerConnectionReturnedAlongsideError(t *testing.T) {
	left, right := net.Pipe()
	t.Cleanup(func() { _ = right.Close() })
	var closes atomic.Int32
	connection, err := adengine.InternalOpenPortableTransportWithDial(
		t.Context(), portableTLSConfig(admodel.TransportLDAPS, nil),
		portableDialResult{connection: &portableTLSCountedConn{Conn: left, closes: &closes}, err: io.ErrUnexpectedEOF},
	)
	if connection != nil || !errors.Is(err, io.ErrUnexpectedEOF) || !errors.Is(err, admodel.ErrConnection) || closes.Load() != 1 {
		t.Fatalf("dial failure lost a returned socket: connection=%v err=%v closes=%d", connection, err, closes.Load())
	}
	connection, err = adengine.InternalOpenPortableTransportWithDial(
		t.Context(), portableTLSConfig(admodel.TransportLDAPS, nil), portableDialResult{},
	)
	if connection != nil || !errors.Is(err, admodel.ErrConnection) {
		t.Fatalf("nil dial result accepted: %v", err)
	}
}

func TestPortableConnectionCauseCannotMaskWriteUncertainty(t *testing.T) {
	if admodel.Classify(admodel.ErrConnection) != admodel.ClassTransport {
		t.Fatal("connection failure lacks a stable transport class")
	}
	uncertain := errors.Join(admodel.ErrConnection, admodel.ErrObjectWriteUncertain, io.ErrUnexpectedEOF)
	if !errors.Is(uncertain, admodel.ErrConnection) || !errors.Is(uncertain, admodel.ErrObjectWriteUncertain) ||
		admodel.Classify(uncertain) != admodel.ClassUncertain {
		t.Fatalf("connection failure hid a possibly submitted write: %v", uncertain)
	}
}

type portablePendingTimerContext struct {
	context.Context
	deadline time.Time
}

func (c portablePendingTimerContext) Deadline() (time.Time, bool) { return c.deadline, true }

func TestPortableDeadlineCauseSurvivesContextTimerScheduling(t *testing.T) {
	pending := portablePendingTimerContext{Context: t.Context(), deadline: time.Now().Add(-time.Second)}
	if context.Cause(pending) != nil {
		t.Fatal("fixture context already observed its delayed timer")
	}
	if err := adengine.InternalConnectionContextCause(pending); !errors.Is(err, context.DeadlineExceeded) {
		t.Fatalf("elapsed socket deadline lost context semantics: %v", err)
	}
	future := portablePendingTimerContext{Context: t.Context(), deadline: time.Now().Add(time.Minute)}
	if err := adengine.InternalConnectionContextCause(future); err != nil {
		t.Fatalf("deadline inferred before expiry: %v", err)
	}
	custom := errors.New("caller stopped the owned operation")
	cancelled, cancel := context.WithCancelCause(t.Context())
	cancel(custom)
	expired := portablePendingTimerContext{Context: cancelled, deadline: pending.deadline}
	if err := adengine.InternalConnectionContextCause(expired); !errors.Is(err, custom) || errors.Is(err, context.DeadlineExceeded) {
		t.Fatalf("deadline replaced an observed caller cancellation: %v", err)
	}
}

func TestPortableTransportPrecancelledContextDoesNotDial(t *testing.T) {
	ctx, cancel := context.WithCancel(t.Context())
	cancel()
	dialer := &portableRejectDialer{}
	connection, err := adengine.InternalOpenPortableTransportWithDial(ctx, portableTLSConfig(admodel.TransportLDAPS, nil), dialer)
	if connection != nil || dialer.calls != 0 || !errors.Is(err, context.Canceled) || !errors.Is(err, admodel.ErrConnection) {
		t.Fatalf("cancelled establishment reached dial: calls=%d err=%v", dialer.calls, err)
	}
}

func FuzzPortableStartTLSResponse(f *testing.F) {
	for _, seed := range [][]byte{
		{},
		{0x30, 0x80},
		{0x30, 0x84, 0xff, 0xff, 0xff, 0xff},
		{0x30, 0x0c, 0x02, 0x01, 0x01, 0x78, 0x07, 0x0a, 0x01, 0x00, 0x04, 0x00, 0x04, 0x00},
	} {
		f.Add(seed)
	}
	f.Fuzz(func(_ *testing.T, data []byte) {
		_ = adengine.InternalReadPortableStartTLSResponse(bytes.NewReader(data))
	})
}
