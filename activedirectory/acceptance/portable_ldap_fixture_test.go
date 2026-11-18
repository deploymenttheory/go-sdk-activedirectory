package acceptance

import (
	"context"
	"crypto/tls"
	"errors"
	"fmt"
	"io"
	"net"
	"runtime"
	"sort"
	"sync/atomic"
	"syscall"
	"testing"
	"time"

	ber "github.com/go-asn1-ber/asn1-ber"

	ldap "github.com/deploymenttheory/go-sdk-activedirectory/3rd_party/ldap/v3"
	adengine "github.com/deploymenttheory/go-sdk-activedirectory/activedirectory/internal/engine"
	admodel "github.com/deploymenttheory/go-sdk-activedirectory/activedirectory/internal/model"
)

type portableLDAPStep func(net.Conn, *ber.Packet) error

type portableLDAPWire struct {
	listener    net.Listener
	certificate tls.Certificate
	transport   admodel.Transport
	steps       []portableLDAPStep
	done        chan error
	attempts    atomic.Int32
	closes      atomic.Int32
	requests    atomic.Int32
	retiring    *atomic.Bool
}

func newPortableLDAPWire(t *testing.T, transport admodel.Transport, certificate tls.Certificate, steps ...portableLDAPStep) *portableLDAPWire {
	t.Helper()
	listener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	wire := &portableLDAPWire{listener: listener, certificate: certificate, transport: transport, steps: steps, done: make(chan error, 1)}
	t.Cleanup(func() { _ = listener.Close() })
	go func() { wire.done <- wire.serve(t.Context()) }()
	return wire
}

func (w *portableLDAPWire) serve(ctx context.Context) error {
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
		request, err := ber.ReadPacket(raw)
		if err != nil {
			return err
		}
		if len(request.Children) != 2 || request.Children[1].Tag != ldap.ApplicationExtendedRequest {
			return fmt.Errorf("owned fixture received credentials before StartTLS")
		}
		if _, err := raw.Write(portableLDAPResult(request, ldap.ApplicationExtendedResponse, 0).Bytes()); err != nil {
			return err
		}
	}
	secured := tls.Server(raw, &tls.Config{Certificates: []tls.Certificate{w.certificate}, MinVersion: tls.VersionTLS12})
	if err := secured.HandshakeContext(ctx); err != nil {
		return err
	}
	for _, step := range w.steps {
		request, err := ber.ReadPacket(secured)
		if err != nil {
			return err
		}
		w.requests.Add(1)
		if err := step(secured, request); err != nil {
			return err
		}
	}
	var extra [1]byte
	_, err = secured.Read(extra[:])
	if errors.Is(err, io.EOF) {
		return nil
	}
	return err
}

func (w *portableLDAPWire) DialContext(ctx context.Context, network, address string) (net.Conn, error) {
	w.attempts.Add(1)
	host, _, err := net.SplitHostPort(address)
	if err != nil || host != portableTLSHost || network != "tcp" {
		return nil, fmt.Errorf("owned fixture endpoint was not pinned")
	}
	connection, err := (&net.Dialer{}).DialContext(ctx, network, w.listener.Addr().String())
	if err != nil {
		return nil, err
	}
	return &portableTLSCountedConn{Conn: connection, closes: &w.closes}, nil
}

func (w *portableLDAPWire) wait(t *testing.T) {
	t.Helper()
	select {
	case err := <-w.done:
		if !portableLDAPFixtureClosed(err, w.retiring != nil && w.retiring.Load()) {
			t.Fatal(err)
		}
	case <-time.After(12 * time.Second):
		t.Fatal("owned LDAP fixture did not stop")
	}
	if w.attempts.Load() != 1 || w.closes.Load() != 1 {
		t.Fatalf("connection ownership: attempts=%d closes=%d", w.attempts.Load(), w.closes.Load())
	}
}

func portableLDAPFixtureClosed(err error, retiring bool) bool {
	if err == nil || errors.Is(err, io.EOF) || errors.Is(err, net.ErrClosed) {
		return true
	}
	var operation *net.OpError
	if !retiring || !errors.As(err, &operation) || (operation.Op != "read" && operation.Op != "write") {
		return false
	}
	if errors.Is(err, syscall.ECONNRESET) || errors.Is(err, syscall.ECONNABORTED) {
		return true
	}
	// Winsock uses different error numbers from Go's portable syscall constants.
	return runtime.GOOS == "windows" && (errors.Is(err, syscall.Errno(10054)) || errors.Is(err, syscall.Errno(10053)))
}

func portableLDAPEnvelope(request *ber.Packet, protocol *ber.Packet, controls ...ldap.Control) *ber.Packet {
	packet := ber.Encode(ber.ClassUniversal, ber.TypeConstructed, ber.TagSequence, nil, "")
	packet.AppendChild(ber.NewInteger(ber.ClassUniversal, ber.TypePrimitive, ber.TagInteger, request.Children[0].Value.(int64), ""))
	packet.AppendChild(protocol)
	if len(controls) > 0 {
		list := ber.Encode(ber.ClassContext, ber.TypeConstructed, 0, nil, "")
		for _, control := range controls {
			list.AppendChild(control.Encode())
		}
		packet.AppendChild(list)
	}
	return packet
}

func portableLDAPResult(request *ber.Packet, tag ber.Tag, code int64, controls ...ldap.Control) *ber.Packet {
	protocol := ber.Encode(ber.ClassApplication, ber.TypeConstructed, tag, nil, "")
	protocol.AppendChild(ber.NewInteger(ber.ClassUniversal, ber.TypePrimitive, ber.TagEnumerated, code, ""))
	protocol.AppendChild(ber.NewString(ber.ClassUniversal, ber.TypePrimitive, ber.TagOctetString, "", ""))
	diagnostic := ""
	if code != 0 {
		diagnostic = "owned-private-diagnostic-not-for-error-logging"
	}
	protocol.AppendChild(ber.NewString(ber.ClassUniversal, ber.TypePrimitive, ber.TagOctetString, diagnostic, ""))
	return portableLDAPEnvelope(request, protocol, controls...)
}

func portableLDAPEntry(request *ber.Packet, attributes map[string][][]byte) *ber.Packet {
	protocol := ber.Encode(ber.ClassApplication, ber.TypeConstructed, ldap.ApplicationSearchResultEntry, nil, "")
	protocol.AppendChild(ber.NewString(ber.ClassUniversal, ber.TypePrimitive, ber.TagOctetString, "CN=owned,DC=ad,DC=sdk,DC=test", ""))
	list := ber.Encode(ber.ClassUniversal, ber.TypeConstructed, ber.TagSequence, nil, "")
	names := make([]string, 0, len(attributes))
	for name := range attributes {
		names = append(names, name)
	}
	sort.Strings(names)
	for _, name := range names {
		attribute := ber.Encode(ber.ClassUniversal, ber.TypeConstructed, ber.TagSequence, nil, "")
		attribute.AppendChild(ber.NewString(ber.ClassUniversal, ber.TypePrimitive, ber.TagOctetString, name, ""))
		values := ber.Encode(ber.ClassUniversal, ber.TypeConstructed, ber.TagSet, nil, "")
		for _, bytes := range attributes[name] {
			value := ber.Encode(ber.ClassUniversal, ber.TypePrimitive, ber.TagOctetString, nil, "")
			value.Data.Write(bytes)
			values.AppendChild(value)
		}
		attribute.AppendChild(values)
		list.AppendChild(attribute)
	}
	protocol.AppendChild(list)
	return portableLDAPEnvelope(request, protocol)
}

func portableLDAPBind(code int64) portableLDAPStep {
	return func(connection net.Conn, request *ber.Packet) error {
		if len(request.Children) != 2 || request.Children[1].Tag != ldap.ApplicationBindRequest {
			return fmt.Errorf("expected one explicit simple bind")
		}
		bind := request.Children[1]
		if len(bind.Children) != 3 || bind.Children[2].ClassType != ber.ClassContext || bind.Children[2].Tag != 0 {
			return fmt.Errorf("unexpected authentication mechanism")
		}
		if bind.Children[1].Value != "fixture-user" || bind.Children[2].Data.String() != "fixture-only-not-a-lab-secret" {
			return fmt.Errorf("configured identity was not used exactly")
		}
		_, err := connection.Write(portableLDAPResult(request, ldap.ApplicationBindResponse, code).Bytes())
		return err
	}
}

func portableLDAPPaging(request *ber.Packet) (uint32, []byte, error) {
	if len(request.Children) != 3 {
		return 0, nil, fmt.Errorf("missing paging controls")
	}
	for _, control := range request.Children[2].Children {
		if len(control.Children) < 2 || control.Children[0].Value != ldap.ControlTypePaging {
			continue
		}
		if len(control.Children) != 3 || control.Children[1].Value != true {
			return 0, nil, fmt.Errorf("paging was not critical")
		}
		value, err := ber.DecodePacketErr(control.Children[2].Data.Bytes())
		if err != nil || len(value.Children) != 2 {
			return 0, nil, fmt.Errorf("invalid page value")
		}
		return uint32(value.Children[0].Value.(int64)), value.Children[1].Data.Bytes(), nil
	}
	return 0, nil, fmt.Errorf("missing paging control")
}

func portableLDAPSession(t *testing.T, config admodel.Config, wire *portableLDAPWire) (admodel.InternalDirectorySession, *adengine.Client) {
	t.Helper()
	session, err := adengine.InternalDialPortableWithDial(t.Context(), config, wire)
	if err != nil {
		t.Fatal(err)
	}
	client := adengine.InternalNewClient(config, session)
	t.Cleanup(func() { _ = client.Close() })
	return session, client
}
