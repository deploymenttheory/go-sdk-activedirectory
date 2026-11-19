package acceptance

import (
	"context"
	"encoding/binary"
	"errors"
	"io"
	"net"
	"strings"
	"sync"
	"testing"
	"time"

	"golang.org/x/net/dns/dnsmessage"
)

type portableDiscoveryDNSWire struct {
	udp      net.PacketConn
	tcp      net.Listener
	scenario string
	mu       sync.Mutex
	queries  []string
	networks []string
	failures []error
	workers  sync.WaitGroup
}

func newPortableDiscoveryDNSWire(t *testing.T, scenario string) *portableDiscoveryDNSWire {
	t.Helper()
	// Windows UDP ephemeral allocation can select a TCP-excluded port. Let
	// TCP choose an available port first, then co-allocate UDP on that port.
	// Bounded fixture allocation retries never retry an SDK DNS request.
	var udp net.PacketConn
	var tcp net.Listener
	var err error
	for range 16 {
		tcp, err = net.Listen("tcp", "127.0.0.1:0")
		if err != nil {
			t.Fatal(err)
		}
		udp, err = net.ListenPacket("udp", tcp.Addr().String())
		if err == nil {
			break
		}
		_ = tcp.Close()
	}
	if err != nil {
		t.Fatal(err)
	}
	wire := &portableDiscoveryDNSWire{udp: udp, tcp: tcp, scenario: scenario}
	wire.workers.Add(2)
	go wire.serveUDP()
	go wire.serveTCP()
	t.Cleanup(func() {
		_ = udp.Close()
		_ = tcp.Close()
		wire.workers.Wait()
		wire.mu.Lock()
		defer wire.mu.Unlock()
		if len(wire.failures) != 0 {
			t.Errorf("owned DNS fixture errors: %v", wire.failures)
		}
	})
	return wire
}

func (w *portableDiscoveryDNSWire) resolver() *net.Resolver {
	return &net.Resolver{PreferGo: true, StrictErrors: true, Dial: func(ctx context.Context, network, _ string) (net.Conn, error) {
		if network != "udp" && network != "tcp" {
			return nil, errors.New("unexpected owned DNS network")
		}
		return (&net.Dialer{}).DialContext(ctx, network, w.udp.LocalAddr().String())
	}}
}

func (w *portableDiscoveryDNSWire) failed(err error) {
	if err != nil && !errors.Is(err, net.ErrClosed) && !errors.Is(err, io.EOF) {
		w.mu.Lock()
		w.failures = append(w.failures, err)
		w.mu.Unlock()
	}
}

func (w *portableDiscoveryDNSWire) serveUDP() {
	defer w.workers.Done()
	buffer := make([]byte, 65535)
	for {
		size, address, err := w.udp.ReadFrom(buffer)
		if err != nil {
			w.failed(err)
			return
		}
		reply, err := w.response(buffer[:size], "udp")
		if err != nil {
			w.failed(err)
			continue
		}
		if reply != nil {
			_, err = w.udp.WriteTo(reply, address)
			w.failed(err)
		}
	}
}

func (w *portableDiscoveryDNSWire) serveTCP() {
	defer w.workers.Done()
	for {
		connection, err := w.tcp.Accept()
		if err != nil {
			w.failed(err)
			return
		}
		w.workers.Add(1)
		go func() {
			defer w.workers.Done()
			defer connection.Close()
			if err := connection.SetDeadline(time.Now().Add(3 * time.Second)); err != nil {
				w.failed(err)
				return
			}
			var header [2]byte
			if _, err := io.ReadFull(connection, header[:]); err != nil {
				w.failed(err)
				return
			}
			query := make([]byte, int(binary.BigEndian.Uint16(header[:])))
			if _, err := io.ReadFull(connection, query); err != nil {
				w.failed(err)
				return
			}
			reply, err := w.response(query, "tcp")
			if err != nil {
				w.failed(err)
				return
			}
			if reply == nil {
				return
			}
			binary.BigEndian.PutUint16(header[:], uint16(len(reply)))
			frame := append(header[:], reply...)
			_, err = io.Copy(connection, strings.NewReader(string(frame)))
			w.failed(err)
		}()
	}
}

func discoveryDNSName(name string) dnsmessage.Name {
	value, err := dnsmessage.NewName(name)
	if err != nil {
		panic("invalid literal owned DNS fixture name")
	}
	return value
}

func (w *portableDiscoveryDNSWire) response(data []byte, network string) ([]byte, error) {
	var request dnsmessage.Message
	if err := request.Unpack(data); err != nil {
		return nil, err
	}
	if len(request.Questions) != 1 {
		return nil, errors.New("owned DNS fixture expected one question")
	}
	question := request.Questions[0]
	name := question.Name.String()
	w.mu.Lock()
	w.queries = append(w.queries, name)
	w.networks = append(w.networks, network)
	w.mu.Unlock()
	if w.scenario == "stalled" {
		return nil, nil
	}
	response := dnsmessage.Message{Header: dnsmessage.Header{ID: request.Header.ID, Response: true, Authoritative: true, RecursionAvailable: true}, Questions: request.Questions}
	if question.Type == dnsmessage.TypeSRV {
		if w.scenario == "truncated" && network == "udp" {
			response.Header.Truncated = true
			return response.Pack()
		}
		if w.scenario == "missing" {
			response.Header.RCode = dnsmessage.RCodeNameError
			return response.Pack()
		}
		if w.scenario == "empty" {
			return response.Pack()
		}
		owner := question.Name
		if w.scenario == "wrong-owner" {
			owner = discoveryDNSName("_ldap._tcp.dc._msdcs.wrong.test.")
		}
		ports := []uint16{389, 389}
		if w.scenario == "two-ports" {
			ports[1] = 1389
		}
		for i, port := range ports {
			target := "DC.AD.SDK.TEST."
			if w.scenario == "alias" {
				target = "alias.ad.sdk.test."
			}
			if w.scenario == "bad-host" {
				target = "bad_host.ad.sdk.test."
			}
			if w.scenario == "partial-invalid" && i == 1 {
				target = "bad@host.ad.sdk.test."
			}
			if w.scenario == "unavailable" {
				target = "."
				port = 0
			}
			response.Answers = append(
				response.Answers,
				dnsmessage.Resource{
					Header: dnsmessage.ResourceHeader{Name: owner, Type: dnsmessage.TypeSRV, Class: dnsmessage.ClassINET, TTL: 30},
					Body:   &dnsmessage.SRVResource{Priority: uint16(i), Weight: uint16(10 + i), Port: port, Target: discoveryDNSName(target)},
				},
			)
			if w.scenario == "unavailable" {
				break
			}
		}
	} else {
		canonical := question.Name
		if strings.EqualFold(name, "alias.ad.sdk.test.") {
			canonical = discoveryDNSName(portableTLSHost + ".")
			response.Answers = append(
				response.Answers,
				dnsmessage.Resource{
					Header: dnsmessage.ResourceHeader{Name: question.Name, Type: dnsmessage.TypeCNAME, Class: dnsmessage.ClassINET, TTL: 30},
					Body:   &dnsmessage.CNAMEResource{CNAME: canonical},
				},
			)
		}
		if w.scenario != "missing-address" {
			if question.Type == dnsmessage.TypeA || question.Type == dnsmessage.TypeCNAME {
				for _, last := range []byte{1, 2} {
					response.Answers = append(
						response.Answers,
						dnsmessage.Resource{
							Header: dnsmessage.ResourceHeader{Name: canonical, Type: dnsmessage.TypeA, Class: dnsmessage.ClassINET, TTL: 30},
							Body:   &dnsmessage.AResource{A: [4]byte{127, 0, 0, last}},
						},
					)
				}
			} else if question.Type == dnsmessage.TypeAAAA {
				response.Answers = append(
					response.Answers,
					dnsmessage.Resource{
						Header: dnsmessage.ResourceHeader{Name: canonical, Type: dnsmessage.TypeAAAA, Class: dnsmessage.ClassINET, TTL: 30},
						Body:   &dnsmessage.AAAAResource{AAAA: [16]byte{15: 1}},
					},
				)
			}
		}
	}
	return response.Pack()
}
