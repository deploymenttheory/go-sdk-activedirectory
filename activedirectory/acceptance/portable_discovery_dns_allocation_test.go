package acceptance

import (
	"errors"
	"net"
	"os"
	"testing"
)

type discoveryDNSAllocationListener struct {
	net.Listener
	closed bool
}

func (listener *discoveryDNSAllocationListener) Close() error {
	listener.closed = true
	return listener.Listener.Close()
}

func TestPortableDiscoveryDNSAllocatesEachProtocolIndependently(t *testing.T) {
	var tcpCalls, udpCalls int
	listenTCP := func(network, address string) (net.Listener, error) {
		tcpCalls++
		return net.Listen(network, address)
	}
	listenUDP := func(network, address string) (net.PacketConn, error) {
		udpCalls++
		// Model a valid TCP port excluded for UDP, without changing host settings.
		if address != "127.0.0.1:0" {
			return nil, os.ErrPermission
		}
		return net.ListenPacket(network, address)
	}
	tcp, udp, err := listenPortableDiscoveryDNS(listenTCP, listenUDP)
	if err != nil {
		t.Fatalf("TCP-selected UDP exclusion prevented independent fixture allocation: %v", err)
	}
	t.Cleanup(func() {
		_ = tcp.Close()
		_ = udp.Close()
	})
	if tcpCalls != 1 || udpCalls != 1 {
		t.Fatal("fixture allocation retried instead of asking each protocol for its own port")
	}
}

func TestPortableDiscoveryDNSAllocationClosesTCPOnUDPFailure(t *testing.T) {
	listener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	tracked := &discoveryDNSAllocationListener{Listener: listener}
	t.Cleanup(func() { _ = tracked.Close() })
	var udpCalls int
	tcp, udp, err := listenPortableDiscoveryDNS(
		func(_, _ string) (net.Listener, error) { return tracked, nil },
		func(_, _ string) (net.PacketConn, error) {
			udpCalls++
			return nil, os.ErrPermission
		},
	)
	if !errors.Is(err, os.ErrPermission) || tcp != nil || udp != nil || !tracked.closed || udpCalls != 1 {
		t.Fatal("UDP failure leaked its TCP listener, hid the cause, or retried")
	}
}

func TestPortableDiscoveryDNSAllocationStopsOnTCPFailure(t *testing.T) {
	var udpCalls int
	tcp, udp, err := listenPortableDiscoveryDNS(
		func(_, _ string) (net.Listener, error) { return nil, os.ErrPermission },
		func(_, _ string) (net.PacketConn, error) {
			udpCalls++
			return nil, os.ErrPermission
		},
	)
	if !errors.Is(err, os.ErrPermission) || tcp != nil || udp != nil || udpCalls != 0 {
		t.Fatal("TCP failure attempted another transport or hid its cause")
	}
}
