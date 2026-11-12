package main

import (
	"bytes"
	"context"
	"crypto/sha256"
	"crypto/tls"
	"crypto/x509"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net"
	"os"
	"path/filepath"
	"testing"
	"time"
)

var (
	startTLSRequest = append(
		[]byte{0x30, 0x1d, 0x02, 0x01, 0x2a, 0x77, 0x18, 0x80, 0x16},
		[]byte("1.3.6.1.4.1.1466.20037")...)
	startTLSResponse = []byte{
		0x30,
		0x0c,
		0x02,
		0x01,
		0x2a,
		0x78,
		0x07,
		0x0a,
		0x01,
		0x00,
		0x04,
		0x00,
		0x04,
		0x00,
	}
	bindRequest = []byte{
		0x30,
		0x0c,
		0x02,
		0x01,
		0x01,
		0x60,
		0x07,
		0x02,
		0x01,
		0x03,
		0x04,
		0x00,
		0x80,
		0x00,
	}
)

func testCertificates(t *testing.T) (string, *x509.CertPool) {
	t.Helper()
	dir := filepath.Join(t.TempDir(), "certificates")
	if err := run(
		context.Background(),
		[]string{"generate", "-dir", dir, "-server", "dc2.ad.sdk.test"},
	); err != nil {
		t.Fatal(err)
	}
	data, err := os.ReadFile(filepath.Join(dir, "trusted-root.pem"))
	if err != nil {
		t.Fatal(err)
	}
	roots := x509.NewCertPool()
	roots.AppendCertsFromPEM(data)
	return dir, roots
}

func startPeer(t *testing.T, dir, mode, name string, extra ...string) (string, func() peerResult) {
	t.Helper()
	output := t.TempDir()
	ready, result := filepath.Join(output, "ready.json"), filepath.Join(output, "result.json")
	ctx, cancel := context.WithCancel(context.Background())
	t.Cleanup(cancel)
	args := []string{
		"serve",
		"-mode",
		mode,
		"-listen",
		"127.0.0.1:0",
		"-cert",
		filepath.Join(dir, name+".pem"),
		"-key",
		filepath.Join(dir, name+"-key.pem"),
		"-ready",
		ready,
		"-result",
		result,
		"-timeout",
		"5s",
	}
	args = append(args, extra...)
	done := make(chan error, 1)
	go func() { done <- run(ctx, args) }()
	var signal struct {
		Address string `json:"address"`
	}
	deadline := time.Now().Add(5 * time.Second)
	for signal.Address == "" && time.Now().Before(deadline) {
		select {
		case err := <-done:
			t.Fatalf("peer exited before readiness: %v", err)
		default:
		}
		data, err := os.ReadFile(ready)
		if err == nil {
			if err := json.Unmarshal(data, &signal); err != nil {
				t.Fatalf("readiness was not atomic: %v", err)
			}
		}
		time.Sleep(time.Millisecond)
	}
	if signal.Address == "" {
		t.Fatal("no readiness signal")
	}
	return signal.Address, func() peerResult {
		t.Helper()
		select {
		case err := <-done:
			if err != nil {
				t.Fatal(err)
			}
		case <-time.After(6 * time.Second):
			t.Fatal("peer did not finish")
		}
		data, err := os.ReadFile(result)
		if err != nil {
			t.Fatal(err)
		}
		var evidence peerResult
		if err := json.Unmarshal(data, &evidence); err != nil {
			t.Fatal(err)
		}
		return evidence
	}
}

func connectPeer(t *testing.T, address, mode string) net.Conn {
	t.Helper()
	conn, err := net.DialTimeout("tcp", address, time.Second)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { conn.Close() })
	conn.SetDeadline(time.Now().Add(4 * time.Second))
	if mode == "starttls" {
		// Long-form BER lengths and fragmented writes occur with WinLDAP.
		request := append([]byte{0x30, 0x84, 0, 0, 0, 0x1d}, startTLSRequest[2:]...)
		for _, b := range request {
			if _, err := conn.Write([]byte{b}); err != nil {
				t.Fatal(err)
			}
		}
		response := make([]byte, len(startTLSResponse))
		if _, err := io.ReadFull(
			conn,
			response,
		); err != nil ||
			!bytes.Equal(response, startTLSResponse) {
			t.Fatalf("StartTLS response = %x, %v", response, err)
		}
	}
	return conn
}

func TestPeerRecordsCertificateSelectionWhenClientRejects(t *testing.T) {
	dir, roots := testCertificates(t)
	for _, mode := range []string{"ldaps", "starttls"} {
		for _, name := range []string{"expired", "wrong-host", "untrusted"} {
			t.Run(mode+"/"+name, func(t *testing.T) {
				upstream, err := net.ListenTCP("tcp", &net.TCPAddr{IP: net.IPv4(127, 0, 0, 1)})
				if err != nil {
					t.Fatal(err)
				}
				defer upstream.Close()
				address, result := startPeer(
					t,
					dir,
					mode,
					name,
					"-upstream",
					upstream.Addr().String(),
					"-upstream-ca",
					filepath.Join(dir, "trusted-root.pem"),
					"-upstream-name",
					"dc2.ad.sdk.test",
				)
				conn := tls.Client(
					connectPeer(t, address, mode),
					&tls.Config{
						RootCAs:    roots,
						ServerName: "dc2.ad.sdk.test",
						MinVersion: tls.VersionTLS12,
					},
				)
				handshakeErr := conn.Handshake()
				if handshakeErr == nil {
					t.Fatal("client accepted invalid certificate")
				}
				var actualLeaf *x509.Certificate
				var invalid x509.CertificateInvalidError
				var wrongHost x509.HostnameError
				var unknown x509.UnknownAuthorityError
				switch {
				case name == "expired" && errors.As(handshakeErr, &invalid) && invalid.Reason == x509.Expired:
					actualLeaf = invalid.Cert
				case name == "wrong-host" && errors.As(handshakeErr, &wrongHost):
					actualLeaf = wrongHost.Certificate
				case name == "untrusted" && errors.As(handshakeErr, &unknown):
					actualLeaf = unknown.Cert
				default:
					t.Fatalf("wrong rejection reason: %v", handshakeErr)
				}
				conn.Close()
				evidence := result()
				if len(evidence.Connections) != 1 {
					t.Fatalf("connection evidence: %+v", evidence)
				}
				got := evidence.Connections[0]
				if got.SelectedCertificate == nil || got.SelectedCertificate.SHA256 == "" {
					t.Fatal("missing certificate selection evidence")
				}
				if got.SelectedCertificate.SHA256 != evidence.ConfiguredCertificate.SHA256 ||
					got.HandshakeComplete ||
					got.BindRequests != 0 ||
					got.LDAPBytesForwarded != 0 ||
					got.ErrorCategory == "" {
					t.Fatalf("incorrect rejection evidence: %+v", got)
				}
				if got.SelectedCertificate.SHA256 != fmt.Sprintf(
					"%x",
					sha256.Sum256(actualLeaf.Raw),
				) {
					t.Fatal(
						"selected fingerprint differs from the leaf actually received by the client",
					)
				}
				upstream.SetDeadline(time.Now().Add(10 * time.Millisecond))
				if unexpected, err := upstream.Accept(); err == nil {
					unexpected.Close()
					t.Fatal("rejected front-end TLS connected to upstream")
				}
			})
		}
	}
}

func TestValidPeerForwardsBindAndReadToValidatedTLSUpstream(t *testing.T) {
	dir, roots := testCertificates(t)
	identity, err := tls.LoadX509KeyPair(
		filepath.Join(dir, "valid.pem"),
		filepath.Join(dir, "valid-key.pem"),
	)
	if err != nil {
		t.Fatal(err)
	}
	for _, mode := range []string{"ldaps", "starttls"} {
		t.Run(mode, func(t *testing.T) {
			upstream, err := tls.Listen(
				"tcp",
				"127.0.0.1:0",
				&tls.Config{
					Certificates: []tls.Certificate{identity},
					MinVersion:   tls.VersionTLS12,
				},
			)
			if err != nil {
				t.Fatal(err)
			}
			defer upstream.Close()
			bindResponse := []byte{
				0x30,
				0x0c,
				0x02,
				0x01,
				0x01,
				0x61,
				0x07,
				0x0a,
				0x01,
				0x00,
				0x04,
				0x00,
				0x04,
				0x00,
			}
			// The upstream is a wire sentinel, not a directory implementation.
			searchRequest := []byte{0x30, 0x05, 0x02, 0x01, 0x02, 0x63, 0x00}
			searchResponse := []byte{
				0x30,
				0x0c,
				0x02,
				0x01,
				0x02,
				0x65,
				0x07,
				0x0a,
				0x01,
				0x00,
				0x04,
				0x00,
				0x04,
				0x00,
			}
			upstreamDone := make(chan error, 1)
			go func() {
				conn, err := upstream.Accept()
				if err != nil {
					upstreamDone <- err
					return
				}
				defer conn.Close()
				conn.SetDeadline(time.Now().Add(4 * time.Second))
				for i, request := range [][]byte{bindRequest, searchRequest} {
					buffer := make([]byte, len(request))
					if _, err := io.ReadFull(
						conn,
						buffer,
					); err != nil ||
						!bytes.Equal(buffer, request) {
						upstreamDone <- errFraming
						return
					}
					if _, err := conn.Write([][]byte{bindResponse, searchResponse}[i]); err != nil {
						upstreamDone <- err
						return
					}
				}
				upstreamDone <- nil
			}()
			address, result := startPeer(
				t,
				dir,
				mode,
				"valid",
				"-upstream",
				upstream.Addr().String(),
				"-upstream-ca",
				filepath.Join(dir, "trusted-root.pem"),
				"-upstream-name",
				"dc2.ad.sdk.test",
			)
			conn := tls.Client(
				connectPeer(t, address, mode),
				&tls.Config{
					RootCAs:    roots,
					ServerName: "dc2.ad.sdk.test",
					MinVersion: tls.VersionTLS12,
				},
			)
			for i, request := range [][]byte{bindRequest, searchRequest} {
				if _, err := conn.Write(request); err != nil {
					t.Fatal(err)
				}
				expected := [][]byte{bindResponse, searchResponse}[i]
				buffer := make([]byte, len(expected))
				if _, err := io.ReadFull(
					conn,
					buffer,
				); err != nil ||
					!bytes.Equal(buffer, expected) {
					t.Fatalf("proxy response %x: %v", buffer, err)
				}
			}
			conn.Close()
			if err := <-upstreamDone; err != nil {
				t.Fatal(err)
			}
			got := result().Connections[0]
			if !got.HandshakeComplete || !got.UpstreamHandshakeComplete || got.BindRequests != 1 ||
				got.LDAPBytesForwarded != int64(len(bindRequest)+len(searchRequest)) ||
				got.UpstreamBytesReceived != int64(len(bindResponse)+len(searchResponse)) {
				t.Fatalf("proxy evidence: %+v", got)
			}
		})
	}
}

func TestPeerRejectsInvalidUpstreamBeforeForwardingLDAP(t *testing.T) {
	dir, roots := testCertificates(t)
	identity, err := tls.LoadX509KeyPair(
		filepath.Join(dir, "wrong-host.pem"),
		filepath.Join(dir, "wrong-host-key.pem"),
	)
	if err != nil {
		t.Fatal(err)
	}
	upstream, err := tls.Listen(
		"tcp",
		"127.0.0.1:0",
		&tls.Config{Certificates: []tls.Certificate{identity}, MinVersion: tls.VersionTLS12},
	)
	if err != nil {
		t.Fatal(err)
	}
	defer upstream.Close()
	observed := make(chan int, 1)
	go func() {
		conn, err := upstream.Accept()
		if err != nil {
			observed <- -1
			return
		}
		defer conn.Close()
		conn.SetDeadline(time.Now().Add(4 * time.Second))
		buffer := make([]byte, 128)
		n, _ := conn.Read(buffer)
		observed <- n
	}()
	address, result := startPeer(t, dir, "ldaps", "valid", "-upstream", upstream.Addr().String(),
		"-upstream-ca", filepath.Join(dir, "trusted-root.pem"), "-upstream-name", "dc2.ad.sdk.test")
	conn := tls.Client(
		connectPeer(t, address, "ldaps"),
		&tls.Config{RootCAs: roots, ServerName: "dc2.ad.sdk.test", MinVersion: tls.VersionTLS12},
	)
	conn.Write(bindRequest)
	var response [1]byte
	conn.Read(response[:])
	conn.Close()
	got := result().Connections[0]
	if !got.HandshakeComplete || got.UpstreamHandshakeComplete || got.LDAPBytesForwarded != 0 ||
		got.UpstreamErrorCategory == "" {
		t.Fatalf("invalid upstream evidence: %+v", got)
	}
	if n := <-observed; n != 0 {
		t.Fatalf("invalid upstream received %d LDAP bytes", n)
	}
}
