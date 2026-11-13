package main

import (
	"bytes"
	"context"
	"crypto/tls"
	"encoding/json"
	"io"
	"net"
	"os"
	"path/filepath"
	"testing"
	"time"
)

func TestStartTLSRejectsMalformedAndPlaintextRequests(t *testing.T) {
	dir, _ := testCertificates(t)
	wrongOID := append([]byte(nil), startTLSRequest...)
	wrongOID[len(wrongOID)-1] = '8'
	for _, tc := range []struct {
		name     string
		data     []byte
		category string
		binds    int
	}{
		{"indefinite", []byte{0x30, 0x80}, "invalid_ldap_frame", 0},
		{"oversize", []byte{0x30, 0x84, 0x7f, 0xff, 0xff, 0xff}, "invalid_ldap_frame", 0},
		{"truncated", []byte{0x30, 0x10, 0x02}, "invalid_ldap_frame", 0},
		{"wrong-oid", wrongOID, "starttls_required", 0},
		{"plaintext-bind", bindRequest, "starttls_required", 1},
	} {
		t.Run(tc.name, func(t *testing.T) {
			address, result := startPeer(t, dir, "starttls", "valid")
			conn, err := net.DialTimeout("tcp", address, time.Second)
			if err != nil {
				t.Fatal(err)
			}
			conn.Write(tc.data)
			conn.Close()
			got := result().Connections[0]
			if got.ErrorCategory != tc.category || got.SelectedCertificate != nil || got.HandshakeComplete ||
				got.BindRequests != tc.binds || got.PlaintextBinds != tc.binds ||
				got.LDAPBytesForwarded != 0 {
				t.Fatalf("framing result: %+v", got)
			}
		})
	}
}

func TestPeerBoundsSilentClientsAndConnectionCount(t *testing.T) {
	dir, _ := testCertificates(t)
	t.Run("no-client", func(t *testing.T) {
		_, result := startPeer(t, dir, "ldaps", "valid", "-timeout", "1s")
		got := result()
		if got.Outcome != "timeout" || len(got.Connections) != 0 {
			t.Fatalf("listener budget: %+v", got)
		}
	})
	t.Run("silent-client", func(t *testing.T) {
		address, result := startPeer(t, dir, "ldaps", "valid", "-connection-timeout", "1s")
		conn, err := net.DialTimeout("tcp", address, time.Second)
		if err != nil {
			t.Fatal(err)
		}
		defer conn.Close()
		got := result().Connections[0]
		if got.ErrorCategory != "timeout" || got.SelectedCertificate != nil ||
			got.BindRequests != 0 {
			t.Fatalf("connection budget: %+v", got)
		}
	})
	t.Run("two-connections", func(t *testing.T) {
		address, result := startPeer(t, dir, "ldaps", "valid", "-connections", "2")
		for range 2 {
			conn, err := net.DialTimeout("tcp", address, time.Second)
			if err != nil {
				t.Fatal(err)
			}
			conn.Close()
		}
		got := result()
		if got.ConnectionLimit != 2 || len(got.Connections) != 2 ||
			got.Outcome != "connection_limit" {
			t.Fatalf("connection count: %+v", got)
		}
	})
}

func TestPeerCountsBindWithoutDisclosingPayload(t *testing.T) {
	dir, roots := testCertificates(t)
	address, result := startPeer(t, dir, "ldaps", "valid")
	conn := tls.Client(
		connectPeer(t, address, "ldaps"),
		&tls.Config{RootCAs: roots, ServerName: "dc2.ad.sdk.test", MinVersion: tls.VersionTLS12},
	)
	marker := []byte("fixture-only-secret-sentinel")
	request := []byte{
		0x30,
		byte(12 + len(marker)),
		2,
		1,
		1,
		0x60,
		byte(7 + len(marker)),
		2,
		1,
		3,
		4,
		0,
		0x80,
		byte(len(marker)),
	}
	request = append(request, marker...)
	if _, err := conn.Write(request); err != nil {
		t.Fatal(err)
	}
	// The standalone observer never manufactures successful bind responses.
	conn.Close()
	got := result()
	data, err := json.Marshal(got)
	if err != nil {
		t.Fatal(err)
	}
	if bytes.Contains(data, marker) || got.Connections[0].BindRequests != 1 ||
		got.Connections[0].LDAPBytesForwarded != 0 {
		t.Fatal("incorrect bind evidence or payload disclosure")
	}
}

func TestServeRejectsUnboundedOrPublicConfiguration(t *testing.T) {
	for _, extra := range [][]string{
		{"-listen", "0.0.0.0:0"},
		{"-listen", "8.8.8.8:389"},
		{"-connections", "0"},
		{"-connections", "17"},
		{"-timeout", "11m"},
		{"-connection-timeout", "2m"},
		{"-upstream", "8.8.8.8:636", "-upstream-ca", "public.pem", "-upstream-name", "dc2.ad.sdk.test"},
		{"-upstream", "127.0.0.1:636"},
	} {
		dir := t.TempDir()
		args := []string{
			"serve",
			"-mode",
			"ldaps",
			"-listen",
			"127.0.0.1:0",
			"-cert",
			"missing.pem",
			"-key",
			"missing-key.pem",
			"-ready",
			filepath.Join(dir, "ready.json"),
			"-result",
			filepath.Join(dir, "result.json"),
		}
		if err := run(context.Background(), append(args, extra...)); err != errArguments {
			t.Fatalf("configuration %v: %v", extra, err)
		}
	}
}

func TestPeerRefusesExistingEvidencePath(t *testing.T) {
	dir, _ := testCertificates(t)
	path := filepath.Join(t.TempDir(), "evidence.json")
	original := []byte("existing evidence")
	if err := os.WriteFile(path, original, 0o600); err != nil {
		t.Fatal(err)
	}
	err := run(context.Background(), []string{
		"serve",
		"-mode",
		"ldaps",
		"-listen",
		"127.0.0.1:0",
		"-cert",
		filepath.Join(dir, "valid.pem"),
		"-key",
		filepath.Join(dir, "valid-key.pem"),
		"-ready",
		path,
		"-result",
		path + ".result",
	})
	if err == nil {
		t.Fatal("existing evidence was accepted")
	}
	file, err := os.Open(path)
	if err != nil {
		t.Fatal(err)
	}
	defer file.Close()
	got, err := io.ReadAll(file)
	if err != nil || !bytes.Equal(got, original) {
		t.Fatal("existing evidence changed")
	}
}

// shiftingContext reports no error on its first Err call and a deadline on
// every later one. That is what a real context does when its deadline fires
// while a category is being decided, and it is the ordering CI observed.
type shiftingContext struct {
	context.Context
	reads int
}

func (c *shiftingContext) Err() error {
	c.reads++
	if c.reads == 1 {
		return nil
	}
	return context.DeadlineExceeded
}

// fixtureTimeout is a net.Error that timed out, as the socket deadline
// produces when it beats the context timer.
type fixtureTimeout struct{}

func (fixtureTimeout) Error() string   { return "fixture deadline" }
func (fixtureTimeout) Timeout() bool   { return true }
func (fixtureTimeout) Temporary() bool { return true }

func TestErrorCategoryReadsContextErrorOnce(t *testing.T) {
	ctx := &shiftingContext{Context: context.Background()}
	var err net.Error = fixtureTimeout{}
	if got := errorCategory(err, ctx); got != "timeout" {
		t.Fatalf("category = %q, want timeout: a deadline was reported as a cancellation", got)
	}
	if ctx.reads != 1 {
		t.Fatalf("context error read %d times, want 1", ctx.reads)
	}
}
