package main

import (
	"context"
	"crypto/x509"
	"encoding/json"
	"encoding/pem"
	"os"
	"path/filepath"
	"testing"
	"time"
)

func TestGenerateCertificateCasesAndRefuseOverwrite(t *testing.T) {
	dir := filepath.Join(t.TempDir(), "fixture")
	args := []string{"generate", "-dir", dir, "-server", "dc2.ad.sdk.test"}
	if err := run(context.Background(), args); err != nil {
		t.Fatal(err)
	}
	rootPEM, err := os.ReadFile(filepath.Join(dir, "trusted-root.pem"))
	if err != nil {
		t.Fatal(err)
	}
	roots := x509.NewCertPool()
	if !roots.AppendCertsFromPEM(rootPEM) {
		t.Fatal("missing public root")
	}
	for _, name := range []string{"valid", "expired", "wrong-host", "untrusted"} {
		data, readErr := os.ReadFile(filepath.Join(dir, name+".pem"))
		if readErr != nil {
			t.Fatal(readErr)
		}
		block, _ := pem.Decode(data)
		cert, parseErr := x509.ParseCertificate(block.Bytes)
		if parseErr != nil {
			t.Fatal(parseErr)
		}
		_, verifyErr := cert.Verify(
			x509.VerifyOptions{Roots: roots, DNSName: "dc2.ad.sdk.test", CurrentTime: time.Now()},
		)
		if (verifyErr == nil) != (name == "valid") {
			t.Fatalf("%s verification: %v", name, verifyErr)
		}
	}
	data, err := os.ReadFile(filepath.Join(dir, "manifest.json"))
	if err != nil {
		t.Fatal(err)
	}
	var manifest struct {
		Certificates map[string]json.RawMessage `json:"certificates"`
	}
	if err := json.Unmarshal(data, &manifest); err != nil || len(manifest.Certificates) != 6 {
		t.Fatalf("manifest certificates: %d, %v", len(manifest.Certificates), err)
	}
	if err := run(context.Background(), args); err == nil {
		t.Fatal("generation overwrote existing owned directory")
	}
}
