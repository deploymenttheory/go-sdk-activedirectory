package main

import (
	"bytes"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"encoding/json"
	"encoding/pem"
	"errors"
	"io"
	"math/big"
	"net"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"testing"
	"time"
)

func TestQualificationInputNeverEchoesSecretAndRejectsTrailingOrOversizedData(t *testing.T) {
	r := request{
		RunID:          "sdk03-fixture",
		SourceRevision: strings.Repeat("a", 40),
		Endpoint:       "dc1.ad.sdk.test",
		Port:           636,
		Transport:      "ldaps",
		CAFile:         "root.pem",
		Username:       "fixture",
		Password:       []byte("owned-test-password"),
		Expect:         "valid",
	}
	valid, err := json.Marshal(r)
	if err != nil {
		t.Fatal(err)
	}
	parsed, err := decode(bytes.NewReader(valid))
	if err != nil || !bytes.Equal(parsed.Password, r.Password) {
		t.Fatal("exact password input was not retained")
	}
	clear(parsed.Password)
	for _, bad := range [][]byte{append(append([]byte{}, valid...), []byte(" {}")...), append(append([]byte{}, valid...), bytes.Repeat([]byte{' '}, 65536)...), []byte(`{"unknown":"owned-test-password"}`)} {
		parsed, err := decode(bytes.NewReader(bad))
		if err == nil || len(parsed.Password) != 0 || strings.Contains(err.Error(), "owned-test-password") {
			t.Fatal("malformed input accepted or secret echoed")
		}
	}
}

func TestPublicClientPreservesStartTLSRefusalStatusAndSendsNoFurtherBytes(t *testing.T) {
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	template := &x509.Certificate{
		SerialNumber:          big.NewInt(1),
		NotBefore:             time.Now().Add(-time.Minute),
		NotAfter:              time.Now().Add(time.Minute),
		IsCA:                  true,
		BasicConstraintsValid: true,
		KeyUsage:              x509.KeyUsageCertSign,
	}
	cert, err := x509.CreateCertificate(rand.Reader, template, template, &key.PublicKey, key)
	if err != nil {
		t.Fatal(err)
	}
	roots := filepath.Join(t.TempDir(), "root.pem")
	if err := os.WriteFile(roots, pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: cert}), 0o600); err != nil {
		t.Fatal(err)
	}
	listener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer listener.Close()
	observed := make(chan error, 1)
	go func() {
		conn, err := listener.Accept()
		if err != nil {
			observed <- err
			return
		}
		defer conn.Close()
		_ = conn.SetDeadline(time.Now().Add(3 * time.Second))
		request := make([]byte, 31)
		if _, err := io.ReadFull(conn, request); err != nil {
			observed <- err
			return
		}
		if _, err := conn.Write([]byte{0x30, 0x0c, 2, 1, 1, 0x78, 7, 0x0a, 1, 53, 4, 0, 4, 0}); err != nil {
			observed <- err
			return
		}
		var probe [1]byte
		n, err := conn.Read(probe[:])
		if n != 0 || err != io.EOF {
			observed <- errors.New("client did not close with zero post-refusal bytes")
			return
		}
		observed <- nil
	}()
	_, portText, err := net.SplitHostPort(listener.Addr().String())
	if err != nil {
		t.Fatal(err)
	}
	port, err := strconv.ParseUint(portText, 10, 16)
	if err != nil {
		t.Fatal(err)
	}
	out := execute(
		request{
			RunID:              "sdk03-fixture",
			SourceRevision:     strings.Repeat("a", 40),
			Endpoint:           "127.0.0.1",
			Port:               uint16(port),
			Transport:          "starttls",
			CAFile:             roots,
			Username:           "fixture",
			Password:           []byte("owned-test-password"),
			Expect:             "reject",
			ExpectedLDAPStatus: 53,
		},
	)
	if !out.Passed || !out.TLSFailure || out.LDAPStatus != 53 || out.ErrorClass != "unsupported" {
		t.Fatalf("inaccurate actual refusal classification: %+v", out)
	}
	if err := <-observed; err != nil {
		t.Fatal(err)
	}
}
