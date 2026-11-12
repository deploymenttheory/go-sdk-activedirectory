package main

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/sha256"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/hex"
	"encoding/pem"
	"fmt"
	"math/big"
	"os"
	"path/filepath"
	"regexp"
	"strings"
	"time"
)

type certificateInfo struct {
	SHA256    string    `json:"sha256"`
	NotBefore time.Time `json:"not_before"`
	NotAfter  time.Time `json:"not_after"`
	DNSNames  []string  `json:"dns_names"`
}

func describeCertificate(cert *x509.Certificate) certificateInfo {
	hash := sha256.Sum256(cert.Raw)
	return certificateInfo{
		hex.EncodeToString(hash[:]),
		cert.NotBefore,
		cert.NotAfter,
		cert.DNSNames,
	}
}

var labName = regexp.MustCompile(
	`^[a-zA-Z0-9](?:[a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?(?:\.[a-zA-Z0-9](?:[a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?)+$`,
)

func generateCertificates(dir, server string) error {
	if dir == "" || len(server) > 253 || !labName.MatchString(server) ||
		!strings.HasSuffix(server, ".ad.sdk.test") {
		return errArguments
	}
	if err := os.Mkdir(dir, 0o700); err != nil {
		return fmt.Errorf("create owned certificate directory: %w", err)
	}
	now := time.Now().UTC().Truncate(time.Second)
	manifest := struct {
		Server       string                     `json:"server"`
		Certificates map[string]certificateInfo `json:"certificates"`
	}{server, make(map[string]certificateInfo)}
	trusted, trustedKey, err := makeCertificate(
		"trusted-root",
		nil,
		nil,
		nil,
		now.Add(-time.Hour),
		now.Add(7*24*time.Hour),
	)
	if err != nil {
		return err
	}
	untrusted, untrustedKey, err := makeCertificate(
		"untrusted-root",
		nil,
		nil,
		nil,
		now.Add(-time.Hour),
		now.Add(7*24*time.Hour),
	)
	if err != nil {
		return err
	}
	// Root keys never leave memory. Only public roots are persisted/imported.
	for name, cert := range map[string]*x509.Certificate{"trusted-root": trusted, "untrusted-root": untrusted} {
		if err := writePEM(dir, name+".pem", "CERTIFICATE", cert.Raw); err != nil {
			return err
		}
		manifest.Certificates[name] = describeCertificate(cert)
	}
	wrongName := "wrong-host.ad.sdk.test"
	if strings.EqualFold(server, wrongName) {
		wrongName = "other-host.ad.sdk.test"
	}
	for _, name := range []string{"valid", "expired", "wrong-host", "untrusted"} {
		issuer, issuerKey := trusted, trustedKey
		names, before, after := []string{server}, now.Add(-time.Hour), now.Add(48*time.Hour)
		if name == "expired" {
			before, after = now.Add(-72*time.Hour), now.Add(-24*time.Hour)
		}
		if name == "wrong-host" {
			names = []string{wrongName}
		}
		if name == "untrusted" {
			issuer, issuerKey = untrusted, untrustedKey
		}
		cert, key, err := makeCertificate(name, names, issuer, issuerKey, before, after)
		if err != nil {
			return err
		}
		if err := writePEM(dir, name+".pem", "CERTIFICATE", cert.Raw); err != nil {
			return err
		}
		keyDER, err := x509.MarshalPKCS8PrivateKey(key)
		if err != nil {
			return fmt.Errorf("encode private key: %w", err)
		}
		err = writePEM(dir, name+"-key.pem", "PRIVATE KEY", keyDER)
		clear(keyDER)
		if err != nil {
			return err
		}
		manifest.Certificates[name] = describeCertificate(cert)
	}
	return publishJSON(filepath.Join(dir, "manifest.json"), manifest)
}

func makeCertificate(
	name string,
	names []string,
	issuer *x509.Certificate,
	issuerKey *ecdsa.PrivateKey,
	before, after time.Time,
) (*x509.Certificate, *ecdsa.PrivateKey, error) {
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		return nil, nil, fmt.Errorf("generate fixture key: %w", err)
	}
	serial, err := rand.Int(rand.Reader, new(big.Int).Lsh(big.NewInt(1), 128))
	if err != nil {
		return nil, nil, fmt.Errorf("generate serial: %w", err)
	}
	template := &x509.Certificate{
		SerialNumber:          serial,
		Subject:               pkix.Name{CommonName: "AD SDK TLS fixture " + name},
		NotBefore:             before,
		NotAfter:              after,
		DNSNames:              names,
		BasicConstraintsValid: true,
		KeyUsage:              x509.KeyUsageDigitalSignature,
		ExtKeyUsage:           []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
	}
	if issuer == nil {
		template.IsCA = true
		template.KeyUsage |= x509.KeyUsageCertSign
		template.ExtKeyUsage = nil
		issuer, issuerKey = template, key
	}
	der, err := x509.CreateCertificate(rand.Reader, template, issuer, key.Public(), issuerKey)
	if err != nil {
		return nil, nil, fmt.Errorf("sign fixture certificate: %w", err)
	}
	cert, err := x509.ParseCertificate(der)
	if err != nil {
		return nil, nil, fmt.Errorf("parse fixture certificate: %w", err)
	}
	return cert, key, nil
}

func writePEM(dir, name, kind string, der []byte) error {
	file, err := os.OpenFile(filepath.Join(dir, name), os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0o600)
	if err != nil {
		return fmt.Errorf("create PEM: %w", err)
	}
	data := pem.EncodeToMemory(&pem.Block{Type: kind, Bytes: der})
	_, writeErr := file.Write(data)
	clear(data)
	closeErr := file.Close()
	if writeErr != nil {
		return fmt.Errorf("write PEM: %w", writeErr)
	}
	if closeErr != nil {
		return fmt.Errorf("close PEM: %w", closeErr)
	}
	return nil
}
