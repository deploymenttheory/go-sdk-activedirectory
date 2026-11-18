// Command portable-tls-client qualifies the public portable TLS client in an
// isolated lab. Secrets enter only through bounded stdin and are never reported.
package main

import (
	"bytes"
	"context"
	"crypto/sha256"
	"crypto/tls"
	"crypto/x509"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"regexp"
	"runtime"
	"time"

	ad "github.com/deploymenttheory/go-sdk-activedirectory/activedirectory"
)

type request struct {
	ExpectedLDAPStatus uint32 `json:"expected_ldap_status,omitempty"`
	RunID              string `json:"run_id"`
	SourceRevision     string `json:"source_revision"`
	Endpoint           string `json:"endpoint"`
	Port               uint16 `json:"port"`
	Transport          string `json:"transport"`
	CAFile             string `json:"ca_file"`
	Username           string `json:"username"`
	Password           []byte `json:"password_base64"`
	Expect             string `json:"expect"`
}

type observation struct {
	LDAPStatus         uint32 `json:"ldap_status,omitempty"`
	RunID              string `json:"run_id"`
	SourceRevision     string `json:"source_revision"`
	Platform           string `json:"platform"`
	GoVersion          string `json:"go_version"`
	Endpoint           string `json:"endpoint"`
	Port               uint16 `json:"port"`
	Transport          string `json:"transport"`
	Expect             string `json:"expect"`
	PublicRootsSHA256  string `json:"public_roots_sha256"`
	TLSVerified        bool   `json:"tls_verified"`
	ProtectionComplete bool   `json:"protection_complete"`
	TLSVersion         string `json:"tls_version,omitempty"`
	TLSCipherSuite     string `json:"tls_cipher_suite,omitempty"`
	CipherBits         uint32 `json:"cipher_bits"`
	Server             string `json:"server,omitempty"`
	ErrorClass         string `json:"error_class,omitempty"`
	TLSFailure         bool   `json:"tls_failure"`
	Passed             bool   `json:"passed"`
}

func decode(input io.Reader) (request, error) {
	var r request
	raw, err := io.ReadAll(io.LimitReader(input, 65537))
	defer clear(raw)
	if err != nil || len(raw) > 65536 {
		return r, errors.New("invalid qualification input")
	}
	decoder := json.NewDecoder(bytes.NewReader(raw))
	decoder.DisallowUnknownFields()
	if err := decoder.Decode(&r); err != nil {
		clear(r.Password)
		return request{}, errors.New("invalid qualification input")
	}
	var trailing any
	if err := decoder.Decode(&trailing); err != io.EOF {
		clear(r.Password)
		return request{}, errors.New("invalid qualification input")
	}
	if !regexp.MustCompile(`^[a-z0-9][a-z0-9-]{5,47}$`).MatchString(r.RunID) ||
		!regexp.MustCompile(`^[0-9a-f]{40}$`).MatchString(r.SourceRevision) || len(r.Password) == 0 ||
		len(r.Password) > 4096 || r.Username == "" || r.CAFile == "" || r.Endpoint == "" || r.Port == 0 ||
		(r.Transport != "ldaps" && r.Transport != "starttls") || (r.Expect != "valid" && r.Expect != "reject") ||
		(r.ExpectedLDAPStatus != 0 && (r.ExpectedLDAPStatus != 53 || r.Transport != "starttls" || r.Expect != "reject")) {
		clear(r.Password)
		return request{}, errors.New("invalid qualification input")
	}
	return r, nil
}

func execute(r request) (out observation) {
	defer clear(r.Password)
	out = observation{
		RunID: r.RunID, SourceRevision: r.SourceRevision, Platform: runtime.GOOS + "/" + runtime.GOARCH,
		GoVersion: runtime.Version(), Endpoint: r.Endpoint, Port: r.Port, Transport: r.Transport, Expect: r.Expect,
	}
	pem, err := os.ReadFile(r.CAFile)
	if err != nil {
		out.ErrorClass = "fixture-input"
		return out
	}
	digest := sha256.Sum256(pem)
	out.PublicRootsSHA256 = hex.EncodeToString(digest[:])
	roots := x509.NewCertPool()
	if !roots.AppendCertsFromPEM(pem) {
		out.ErrorClass = "fixture-input"
		return out
	}
	transport := ad.TransportLDAPS
	if r.Transport == "starttls" {
		transport = ad.TransportStartTLS
	}
	config := ad.Config{
		Backend: ad.BackendPortable, Endpoint: ad.Endpoint{Host: r.Endpoint, Port: r.Port}, Transport: transport,
		Authentication: ad.AuthenticationSimple, Credentials: &ad.Credentials{Username: r.Username, Password: r.Password},
		TLS: &ad.TLSOptions{RootCAs: roots}, Timeout: 15 * time.Second,
	}
	ctx, cancel := context.WithTimeout(context.Background(), 20*time.Second)
	defer cancel()
	client, err := ad.Dial(ctx, config)
	clear(r.Password)
	config.Credentials = nil
	if err != nil {
		out.ErrorClass = ad.Classify(err).String()
		out.TLSFailure = errors.Is(err, ad.ErrTLSNegotiation)
		var ldapError *ad.LDAPError
		if errors.As(err, &ldapError) {
			out.LDAPStatus = ldapError.Code
		}
		expectedClass := ad.Classify(err) == ad.ClassTransport
		if r.ExpectedLDAPStatus != 0 {
			expectedClass = out.LDAPStatus == r.ExpectedLDAPStatus && ad.Classify(err) == ad.ClassUnsupported
		}
		out.Passed = r.Expect == "reject" && out.TLSFailure && expectedClass
		return out
	}
	defer func() {
		if err := client.Close(); err != nil {
			out.Passed = false
			out.ErrorClass = "close-failure"
		}
	}()
	if r.Expect != "valid" {
		out.ErrorClass = "unexpected-session"
		return out
	}
	protection, err := client.Protection(ctx)
	if err != nil {
		out.ErrorClass = ad.Classify(err).String()
		return out
	}
	out.TLSVerified = protection.TLSVerified
	out.ProtectionComplete = protection.Complete
	out.TLSVersion = tls.VersionName(protection.TLSVersion)
	out.TLSCipherSuite = tls.CipherSuiteName(protection.TLSCipherSuite)
	out.CipherBits = protection.CipherBits
	if !protection.Complete || !protection.TLSVerified || protection.Backend != ad.BackendPortable ||
		protection.Authentication != ad.AuthenticationSimple || protection.TLSVersion < tls.VersionTLS12 || protection.CipherBits < 128 ||
		protection.MutualAuthentication || protection.ChannelBound || protection.Delegated {
		out.ErrorClass = "inaccurate-protection"
		return out
	}
	root, err := client.Directory.RootDSE(ctx, ad.RootDSEOptions{})
	if err != nil {
		out.ErrorClass = ad.Classify(err).String()
		return out
	}
	if root.DNSHostName == nil || root.DefaultNamingContext == nil || *root.DefaultNamingContext != "DC=ad,DC=sdk,DC=test" ||
		root.Capabilities().RequireADDS("portable TLS qualification") != nil {
		out.ErrorClass = "unexpected-directory"
		return out
	}
	out.Server = *root.DNSHostName
	out.Passed = true
	return out
}

func main() {
	r, err := decode(os.Stdin)
	if err != nil {
		fmt.Fprintln(os.Stderr, "invalid qualification input")
		os.Exit(2)
	}
	out := execute(r)
	if err := json.NewEncoder(os.Stdout).Encode(out); err != nil {
		os.Exit(2)
	}
	if !out.Passed {
		os.Exit(1)
	}
}
