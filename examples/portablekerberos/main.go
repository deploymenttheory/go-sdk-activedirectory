// Command portablekerberos authenticates one explicit Kerberos source and reads
// RootDSE. Supply one JSON object through redirected stdin; no password argument,
// ambient cache, credential generation or directory write is supported.
package main

import (
	"bytes"
	"context"
	"crypto/x509"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net"
	"os"
	"runtime"
	"strconv"
	"strings"
	"time"

	ad "github.com/deploymenttheory/go-sdk-activedirectory/activedirectory"
)

// Lab builds set this to the exact source commit with -ldflags -X.
var buildRevision string

type request struct {
	Endpoint       string `json:"endpoint"`
	Transport      string `json:"transport"`
	Protection     string `json:"protection,omitempty"`
	Source         string `json:"source"`
	Username       string `json:"username"`
	Realm          string `json:"realm"`
	SPN            string `json:"spn"`
	Password       []byte `json:"password_base64,omitempty"`
	KeytabPath     string `json:"keytab_path,omitempty"`
	CachePath      string `json:"cache_path,omitempty"`
	CAFile         string `json:"ca_file"`
	RunID          string `json:"run_id,omitempty"`
	SourceRevision string `json:"source_revision,omitempty"`
	Result         string `json:"result,omitempty"`
}

type report struct {
	SchemaVersion           int    `json:"schema_version"`
	Success                 bool   `json:"success"`
	RunID                   string `json:"run_id"`
	SourceRevision          string `json:"source_revision"`
	SourceVerified          bool   `json:"source_label_matches"`
	Toolchain               string `json:"toolchain"`
	Platform                string `json:"platform"`
	Source                  string `json:"credential_source"`
	Transport               string `json:"transport"`
	TLSVerified             bool   `json:"tls_verified"`
	TLSVersion              uint16 `json:"tls_version"`
	TLSCipherSuite          uint16 `json:"tls_cipher_suite"`
	CipherBits              uint32 `json:"cipher_bits"`
	SASLProtection          string `json:"sasl_protection"`
	SASLCipherBits          uint32 `json:"sasl_cipher_bits"`
	SASLEncryptionType      int32  `json:"sasl_encryption_type"`
	MutualAuthentication    bool   `json:"mutual_authentication"`
	ChannelBindingSent      bool   `json:"channel_binding_sent"`
	ChannelBound            bool   `json:"channel_bound"`
	PeerBindingVerification string `json:"channel_binding_peer_verification"`
	Complete                bool   `json:"complete"`
	DNSHostName             string `json:"dns_host_name,omitempty"`
	DefaultNamingContext    string `json:"default_naming_context,omitempty"`
	LDAPCode                uint32 `json:"ldap_code,omitempty"`
	KerberosCode            int32  `json:"kerberos_code,omitempty"`
	Error                   string `json:"error,omitempty"`
}

func readRequest(reader io.Reader) (request, error) {
	data, err := io.ReadAll(io.LimitReader(reader, 128*1024+1))
	defer clear(data)
	if err != nil {
		return request{}, err
	}
	if len(data) > 128*1024 {
		return request{}, errors.New("input exceeds 128 KiB")
	}
	if trimmed := bytes.TrimSpace(data); len(trimmed) == 0 || trimmed[0] != '{' {
		return request{}, errors.New("a Kerberos input object is required")
	}
	decoder := json.NewDecoder(bytes.NewReader(data))
	decoder.DisallowUnknownFields()
	var input request
	if err := decoder.Decode(&input); err != nil {
		clear(input.Password)
		return request{}, errors.New("invalid Kerberos input object")
	}
	if err := decoder.Decode(new(any)); !errors.Is(err, io.EOF) {
		clear(input.Password)
		return request{}, errors.New("exactly one Kerberos input object is required")
	}
	return input, nil
}

func requestConfig(input request) (ad.Config, error) {
	host, port := input.Endpoint, uint16(0)
	if strings.Contains(host, ":") {
		name, service, err := net.SplitHostPort(host)
		if err != nil {
			return ad.Config{}, errors.New("invalid explicit LDAP endpoint")
		}
		number, err := strconv.ParseUint(service, 10, 16)
		if err != nil || number == 0 {
			return ad.Config{}, errors.New("invalid explicit LDAP port")
		}
		host, port = name, uint16(number)
	}
	c := ad.Config{
		Backend:        ad.BackendPortable,
		Endpoint:       ad.Endpoint{Host: host, Port: port},
		Authentication: ad.AuthenticationKerberos,
		Transport:      ad.TransportLDAPS,
		Timeout:        20 * time.Second,
	}
	switch input.Transport {
	case "ldaps":
	case "starttls":
		c.Transport = ad.TransportStartTLS
	case "ldap":
		c.Transport = ad.TransportLDAP
	default:
		return ad.Config{}, errors.New("transport must be ldap, ldaps or starttls")
	}
	switch input.Protection {
	case "", "default":
		c.SASLProtection = ad.SASLProtectionDefault
	case "none":
		c.SASLProtection = ad.SASLProtectionNone
	case "sign":
		c.SASLProtection = ad.SASLProtectionSign
	case "seal":
		c.SASLProtection = ad.SASLProtectionSeal
	default:
		return ad.Config{}, errors.New("protection must be default, none, sign or seal")
	}
	k := &ad.KerberosCredentials{Username: input.Username, Realm: input.Realm, SPN: input.SPN, Password: input.Password, KeytabPath: input.KeytabPath, CachePath: input.CachePath}
	switch input.Source {
	case "password":
		k.Source = ad.KerberosPassword
	case "keytab":
		k.Source = ad.KerberosKeytabFile
	case "cache":
		k.Source = ad.KerberosCredentialCacheFile
	default:
		return ad.Config{}, errors.New("source must be password, keytab or cache")
	}
	c.Kerberos = k
	if input.CAFile != "" {
		pem, err := os.ReadFile(input.CAFile)
		if err != nil {
			return ad.Config{}, fmt.Errorf("read explicit CA file: %w", err)
		}
		roots := x509.NewCertPool()
		if !roots.AppendCertsFromPEM(pem) {
			return ad.Config{}, errors.New("CA file has no PEM certificate")
		}
		c.TLS = &ad.TLSOptions{RootCAs: roots}
	}
	return c, c.Validate()
}

func probe(ctx context.Context, input request) (result report, err error) {
	result = report{
		SchemaVersion: 1, RunID: input.RunID, SourceRevision: buildRevision, SourceVerified: buildRevision != "" && buildRevision == input.SourceRevision,
		Toolchain: runtime.Version(), Platform: runtime.GOOS + "/" + runtime.GOARCH, Source: input.Source, Transport: input.Transport,
		PeerBindingVerification: "unconfirmed",
	}
	defer func() {
		if err == nil {
			return
		}
		result.Error = err.Error()
		result.Success = false
		var ldapError *ad.LDAPError
		if errors.As(err, &ldapError) {
			result.LDAPCode = ldapError.Code
		}
		var kerberosError *ad.KerberosError
		if errors.As(err, &kerberosError) {
			result.KerberosCode = kerberosError.Code
		}
	}()
	if input.SourceRevision != "" && !result.SourceVerified {
		return result, errors.New("requested source revision does not match this binary")
	}
	c, err := requestConfig(input)
	if err != nil {
		return result, err
	}
	client, err := ad.Dial(ctx, c)
	clear(input.Password)
	c.Kerberos = nil
	if err != nil {
		return result, err
	}
	defer func() { err = errors.Join(err, client.Close()) }()
	observed, err := client.Directory.Protection(ctx)
	if err != nil {
		return result, err
	}
	result.TLSVerified, result.TLSVersion, result.TLSCipherSuite, result.CipherBits = observed.TLSVerified, observed.TLSVersion, observed.TLSCipherSuite, observed.CipherBits
	result.MutualAuthentication, result.ChannelBindingSent, result.ChannelBound, result.Complete = observed.MutualAuthentication, observed.ChannelBindingSent, observed.ChannelBound, observed.Complete
	result.SASLCipherBits, result.SASLEncryptionType = observed.SASLCipherBits, observed.SASLEncryptionType
	switch observed.SASLProtection {
	case ad.SASLProtectionNone:
		result.SASLProtection = "none"
	case ad.SASLProtectionSign:
		result.SASLProtection = "sign"
	case ad.SASLProtectionSeal:
		result.SASLProtection = "seal"
	default:
		return result, errors.New("negotiated SASL observations are unavailable")
	}
	if !observed.Complete || !observed.MutualAuthentication || observed.ChannelBound || observed.ChannelBindingSent != observed.TLSVerified ||
		(!observed.TLSVerified && observed.SASLProtection != ad.SASLProtectionSign && observed.SASLProtection != ad.SASLProtectionSeal) {
		return result, errors.New("required Kerberos/TLS authentication observations are unavailable")
	}
	root, err := client.Directory.RootDSE(ctx, ad.RootDSEOptions{})
	if err != nil {
		return result, err
	}
	if root.DNSHostName != nil {
		result.DNSHostName = *root.DNSHostName
	}
	if root.DefaultNamingContext != nil {
		result.DefaultNamingContext = *root.DefaultNamingContext
	}
	result.Success = true
	return result, nil
}

func run(reader io.Reader, writer io.Writer) error {
	input, err := readRequest(reader)
	if err != nil {
		return err
	}
	defer clear(input.Password)
	ctx, cancel := context.WithTimeout(context.Background(), time.Minute)
	defer cancel()
	result, probeErr := probe(ctx, input)
	encoded, err := json.MarshalIndent(result, "", "  ")
	if err != nil {
		return errors.Join(probeErr, err)
	}
	if input.Result != "" {
		if err := os.WriteFile(input.Result, append(encoded, '\n'), 0o600); err != nil {
			return errors.Join(probeErr, err)
		}
	}
	_, err = writer.Write(append(encoded, '\n'))
	return errors.Join(probeErr, err)
}

func main() {
	if err := run(os.Stdin, os.Stdout); err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(1)
	}
}
