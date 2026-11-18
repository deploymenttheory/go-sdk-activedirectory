package engine

import (
	"bytes"
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
	"testing"
	"time"

	krbclient "github.com/deploymenttheory/go-sdk-activedirectory/3rd_party/gokrb5/v8/client"
	ldap "github.com/deploymenttheory/go-sdk-activedirectory/3rd_party/ldap/v3"
	"github.com/deploymenttheory/go-sdk-activedirectory/3rd_party/ldap/v3/gssapi"
	admodel "github.com/deploymenttheory/go-sdk-activedirectory/activedirectory/internal/model"
)

// An independent build manifest proves source bytes. This linker label only
// prevents an operator from attributing a result to a differently labelled binary.
var internalKerberosLabBuildRevision string

type internalKerberosLabInput struct {
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
	RunID          string `json:"run_id"`
	SourceRevision string `json:"source_revision"`
	Result         string `json:"result"`
	CBTFault       string `json:"cbt_fault,omitempty"`
	SASLFault      string `json:"sasl_fault,omitempty"`
	FixtureDN      string `json:"fixture_dn,omitempty"`
	FixtureGUID    string `json:"fixture_guid,omitempty"`
}

func (internalKerberosLabInput) String() string   { return "KerberosLabInput{redacted}" }
func (internalKerberosLabInput) GoString() string { return "KerberosLabInput{redacted}" }

func internalReadKerberosLabInput(reader io.Reader) (internalKerberosLabInput, error) {
	data, err := io.ReadAll(io.LimitReader(reader, 128*1024+1))
	defer clear(data)
	if err != nil || len(data) > 128*1024 {
		return internalKerberosLabInput{}, errors.New("invalid bounded lab input")
	}
	if trimmed := bytes.TrimSpace(data); len(trimmed) == 0 || trimmed[0] != '{' {
		return internalKerberosLabInput{}, errors.New("a lab input object is required")
	}
	decoder := json.NewDecoder(bytes.NewReader(data))
	decoder.DisallowUnknownFields()
	var input internalKerberosLabInput
	if err := decoder.Decode(&input); err != nil {
		clear(input.Password)
		return internalKerberosLabInput{}, errors.New("invalid lab input object")
	}
	if err := decoder.Decode(new(any)); !errors.Is(err, io.EOF) {
		clear(input.Password)
		return internalKerberosLabInput{}, errors.New("lab input must contain exactly one object")
	}
	return input, nil
}

func internalKerberosLabConfig(input internalKerberosLabInput) (admodel.Config, error) {
	host, port := input.Endpoint, uint16(0)
	if strings.Contains(host, ":") {
		name, service, err := net.SplitHostPort(host)
		if err != nil {
			return admodel.Config{}, admodel.ErrInvalidConfig
		}
		number, err := strconv.ParseUint(service, 10, 16)
		if err != nil || number == 0 {
			return admodel.Config{}, admodel.ErrInvalidConfig
		}
		host, port = name, uint16(number)
	}
	c := admodel.Config{
		Backend:        admodel.BackendPortable,
		Endpoint:       admodel.Endpoint{Host: host, Port: port},
		Authentication: admodel.AuthenticationKerberos,
		Timeout:        20 * time.Second,
	}
	switch input.Transport {
	case "ldaps":
		c.Transport = admodel.TransportLDAPS
	case "starttls":
		c.Transport = admodel.TransportStartTLS
	case "ldap":
		c.Transport = admodel.TransportLDAP
	default:
		return c, admodel.ErrInvalidConfig
	}
	switch input.Protection {
	case "", "default":
		c.SASLProtection = admodel.SASLProtectionDefault
	case "none":
		c.SASLProtection = admodel.SASLProtectionNone
	case "sign":
		c.SASLProtection = admodel.SASLProtectionSign
	case "seal":
		c.SASLProtection = admodel.SASLProtectionSeal
	default:
		return c, admodel.ErrInvalidConfig
	}
	k := &admodel.KerberosCredentials{
		Username:   input.Username,
		Realm:      input.Realm,
		SPN:        input.SPN,
		Password:   input.Password,
		KeytabPath: input.KeytabPath,
		CachePath:  input.CachePath,
	}
	switch input.Source {
	case "password":
		k.Source = admodel.KerberosPassword
	case "keytab":
		k.Source = admodel.KerberosKeytabFile
	case "cache":
		k.Source = admodel.KerberosCredentialCacheFile
	default:
		return c, admodel.ErrInvalidConfig
	}
	c.Kerberos = k
	if input.CAFile != "" {
		pem, err := os.ReadFile(input.CAFile)
		if err != nil {
			return c, fmt.Errorf("read explicit lab CA: %w", err)
		}
		roots := x509.NewCertPool()
		if !roots.AppendCertsFromPEM(pem) {
			return c, admodel.ErrInvalidConfig
		}
		c.TLS = &admodel.TLSOptions{RootCAs: roots}
	}
	return admodel.InternalConfigNormalized(c)
}

type internalKerberosLabBinding struct {
	*gssapi.Client
	fault                   string
	applied                 bool
	finalAcceptanceObserved bool
}

func (m *internalKerberosLabBinding) SetChannelBinding(cert *x509.Certificate) error {
	m.applied = true
	if m.fault == "missing" {
		return nil
	}
	if m.fault != "tampered" || cert == nil || len(cert.Raw) == 0 {
		return admodel.ErrInvalidConfig
	}
	copy := *cert
	copy.Raw = bytes.Clone(cert.Raw)
	copy.Raw[len(copy.Raw)-1] ^= 1
	return m.Client.SetChannelBinding(&copy)
}

func (m *internalKerberosLabBinding) AuthenticationContext() (gssapi.AuthenticationContext, error) {
	// The bind-result contract invokes this observer only AFTER a complete,
	// successful final LDAP acknowledgement. No application operation follows.
	m.finalAcceptanceObserved = true
	return m.Client.AuthenticationContext()
}

func TestPortableKerberosLab(t *testing.T) {
	if os.Getenv("ADSDK_KERBEROS_LAB_INPUT") != "stdin" {
		t.Skip("set ADSDK_KERBEROS_LAB_INPUT=stdin for the owned lab fixture")
	}
	input, err := internalReadKerberosLabInput(os.Stdin)
	if err != nil {
		t.Fatal(err)
	}
	defer clear(input.Password)
	if input.SourceRevision == "" || input.SourceRevision != internalKerberosLabBuildRevision || input.Result == "" || input.RunID == "" ||
		(input.CBTFault != "missing" && input.CBTFault != "tampered") || input.SASLFault != "" || input.Transport == "ldap" {
		t.Fatal("invalid owned CBT lab selection or binary label")
	}
	c, err := internalKerberosLabConfig(input)
	if err != nil {
		t.Fatal(err)
	}
	result := struct {
		SchemaVersion           int    `json:"schema_version"`
		RunID                   string `json:"run_id"`
		SourceRevision          string `json:"source_revision"`
		Platform                string `json:"platform"`
		Toolchain               string `json:"toolchain"`
		Source                  string `json:"credential_source"`
		Transport               string `json:"transport"`
		Fault                   string `json:"cbt_fault"`
		FaultApplied            bool   `json:"fault_applied"`
		ServerRefused           bool   `json:"server_refused"`
		LDAPCode                uint32 `json:"ldap_code"`
		CBTStatus               string `json:"cbt_status"`
		FinalAcceptanceObserved bool   `json:"final_acceptance_observed"`
		ApplicationOperations   int    `json:"application_operations"`
		Success                 bool   `json:"success"`
	}{
		SchemaVersion: 1, RunID: input.RunID, SourceRevision: internalKerberosLabBuildRevision, Platform: runtime.GOOS + "/" + runtime.GOARCH, Toolchain: runtime.Version(),
		Source: input.Source, Transport: input.Transport, Fault: input.CBTFault,
	}
	var mechanism *internalKerberosLabBinding
	factory := func(client *krbclient.Client) (ldap.GSSAPIClient, func() error, error) {
		actual, err := gssapi.NewClient(client)
		if err != nil {
			return nil, nil, err
		}
		mechanism = &internalKerberosLabBinding{Client: actual, fault: input.CBTFault}
		return mechanism, actual.Close, nil
	}
	session, bindErr := internalDialPortableKerberosWithFactory(t.Context(), c, &net.Dialer{}, factory)
	clear(input.Password)
	if session != nil {
		_ = session.InternalClose()
	}
	if mechanism != nil {
		result.FaultApplied = mechanism.applied
		result.FinalAcceptanceObserved = mechanism.finalAcceptanceObserved
	}
	var server *admodel.LDAPError
	if errors.As(bindErr, &server) {
		result.LDAPCode = server.Code
		result.ServerRefused = server.Code != 0
		if strings.Contains(strings.ToLower(server.Diagnostic), "80090346") {
			result.CBTStatus = "SEC_E_BAD_BINDINGS(0x80090346)"
		}
	}
	result.Success = session == nil && bindErr != nil && result.FaultApplied && result.ServerRefused && result.LDAPCode == 49 && result.CBTStatus != "" &&
		!result.FinalAcceptanceObserved
	encoded, encodeErr := json.MarshalIndent(result, "", "  ")
	if encodeErr != nil {
		t.Fatal("encode public lab result:", encodeErr)
	}
	if err := os.WriteFile(input.Result, append(encoded, '\n'), 0o600); err != nil {
		t.Fatal("write public lab result:", err)
	}
	if !result.Success {
		t.Fatalf("server did not prove the required CBT refusal: LDAP=%d CBT=%s accepted=%t fault_applied=%t", result.LDAPCode, result.CBTStatus,
			result.FinalAcceptanceObserved, result.FaultApplied)
	}
}
