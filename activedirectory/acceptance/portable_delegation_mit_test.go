package acceptance

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"slices"
	"strings"
	"testing"
	"time"

	"github.com/jcmturner/gofork/encoding/asn1"

	krbgss "github.com/deploymenttheory/go-sdk-activedirectory/3rd_party/gokrb5/v8/gssapi"
	"github.com/deploymenttheory/go-sdk-activedirectory/3rd_party/gokrb5/v8/messages"
	ldap "github.com/deploymenttheory/go-sdk-activedirectory/3rd_party/ldap/v3"
	adengine "github.com/deploymenttheory/go-sdk-activedirectory/activedirectory/internal/engine"
	admodel "github.com/deploymenttheory/go-sdk-activedirectory/activedirectory/internal/model"
)

// MIT independently accepts the actual emitted AP-REQ and imports its delegated
// credential into a MEMORY cache. The SDK still authenticates the owned LDAP
// acceptor's AP-REP separately; MIT is a test-only peer, never a runtime gateway.
func TestPortableDelegationIndependentMITAcceptor(t *testing.T) {
	if runtime.GOOS != "linux" || os.Getenv("ADSDK_DELEGATION_MIT_INTEROP") != "1" {
		t.Skip("explicit offline Linux MIT GSS interoperability fixture")
	}
	certificate, _ := portableKerberosTLSCertificate(t)
	for _, delegated := range []bool{false, true} {
		t.Run(fmt.Sprint(delegated), func(t *testing.T) {
			private := t.TempDir()
			kdc := newPortableKerberosKDC(t, func(k *portableKerberosKDC) {
				k.delegation = delegated
				k.inspectAP = func(ap *messages.APReq) error {
					return verifyPortableMITForwarding(t.Context(), private, k, ap, delegated)
				}
			})
			wire := newPortableSASLWire(t, admodel.TransportLDAP, certificate, kdc, ldap.SASLSecuritySeal, 7, "", portableSASLReadStep([]byte{0, 255}))
			options := portableTLSConfig(admodel.TransportLDAP, nil)
			options.TLS = nil
			options.Authentication, options.Credentials, options.AllowDelegation = admodel.AuthenticationKerberos, nil, delegated
			options.SASLProtection = admodel.SASLProtectionSeal
			options.Kerberos = portableKerberosSource(t, kdc, admodel.KerberosPassword, false)
			session, err := adengine.InternalDialPortableWithDial(t.Context(), options, wire)
			if err != nil {
				// Capture the owned peer failure too; the production SDK correctly
				// sanitizes library diagnostics and cannot expose ctypes test state.
				wire.wait(t)
				t.Fatal(err)
			}
			t.Cleanup(func() { _ = session.InternalClose() })
			observed, err := session.(admodel.InternalSessionProtectionObserver).InternalSessionProtection(t.Context())
			if err != nil || !observed.Complete || !observed.MutualAuthentication || observed.Delegated != delegated || observed.DelegationSent != delegated {
				t.Fatal("actual forwarding and established local context disagree")
			}
			if _, err := session.InternalBaseObject(t.Context(), "CN=owned,DC=ad,DC=sdk,DC=test", []string{"thumbnailPhoto"}); err != nil {
				t.Fatal(err)
			}
			if err := session.InternalClose(); err != nil {
				t.Fatal(err)
			}
			wire.wait(t)
			if _, err := os.Stat(filepath.Join(private, "owned-service.keytab")); !os.IsNotExist(err) {
				t.Fatal("independent acceptor retained its owned private keytab")
			}
		})
	}
}

func verifyPortableMITForwarding(ctx context.Context, private string, kdc *portableKerberosKDC, ap *messages.APReq, delegated bool) error {
	keytab, err := kdc.keys.Marshal()
	if err != nil {
		return err
	}
	defer clear(keytab)
	path := filepath.Join(private, "owned-service.keytab")
	file, err := os.OpenFile(path, os.O_CREATE|os.O_EXCL|os.O_WRONLY, 0o600)
	if err != nil {
		return err
	}
	_, writeErr := file.Write(keytab)
	closeErr := file.Close()
	defer func() { _ = os.Remove(path) }()
	if writeErr != nil {
		return writeErr
	}
	if closeErr != nil {
		return closeErr
	}
	configuration := filepath.Join(private, "krb5.conf")
	if err := os.WriteFile(
		configuration,
		[]byte("[libdefaults]\n default_realm = AD.SDK.TEST\n dns_lookup_kdc = false\n dns_lookup_realm = false\n rdns = false\n"),
		0o600,
	); err != nil {
		return err
	}
	request, err := portableMITForwardingInput(path, ap, delegated)
	if err != nil {
		return err
	}
	defer clear(request)
	bounded, cancel := context.WithTimeout(ctx, 8*time.Second)
	defer cancel()
	command := exec.CommandContext(bounded, "python3", "testdata/mit_forwarded_credential.py")
	command.Env = []string{"PATH=" + os.Getenv("PATH"), "LANG=C", "KRB5_CONFIG=" + configuration, "KRB5RCACHEDIR=" + private}
	command.Stdin = bytes.NewReader(request)
	output, err := command.Output()
	if err != nil {
		// ExitError.Error includes only the exit status, never private input or
		// a traceback. The Python helper likewise emits only codes/class names.
		var failed *exec.ExitError
		if errors.As(err, &failed) {
			return fmt.Errorf("independent MIT forwarding acceptor failed (%s): %w", portableMITDiagnostic(failed.Stderr), err)
		}
		return fmt.Errorf("independent MIT forwarding acceptor failed: %w", err)
	}
	return validatePortableMITForwarding(output, delegated)
}

func portableMITDiagnostic(raw []byte) string {
	const unavailable = "no allowlisted diagnostic"
	if len(raw) > 4096 {
		return unavailable
	}
	var result struct {
		Operation string `json:"error"`
		Code      int64  `json:"code"`
		Minor     int64  `json:"minor"`
		ClassName string `json:"class_name"`
	}
	decoder := json.NewDecoder(bytes.NewReader(raw))
	decoder.DisallowUnknownFields()
	if err := decoder.Decode(&result); err != nil {
		return unavailable
	}
	var extra any
	if err := decoder.Decode(&extra); err != io.EOF {
		return unavailable
	}
	operations := strings.Fields("input_bound input_schema input_types private_keytab token_bound display_name name_bound principal_name import_name " +
		"acquire_explicit_keytab accept_context mechanism inquire_context authenticated_identity_or_flags actual_delegated_credential init_krb " +
		"new_memory_cache nonmemory_cache parse_actor init_memory_cache copy_delegated_cache start_cache_cursor next_cache_credential " +
		"forwarded_ticket_metadata cache_count_bound credential_cardinality retire_owned_state mit_fixture_boundary")
	classes := []string{
		"",
		"ValueError",
		"KeyError",
		"TypeError",
		"AttributeError",
		"OSError",
		"JSONDecodeError",
		"NameError",
		"OverflowError",
		"UnicodeDecodeError",
		"ArgumentError",
		"IndexError",
	}
	if !slices.Contains(operations, result.Operation) || !slices.Contains(classes, result.ClassName) {
		return unavailable
	}
	return fmt.Sprintf("operation=%s code=%d minor=%d class=%s", result.Operation, result.Code, result.Minor, result.ClassName)
}

func portableMITForwardingInput(path string, ap *messages.APReq, delegated bool) ([]byte, error) {
	encoded, err := ap.Marshal()
	if err != nil {
		return nil, err
	}
	defer clear(encoded)
	oid, err := asn1.Marshal(krbgss.OIDKRB5.OID())
	if err != nil {
		return nil, err
	}
	inner := append(append(oid, 1, 0), encoded...)
	defer clear(inner)
	token, err := asn1.Marshal(asn1.RawValue{Class: asn1.ClassApplication, Tag: 0, IsCompound: true, Bytes: inner})
	if err != nil {
		return nil, err
	}
	defer clear(token)
	return json.Marshal(struct {
		Token   []byte `json:"token"`
		Keytab  string `json:"keytab"`
		Service string `json:"service"`
		Client  string `json:"client"`
		Realm   string `json:"realm"`
		Forward bool   `json:"delegate"`
	}{token, path, "ldap/" + portableTLSHost + "@" + portableKerberosRealm, portableKerberosUser + "@" + portableKerberosRealm, portableKerberosRealm, delegated})
}

func validatePortableMITForwarding(output []byte, delegated bool) error {
	if len(output) > 16384 {
		return fmt.Errorf("independent MIT report exceeds its output bound")
	}
	var result struct {
		SchemaVersion   int    `json:"schema_version"`
		Complete        bool   `json:"complete"`
		Mechanism       string `json:"mechanism"`
		Client          string `json:"client"`
		Service         string `json:"service"`
		Flags           uint32 `json:"flags"`
		LifetimeSeconds uint32 `json:"lifetime_seconds"`
		Delegated       bool   `json:"delegated_credential"`
		CacheType       string `json:"cache_type"`
		Tickets         []struct {
			Client  string `json:"client"`
			Service string `json:"service"`
			Etype   int32  `json:"enctype"`
			Flags   uint32 `json:"flags"`
			End     int64  `json:"end_unix"`
		} `json:"tickets"`
	}
	decoder := json.NewDecoder(io.LimitReader(bytes.NewReader(output), 16384))
	decoder.DisallowUnknownFields()
	if err := decoder.Decode(&result); err != nil {
		return err
	}
	var extra any
	if err := decoder.Decode(&extra); err != io.EOF {
		return fmt.Errorf("independent MIT report contains trailing data")
	}
	if result.SchemaVersion != 1 || !result.Complete || result.Mechanism != "Kerberos" || result.Flags&0x3e != 0x3e || result.Delegated != delegated ||
		result.Client != portableKerberosUser+"@"+portableKerberosRealm || result.Service != "ldap/"+portableTLSHost+"@"+portableKerberosRealm || result.LifetimeSeconds == 0 {
		return fmt.Errorf("independent MIT actual context facts do not match the explicit session")
	}
	if delegated {
		if result.CacheType != "MEMORY" || len(result.Tickets) != 1 || result.Tickets[0].Client != result.Client ||
			result.Tickets[0].Service != "krbtgt/"+portableKerberosRealm+"@"+portableKerberosRealm || result.Tickets[0].Etype != 18 ||
			result.Tickets[0].Flags&0x60000000 != 0x60000000 || result.Tickets[0].End <= time.Now().Unix() || result.Flags&1 != 1 {
			return fmt.Errorf("independent MIT did not import the actual fresh forwarded TGT")
		}
	} else if result.CacheType != "none" || len(result.Tickets) != 0 || result.Flags&1 != 0 {
		return fmt.Errorf("default authentication forwarded an unsolicited credential")
	}
	return nil
}

func TestIndependentMITReportRequiresActualIdentityFlagsAndForwardedCredential(t *testing.T) {
	for _, fault := range []string{"", "incomplete", "wrong-client", "no-mutual", "no-delegation", "persistent-cache", "no-TGT", "wrong-service", "expired", "unknown-field", "trailing"} {
		t.Run(fault, func(t *testing.T) {
			ticket := map[string]any{
				"client":  portableKerberosUser + "@" + portableKerberosRealm,
				"service": "krbtgt/" + portableKerberosRealm + "@" + portableKerberosRealm,
				"enctype": 18, "flags": 0x60000000, "end_unix": time.Now().Add(time.Hour).Unix(),
			}
			report := map[string]any{
				"schema_version": 1, "complete": true, "mechanism": "Kerberos", "client": ticket["client"],
				"service": "ldap/" + portableTLSHost + "@" + portableKerberosRealm, "flags": 0x3f,
				"lifetime_seconds": 3600, "delegated_credential": true, "cache_type": "MEMORY", "tickets": []any{ticket},
			}
			switch fault {
			case "incomplete":
				report["complete"] = false
			case "wrong-client":
				report["client"] = "other@OTHER.TEST"
			case "no-mutual":
				report["flags"] = 0x3d
			case "no-delegation":
				report["delegated_credential"] = false
			case "persistent-cache":
				report["cache_type"] = "FILE"
			case "no-TGT":
				report["tickets"] = []any{}
			case "wrong-service":
				ticket["service"] = "krbtgt/OTHER.TEST@OTHER.TEST"
			case "expired":
				ticket["end_unix"] = time.Now().Add(-time.Minute).Unix()
			case "unknown-field":
				report["ignored_claim"] = true
			}
			encoded, err := json.Marshal(report)
			if err != nil {
				t.Fatal(err)
			}
			if fault == "trailing" {
				encoded = append(encoded, []byte(` {"complete":true}`)...)
			}
			if err := validatePortableMITForwarding(encoded, true); (err != nil) != (fault != "") {
				t.Fatalf("independent report accepted missing evidence or rejected valid facts: %v", err)
			}
		})
	}
}

func TestIndependentMITDiagnosticsNeverEchoPrivatePayloads(t *testing.T) {
	const secret = "private-ticket-and-key-material"
	for _, raw := range [][]byte{
		[]byte(secret), []byte(`{"error":"` + secret + `","code":1}`),
		[]byte(`{"error":"accept_context","code":1,"token":"` + secret + `"}`),
		[]byte(`{"error":"mit_fixture_boundary","class_name":"` + secret + `"}`),
		[]byte(`{"error":"accept_context","code":1} {"token":"` + secret + `"}`), bytes.Repeat([]byte(secret), 4096),
	} {
		if result := portableMITDiagnostic(raw); strings.Contains(result, secret) || result != "no allowlisted diagnostic" {
			t.Fatal("independent peer diagnostics echoed untrusted private data")
		}
	}
	if result := portableMITDiagnostic([]byte(`{"error":"accept_context","code":851968,"minor":13}`)); result != "operation=accept_context code=851968 minor=13 class=" {
		t.Fatal("independent peer diagnostic lost its precise safe status")
	}
}
