package engine

import (
	"encoding/json"
	"errors"
	"fmt"
	"net"
	"os"
	"strings"
	"testing"

	"github.com/deploymenttheory/go-sdk-activedirectory/3rd_party/gokrb5/v8/krberror"
	admodel "github.com/deploymenttheory/go-sdk-activedirectory/activedirectory/internal/model"
)

// This diagnostic emits only allowlisted error categories, never library error
// text, credential fields, ticket bytes or keys. It makes no application request.
func TestPortableKerberosDiagnosticLab(t *testing.T) {
	if os.Getenv("ADSDK_KERBEROS_DIAGNOSTIC") != "stdin" {
		t.Skip("set ADSDK_KERBEROS_DIAGNOSTIC=stdin for a bounded owned-lab diagnosis")
	}
	input, err := internalReadKerberosLabInput(os.Stdin)
	if err != nil {
		t.Fatal(err)
	}
	defer clear(input.Password)
	if input.SourceRevision == "" || input.SourceRevision != internalKerberosLabBuildRevision || input.Result == "" || input.CBTFault != "" || input.SASLFault != "" {
		t.Fatal("invalid diagnostic source label or fault selection")
	}
	c, err := internalKerberosLabConfig(input)
	if err != nil {
		t.Fatal("invalid diagnostic configuration")
	}
	session, bindErr := internalDialPortableKerberos(t.Context(), c, &net.Dialer{})
	clear(input.Password)
	result := struct {
		SourceRevision     string   `json:"source_revision"`
		SessionEstablished bool     `json:"session_established"`
		ConnectionError    bool     `json:"connection_error"`
		LibraryRootCause   string   `json:"library_root_cause"`
		ClockSkewCheck     bool     `json:"clock_skew_check_failed"`
		NonceCheck         bool     `json:"nonce_check_failed"`
		IdentityCheck      bool     `json:"identity_check_failed"`
		Timeout            bool     `json:"timeout"`
		LDAPCode           uint32   `json:"ldap_code"`
		KerberosCode       int32    `json:"kerberos_code"`
		CauseTypes         []string `json:"cause_types"`
		CauseCategories    []string `json:"cause_categories"`
	}{SourceRevision: internalKerberosLabBuildRevision, SessionEstablished: session != nil, ConnectionError: errors.Is(bindErr, admodel.ErrConnection)}
	if session != nil {
		_ = session.InternalClose()
	}
	var detail krberror.Krberror
	if errors.As(bindErr, &detail) {
		switch detail.RootCause {
		case krberror.NetworkingError, krberror.KRBMsgError, krberror.EncodingError, krberror.DecryptingError, krberror.EncryptingError, krberror.ChksumError, krberror.ConfigError, krberror.KDCError:
			result.LibraryRootCause = detail.RootCause
		default:
			result.LibraryRootCause = "other"
		}
		text := strings.ToLower(strings.Join(detail.EText, " "))
		result.ClockSkewCheck = strings.Contains(text, "clock skew")
		result.NonceCheck = strings.Contains(text, "nonce")
		result.IdentityCheck = strings.Contains(text, "sname") || strings.Contains(text, "crealm") || strings.Contains(text, "cname")
	}
	var network net.Error
	if errors.As(bindErr, &network) {
		result.Timeout = network.Timeout()
	}
	var ldap *admodel.LDAPError
	if errors.As(bindErr, &ldap) {
		result.LDAPCode = ldap.Code
	}
	var kerberos *admodel.KerberosError
	if errors.As(bindErr, &kerberos) {
		result.KerberosCode = kerberos.Code
	}
	stack := []error{bindErr}
	for examined := 0; len(stack) > 0 && examined < 64; examined++ {
		cause := stack[len(stack)-1]
		stack = stack[:len(stack)-1]
		if cause == nil {
			continue
		}
		result.CauseTypes = append(result.CauseTypes, fmt.Sprintf("%T", cause))
		text := strings.ToLower(cause.Error())
		category := "other"
		switch {
		case strings.Contains(text, "clock skew"):
			category = "clock-skew"
		case strings.Contains(text, "ticket is expired"):
			category = "ticket-time-validity"
		case strings.Contains(text, "exceeded requested ticket lifetime"):
			category = "requested-profile-or-lifetime"
		case strings.Contains(text, "service ticket") && strings.Contains(text, "cache"):
			category = "cache-state"
		case strings.Contains(text, "explicit client"):
			category = "client-identity"
		case strings.Contains(text, "explicit realm"):
			category = "realm-or-service-identity"
		case strings.Contains(text, "ap-rep"):
			category = "mutual-proof"
		case strings.Contains(text, "sasl"):
			category = "sasl-exchange"
		case strings.Contains(text, "checksum") || strings.Contains(text, "integrity"):
			category = "integrity"
		case strings.Contains(text, "key size") || strings.Contains(text, "aes profile"):
			category = "key-profile"
		}
		result.CauseCategories = append(result.CauseCategories, category)
		if joined, ok := cause.(interface{ Unwrap() []error }); ok {
			stack = append(stack, joined.Unwrap()...)
		} else if wrapped, ok := cause.(interface{ Unwrap() error }); ok {
			stack = append(stack, wrapped.Unwrap())
		}
	}
	encoded, err := json.MarshalIndent(result, "", "  ")
	if err != nil {
		t.Fatal("encode safe diagnostic result")
	}
	if err := os.WriteFile(input.Result, append(encoded, '\n'), 0o600); err != nil {
		t.Fatal("write safe diagnostic result")
	}
}
