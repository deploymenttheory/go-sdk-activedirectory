package engine

import (
	"encoding/json"
	"errors"
	"net"
	"os"
	"runtime"
	"testing"

	krbclient "github.com/deploymenttheory/go-sdk-activedirectory/3rd_party/gokrb5/v8/client"
	ldap "github.com/deploymenttheory/go-sdk-activedirectory/3rd_party/ldap/v3"
	"github.com/deploymenttheory/go-sdk-activedirectory/3rd_party/ldap/v3/gssapi"
	admodel "github.com/deploymenttheory/go-sdk-activedirectory/activedirectory/internal/model"
)

// This observer preserves every mechanism call and result. It never changes the
// requested layer or manufactures a refusal. MS-ADTS forbids SASL traffic layers
// on a TLS-protected AD connection, although RFC4513 permits them generically.
type internalSASLLabTLSObserver struct {
	*gssapi.Client
	mutualReplyVerified bool
	layerAttempted      bool
	layerGenerated      bool
	finalAccepted       bool
}

func (m *internalSASLLabTLSObserver) InitSecContextWithOptions(target string, token []byte, options []int) ([]byte, bool, error) {
	output, more, err := m.Client.InitSecContextWithOptions(target, token, options)
	if len(token) != 0 && err == nil && !more {
		m.mutualReplyVerified = true
	}
	return output, more, err
}

func (m *internalSASLLabTLSObserver) NegotiateSaslAuth(token []byte, authzid string) ([]byte, error) {
	m.layerAttempted = true
	output, err := m.Client.NegotiateSaslAuth(token, authzid)
	m.layerGenerated = err == nil
	return output, err
}

func (m *internalSASLLabTLSObserver) AuthenticationContext() (gssapi.AuthenticationContext, error) {
	m.finalAccepted = true // The bind caller observes only after final LDAP success.
	return m.Client.AuthenticationContext()
}

func TestPortableSASLTLSRefusalLab(t *testing.T) {
	if os.Getenv("ADSDK_SASL_TLS_REFUSAL_LAB_INPUT") != "stdin" {
		t.Skip("set ADSDK_SASL_TLS_REFUSAL_LAB_INPUT=stdin for actual AD TLS/layer refusal")
	}
	input, err := internalReadKerberosLabInput(os.Stdin)
	if err != nil {
		t.Fatal("invalid bounded TLS/layer lab input")
	}
	defer clear(input.Password)
	if input.SourceRevision == "" || input.SourceRevision != internalKerberosLabBuildRevision || input.RunID == "" || input.Result == "" ||
		input.CBTFault != "" || input.SASLFault != "" || input.Protection != "sign" && input.Protection != "seal" ||
		input.Transport != "ldaps" && input.Transport != "starttls" {
		t.Fatal("invalid actual AD TLS/layer refusal selection")
	}
	config, err := internalKerberosLabConfig(input)
	if err != nil {
		t.Fatal("invalid TLS/layer lab configuration")
	}
	result := struct {
		SchemaVersion         int    `json:"schema_version"`
		RunID                 string `json:"run_id"`
		SourceRevision        string `json:"source_revision"`
		Platform              string `json:"platform"`
		Toolchain             string `json:"toolchain"`
		Transport             string `json:"transport"`
		RequestedProtection   string `json:"requested_protection"`
		FactoryCalls          int    `json:"factory_calls"`
		MutualReplyVerified   bool   `json:"mutual_reply_verified"`
		LayerAttempted        bool   `json:"layer_attempted"`
		LayerGenerated        bool   `json:"layer_generated"`
		FinalAcceptance       bool   `json:"final_acceptance"`
		ApplicationOperations int    `json:"application_operations"`
		LDAPCode              uint32 `json:"ldap_code"`
		ErrorClass            string `json:"error_class"`
		Success               bool   `json:"success"`
	}{
		SchemaVersion: 1, RunID: input.RunID, SourceRevision: internalKerberosLabBuildRevision,
		Platform: runtime.GOOS + "/" + runtime.GOARCH, Toolchain: runtime.Version(), Transport: input.Transport, RequestedProtection: input.Protection,
	}
	var observed *internalSASLLabTLSObserver
	factory := func(client *krbclient.Client) (ldap.GSSAPIClient, func() error, error) {
		result.FactoryCalls++
		actual, err := gssapi.NewClient(client)
		if err != nil {
			return nil, nil, err
		}
		observed = &internalSASLLabTLSObserver{Client: actual}
		return observed, actual.Close, nil
	}
	session, bindErr := internalDialPortableKerberosWithFactory(t.Context(), config, &net.Dialer{}, factory)
	if session != nil {
		_ = session.InternalClose()
	}
	if observed != nil {
		result.MutualReplyVerified, result.LayerAttempted = observed.mutualReplyVerified, observed.layerAttempted
		result.LayerGenerated, result.FinalAcceptance = observed.layerGenerated, observed.finalAccepted
	}
	var server *admodel.LDAPError
	if errors.As(bindErr, &server) {
		result.LDAPCode = server.Code
	}
	result.ErrorClass = admodel.Classify(bindErr).String()
	result.Success = bindErr != nil && session == nil && result.FactoryCalls == 1 && result.MutualReplyVerified && result.LayerAttempted && !result.FinalAcceptance
	file, err := os.OpenFile(input.Result, os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0o600)
	if err != nil {
		t.Fatal("TLS/layer refusal result must be fresh")
	}
	if err := errors.Join(json.NewEncoder(file).Encode(result), file.Close()); err != nil {
		t.Fatal("TLS/layer refusal result persistence failed")
	}
	if !result.Success {
		t.Fatal("AD unexpectedly accepted a requested TLS/SASL traffic-layer combination or failed before the observed layer exchange")
	}
}
