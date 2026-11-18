package engine

import (
	"context"
	"encoding/json"
	"errors"
	"net"
	"os"
	"runtime"
	"strings"
	"testing"

	krbclient "github.com/deploymenttheory/go-sdk-activedirectory/3rd_party/gokrb5/v8/client"
	ldap "github.com/deploymenttheory/go-sdk-activedirectory/3rd_party/ldap/v3"
	"github.com/deploymenttheory/go-sdk-activedirectory/3rd_party/ldap/v3/gssapi"
	admodel "github.com/deploymenttheory/go-sdk-activedirectory/activedirectory/internal/model"
)

type internalSASLLabResult struct {
	SchemaVersion               int                       `json:"schema_version"`
	RunID                       string                    `json:"run_id"`
	SourceRevision              string                    `json:"source_revision"`
	Platform                    string                    `json:"platform"`
	Toolchain                   string                    `json:"toolchain"`
	CredentialSource            string                    `json:"credential_source"`
	RequestedProtection         string                    `json:"requested_protection"`
	Fault                       string                    `json:"fault"`
	FixtureDN                   string                    `json:"fixture_dn"`
	FixtureGUID                 string                    `json:"fixture_guid"`
	Protection                  admodel.SessionProtection `json:"protection"`
	RootDSEVerified             bool                      `json:"root_dse_verified"`
	IdentityVerified            bool                      `json:"identity_verified"`
	PreflightReads              int                       `json:"preflight_reads"`
	PreflightSchemaBytes        uint64                    `json:"preflight_schema_bytes"`
	ReorderReadDN               string                    `json:"reorder_read_dn,omitempty"`
	ProbeApplicationOperations  int                       `json:"probe_application_operations"`
	WriteState                  string                    `json:"write_state"`
	ErrorClass                  string                    `json:"error_class"`
	ReadbackMatches             bool                      `json:"readback_matches"`
	Retired                     bool                      `json:"retired"`
	SubsequentWriteNotSubmitted bool                      `json:"subsequent_write_not_submitted"`
	ReconciliationReadOnly      bool                      `json:"reconciliation_read_only"`
	ReconciliationMatches       bool                      `json:"reconciliation_matches"`
	FinalAcceptanceObserved     bool                      `json:"final_acceptance_observed"`
	ActualMechanismLayer        int                       `json:"actual_mechanism_layer"`
	ClientRefusedMismatch       bool                      `json:"client_refused_mismatch"`
	Failure                     string                    `json:"failure,omitempty"`
	Success                     bool                      `json:"success"`
}

type internalSASLLabMismatch struct {
	*gssapi.Client
	finalAccepted bool
	actualLayer   int
}

func (m *internalSASLLabMismatch) SetSASLSecurity(int) {
	m.Client.SetSASLSecurity(int(ldap.SASLSecuritySign))
}

func (m *internalSASLLabMismatch) AuthenticationContext() (gssapi.AuthenticationContext, error) {
	observed, err := m.Client.AuthenticationContext()
	m.finalAccepted, m.actualLayer = true, observed.SASLSecurity
	return observed, err
}

func TestPortableSASLLab(t *testing.T) {
	if os.Getenv("ADSDK_SASL_LAB_INPUT") != "stdin" {
		t.Skip("set ADSDK_SASL_LAB_INPUT=stdin for the independently owned SASL fixture")
	}
	input, err := internalReadKerberosLabInput(os.Stdin)
	if err != nil {
		t.Fatal("invalid bounded SASL lab input")
	}
	defer clear(input.Password)
	if input.SourceRevision == "" || input.SourceRevision != internalKerberosLabBuildRevision || input.Transport != "ldap" || input.CBTFault != "" ||
		input.RunID == "" || len(input.RunID) > 40 || strings.IndexFunc(input.RunID, func(c rune) bool {
		return !(c >= 'a' && c <= 'z' || c >= '0' && c <= '9' || c == '-')
	}) != -1 {
		t.Fatal("invalid owned SASL lab identity or binary source label")
	}
	config, err := internalKerberosLabConfig(input)
	if err != nil {
		t.Fatal("invalid owned SASL lab configuration")
	}
	mode, err := internalPortableSASLMode(config)
	if err != nil || mode == ldap.SASLSecurityNone || input.Result == "" {
		t.Fatal("SASL lab requires a protected connection and fresh result path")
	}
	switch input.SASLFault {
	case "", "pass", "selected-sign", "tampered", "reordered", "truncated-prefix", "truncated-body":
	default:
		t.Fatal("unsupported SASL lab fault selection")
	}
	result := internalSASLLabResult{
		SchemaVersion: 1,
		RunID:         input.RunID, SourceRevision: internalKerberosLabBuildRevision, Platform: runtime.GOOS + "/" + runtime.GOARCH,
		Toolchain: runtime.Version(), CredentialSource: input.Source, RequestedProtection: input.Protection, Fault: input.SASLFault,
		FixtureDN: input.FixtureDN, FixtureGUID: input.FixtureGUID, WriteState: "not-attempted",
	}
	file, err := os.OpenFile(input.Result, os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0o600)
	if err != nil {
		t.Fatal("SASL result must be fresh")
	}
	defer func() {
		if err := errors.Join(json.NewEncoder(file).Encode(result), file.Close()); err != nil {
			t.Error("SASL result persistence failed")
		}
	}()
	if input.SASLFault == "selected-sign" {
		result.Success = internalSASLLabRejectMismatch(t.Context(), config, &result)
	} else {
		result.Success = internalSASLLabDirectoryProbe(t.Context(), input, config, mode, &result)
	}
	if !result.Success {
		t.Fatal("owned SASL lab probe failed; inspect count-only result")
	}
}

func internalSASLLabRejectMismatch(ctx context.Context, config admodel.Config, result *internalSASLLabResult) bool {
	if config.SASLProtection != admodel.SASLProtectionSeal || config.Endpoint.Port != 389 {
		result.Failure = "invalid-mismatch-probe"
		return false
	}
	var mechanism *internalSASLLabMismatch
	factory := func(client *krbclient.Client) (ldap.GSSAPIClient, func() error, error) {
		actual, err := gssapi.NewClient(client)
		if err != nil {
			return nil, nil, err
		}
		mechanism = &internalSASLLabMismatch{Client: actual}
		return mechanism, actual.Close, nil
	}
	session, err := internalDialPortableKerberosWithFactory(ctx, config, &net.Dialer{}, factory)
	if session != nil {
		_ = session.InternalClose()
	}
	result.ErrorClass = admodel.Classify(err).String()
	if mechanism != nil {
		result.FinalAcceptanceObserved, result.ActualMechanismLayer = mechanism.finalAccepted, mechanism.actualLayer
	}
	result.ClientRefusedMismatch = err != nil && session == nil && result.FinalAcceptanceObserved && result.ActualMechanismLayer == int(ldap.SASLSecuritySign)
	return result.ClientRefusedMismatch
}

func internalSASLLabOwnedContact(ctx context.Context, session admodel.InternalDirectorySession, input internalKerberosLabInput) (string, error) {
	expectedDN := "CN=probe,OU=sasl,OU=sdk-kerberos-" + input.RunID + ",DC=ad,DC=sdk,DC=test"
	guid, err := admodel.ParseGUID(input.FixtureGUID)
	if err != nil || input.FixtureDN != expectedDN {
		return "", admodel.ErrInvalidConfig
	}
	object, err := session.InternalBaseObject(ctx, input.FixtureDN, []string{"objectGUID", "displayName", "description", "objectClass"})
	if err != nil || len(object["objectguid"]) != 1 || len(object["displayname"]) != 1 || len(object["description"]) != 1 {
		return "", admodel.ErrInvalidResult
	}
	actual, err := admodel.GUIDFromBytes(object["objectguid"][0])
	if err != nil || actual != guid || string(object["displayname"][0]) != "sdk-sasl-contact:"+input.RunID {
		return "", admodel.ErrInvalidResult
	}
	contact := false
	for _, class := range object["objectclass"] {
		contact = contact || strings.EqualFold(string(class), "contact")
	}
	description := string(object["description"][0])
	if !contact || !strings.HasPrefix(description, "sdk-sasl-value:"+input.RunID+":") {
		return "", admodel.ErrInvalidResult
	}
	return description, nil
}

func internalSASLLabDirectoryProbe(ctx context.Context, input internalKerberosLabInput, config admodel.Config, mode ldap.SASLSecurityMode, result *internalSASLLabResult) bool {
	direct := config
	direct.Endpoint.Port = 389 // An explicit independent identity/reconciliation connection.
	preflight, err := InternalDialPortableWithDial(ctx, direct, &net.Dialer{})
	if err != nil {
		result.Failure = "preflight-bind"
		return false
	}
	defer preflight.InternalClose()
	rootAttributes := admodel.InternalDefaultRootDSEAttributes()
	rootRaw, err := preflight.InternalBaseObject(ctx, "", rootAttributes)
	result.PreflightReads++
	if err != nil {
		result.Failure = "root-dse-read"
		return false
	}
	root, err := admodel.InternalDecodeRootDSE(rootRaw, rootAttributes)
	if err != nil || root.Capabilities().RequireADDS("owned SASL fixture") != nil || root.DNSHostName == nil || !strings.EqualFold(*root.DNSHostName, config.Endpoint.Host) {
		result.Failure = "root-dse-identity"
		return false
	}
	result.RootDSEVerified = true
	before, err := internalSASLLabOwnedContact(ctx, preflight, input)
	result.PreflightReads++
	if err != nil {
		result.Failure = "owned-contact-identity"
		return false
	}
	result.IdentityVerified = true
	if input.SASLFault == "reordered" {
		if root.SubschemaSubentry == nil || root.SchemaNamingContext == nil ||
			!strings.EqualFold(*root.SubschemaSubentry, "CN=Aggregate,"+*root.SchemaNamingContext) {
			result.Failure = "subschema-identity"
			return false
		}
		// AD may coalesce a small entry and SearchResultDone into one GSS
		// record. An independently valid schema response larger than the
		// advertised 65535-byte receive limit forces multiple records.
		attributes, schemaErr := preflight.InternalRangedBaseObject(ctx, *root.SubschemaSubentry, []string{"attributeTypes"})
		result.PreflightReads++
		for name, values := range attributes {
			if name != "attributetypes" && !strings.HasPrefix(name, "attributetypes;range=") {
				continue
			}
			for _, value := range values {
				result.PreflightSchemaBytes += uint64(len(value))
			}
		}
		if schemaErr != nil || result.PreflightSchemaBytes <= 65535 {
			result.Failure = "independent-large-schema-control"
			return false
		}
		result.ReorderReadDN = *root.SubschemaSubentry
	}
	session := preflight
	if input.SASLFault != "" {
		if config.Endpoint.Port != 31389 {
			result.Failure = "fault-peer-port"
			return false
		}
		_ = preflight.InternalClose()
		session, err = InternalDialPortableWithDial(ctx, config, &net.Dialer{})
		if err != nil {
			result.Failure = "fault-bind"
			return false
		}
		defer session.InternalClose()
	} else if config.Endpoint.Port != 389 {
		result.Failure = "direct-probe-port"
		return false
	}
	result.Protection, err = session.(admodel.InternalSessionProtectionObserver).InternalSessionProtection(ctx)
	expected, mapErr := internalPortableObservedSASL(mode)
	if err != nil || mapErr != nil || !result.Protection.Complete || !result.Protection.MutualAuthentication || result.Protection.TLSVerified ||
		result.Protection.SASLProtection != expected || result.Protection.ChannelBindingSent || result.Protection.ChannelBound || result.Protection.Delegated ||
		result.Protection.SASLEncryptionType < 17 || result.Protection.SASLEncryptionType > 20 ||
		mode == ldap.SASLSecuritySeal && result.Protection.SASLCipherBits < 128 || mode == ldap.SASLSecuritySign && result.Protection.SASLCipherBits != 0 {
		result.Failure = "unproved-protection"
		return false
	}
	guid, _ := admodel.ParseGUID(input.FixtureGUID)
	value := "sdk-sasl-value:" + input.RunID + ":" + runtime.GOOS + ":" + input.Source + ":" + input.Protection + ":" + input.SASLFault
	request := admodel.InternalLdapWriteRequest{
		InternalOperation: admodel.InternalLdapWriteModify, InternalDn: admodel.InternalObjectGUIDTarget(guid),
		InternalModifications: []admodel.InternalLdapAttributeModification{{InternalOperation: 2, InternalAttribute: "description", InternalValues: [][]byte{[]byte(value)}}},
	}
	if input.SASLFault == "reordered" {
		_, err = session.InternalRangedBaseObject(ctx, result.ReorderReadDN, []string{"attributeTypes"})
		result.ProbeApplicationOperations++
		if err == nil {
			result.Failure = "reordered-record-accepted"
			return false
		}
	} else {
		write := session.(admodel.InternalLdapWriteSession)
		mutation := admodel.ObjectMutationResult{}
		err = admodel.InternalSubmitObjectWrite(ctx, write, request, false, &mutation)
		result.ProbeApplicationOperations++
		switch mutation.State {
		case admodel.ObjectWriteAccepted:
			result.WriteState = "accepted"
		case admodel.ObjectWriteRejected:
			result.WriteState = "rejected"
		case admodel.ObjectWriteUncertain:
			result.WriteState = "uncertain"
		}
		if input.SASLFault == "" || input.SASLFault == "pass" {
			if err != nil || mutation.State != admodel.ObjectWriteAccepted {
				result.Failure = "protected-modify-not-accepted"
				return false
			}
			readback, readErr := internalSASLLabOwnedContact(ctx, session, input)
			result.ProbeApplicationOperations++
			result.ReadbackMatches = readErr == nil && readback == value
			return result.ReadbackMatches
		}
		if mutation.State != admodel.ObjectWriteUncertain || admodel.Classify(err) != admodel.ClassUncertain {
			result.Failure = "submitted-effect-not-uncertain"
			return false
		}
	}
	result.ErrorClass = admodel.Classify(err).String()
	observed, observeErr := session.(admodel.InternalSessionProtectionObserver).InternalSessionProtection(ctx)
	result.Retired = observeErr != nil && !observed.Complete
	next := session.(admodel.InternalLdapWriteSession).InternalLdapWrite(ctx, request)
	result.SubsequentWriteNotSubmitted = next.State == admodel.InternalLdapWriteNotAttempted && errors.Is(next.Err, admodel.ErrClosed)
	if !result.Retired || !result.SubsequentWriteNotSubmitted {
		result.Failure = "failed-stream-reused"
		return false
	}
	reconcile, err := InternalDialPortableWithDial(ctx, direct, &net.Dialer{})
	if err != nil {
		result.Failure = "independent-read-bind"
		return false
	}
	defer reconcile.InternalClose()
	readback, err := internalSASLLabOwnedContact(ctx, reconcile, input)
	result.ReconciliationReadOnly = true
	if input.SASLFault == "reordered" {
		result.ReconciliationMatches = err == nil && readback == before
	} else {
		result.ReconciliationMatches = err == nil && readback == value
	}
	return result.ReconciliationMatches
}
