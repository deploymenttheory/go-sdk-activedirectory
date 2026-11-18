package engine

import (
	"encoding/json"
	"errors"
	"net"
	"os"
	"runtime"
	"testing"
	"time"

	krbclient "github.com/deploymenttheory/go-sdk-activedirectory/3rd_party/gokrb5/v8/client"
	ldap "github.com/deploymenttheory/go-sdk-activedirectory/3rd_party/ldap/v3"
	admodel "github.com/deploymenttheory/go-sdk-activedirectory/activedirectory/internal/model"
)

func TestPortableKerberosServiceExpiryLab(t *testing.T) {
	if os.Getenv("ADSDK_KERBEROS_EXPIRY_LAB_INPUT") != "stdin" {
		t.Skip("set ADSDK_KERBEROS_EXPIRY_LAB_INPUT=stdin for an owned short service-ticket probe")
	}
	input, err := internalReadKerberosLabInput(os.Stdin)
	if err != nil {
		t.Fatal(err)
	}
	defer clear(input.Password)
	if input.SourceRevision == "" || input.SourceRevision != internalKerberosLabBuildRevision || input.Result == "" || input.Source != "cache" ||
		input.TicketLifetimeSeconds < 5 || input.TicketLifetimeSeconds > 20 || input.CBTFault != "" || input.SASLFault != "" {
		t.Fatal("invalid bounded service-expiry fixture")
	}
	c, err := internalKerberosLabConfig(input)
	if err != nil {
		t.Fatal("invalid service-expiry configuration")
	}
	file, err := internalOpenKerberosLabArtifact(input.Result)
	if err != nil {
		t.Fatal("service-expiry result must be fresh")
	}
	result := struct {
		SchemaVersion                 int       `json:"schema_version"`
		RunID                         string    `json:"run_id"`
		SourceRevision                string    `json:"source_revision"`
		Platform                      string    `json:"platform"`
		Toolchain                     string    `json:"toolchain"`
		RequestedLifetimeSeconds      int       `json:"requested_lifetime_seconds"`
		ObservedEndTime               time.Time `json:"observed_service_end_time"`
		ObservedRemainingMilliseconds int64     `json:"observed_remaining_milliseconds"`
		ShortTicketObserved           bool      `json:"short_ticket_observed"`
		Authenticated                 bool      `json:"authenticated"`
		ReadBeforeExpiry              bool      `json:"read_before_expiry"`
		ExpiredError                  bool      `json:"expired_error"`
		OperationAdmissionRefused     bool      `json:"operation_admission_refused"`
		Retired                       bool      `json:"retired"`
		Success                       bool      `json:"success"`
		Failure                       string    `json:"failure,omitempty"`
	}{
		SchemaVersion: 1, RunID: input.RunID, SourceRevision: internalKerberosLabBuildRevision, Platform: runtime.GOOS + "/" + runtime.GOARCH, Toolchain: runtime.Version(),
		RequestedLifetimeSeconds: input.TicketLifetimeSeconds,
	}
	defer func() {
		if err := errors.Join(json.NewEncoder(file).Encode(result), file.Close()); err != nil {
			t.Error("persist service-expiry result")
		}
	}()
	factory := func(client *krbclient.Client) (ldap.GSSAPIClient, func() error, error) {
		// Per-call test policy, before the normal authenticated TGS exchange.
		// A TGT-only source forces a fresh KDC-issued service ticket.
		client.Config.LibDefaults.TicketLifetime = time.Duration(input.TicketLifetimeSeconds) * time.Second
		return internalPortableKerberosMechanism(client)
	}
	session, bindErr := internalDialPortableKerberosWithFactory(t.Context(), c, &net.Dialer{}, factory)
	if bindErr != nil || session == nil {
		result.Failure = "short-service-bind-refused"
		t.Fatal("KDC did not establish the requested short service context")
	}
	defer session.InternalClose()
	actual, ok := session.(*InternalPortableSession)
	if !ok {
		result.Failure = "unexpected-session-backend"
		t.Fatal("expiry fixture did not use the portable session")
	}
	observed, observeErr := actual.InternalSessionProtection(t.Context())
	result.Authenticated = observeErr == nil && observed.Complete && observed.MutualAuthentication
	result.ObservedEndTime = actual.kerberosExpiresAt
	remaining := time.Until(actual.kerberosExpiresAt)
	result.ObservedRemainingMilliseconds = remaining.Milliseconds()
	result.ShortTicketObserved = remaining > time.Second && remaining <= time.Duration(input.TicketLifetimeSeconds+1)*time.Second
	if !result.Authenticated || !result.ShortTicketObserved {
		result.Failure = "no-authenticated-short-service-ticket"
		t.Fatal("cached long ticket or unproved lifetime cannot qualify service expiry")
	}
	root, readErr := actual.InternalBaseObject(t.Context(), "", []string{"defaultNamingContext", "dnsHostName"})
	result.ReadBeforeExpiry = readErr == nil && len(root["defaultnamingcontext"]) == 1 && string(root["defaultnamingcontext"][0]) == "DC=ad,DC=sdk,DC=test"
	if !result.ReadBeforeExpiry {
		result.Failure = "initial-directory-read"
		t.Fatal("short-lived authenticated read failed")
	}
	timer := time.NewTimer(time.Until(actual.kerberosExpiresAt) + 20*time.Millisecond)
	defer timer.Stop()
	select {
	case <-timer.C:
	case <-t.Context().Done():
		result.Failure = "probe-context-ended"
		t.Fatal("expiry probe ended before the actual service deadline")
	}
	called := false
	expiredErr := actual.invoke(t.Context(), "expiry admission", func() error { called = true; return nil })
	result.ExpiredError = errors.Is(expiredErr, admodel.ErrKerberosExpired)
	result.OperationAdmissionRefused = !called
	after, afterErr := actual.InternalSessionProtection(t.Context())
	result.Retired = afterErr != nil && !after.Complete
	result.Success = result.Authenticated && result.ShortTicketObserved && result.ReadBeforeExpiry && result.ExpiredError && result.OperationAdmissionRefused && result.Retired
	if !result.Success {
		result.Failure = "expired-session-was-not-retired"
		t.Fatal("actual service expiry did not retire the operation gate")
	}
}
