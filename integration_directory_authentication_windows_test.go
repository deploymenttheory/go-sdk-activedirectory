//go:build windows && (amd64 || arm64)

package activedirectory

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"io"
	"os"
	"runtime"
	"strings"
	"testing"
	"time"
	"unicode/utf8"
	"unsafe"

	"github.com/deploymenttheory/go-bindings-win32/bindings/win32/networking/ldap"
)

// authObservation is one operation's authentication-and-permissions result. The
// identity modes are recorded separately so a reader can tell which one failed.
type authObservation struct {
	Cmdlet               string `json:"cmdlet"`
	CurrentIdentityRead  bool   `json:"current_identity_read"`
	CurrentDetail        string `json:"current_identity_detail,omitempty"`
	ExplicitIdentityRead bool   `json:"explicit_identity_read"`
	ExplicitDetail       string `json:"explicit_identity_detail,omitempty"`
	CurrentAllocations   int    `json:"current_identity_allocations_remaining"`
	ExplicitAllocations  int    `json:"explicit_identity_allocations_remaining"`
	Passed               bool   `json:"passed"`
}

func (o authObservation) qualifies() bool {
	return o.CurrentIdentityRead && o.ExplicitIdentityRead &&
		o.CurrentAllocations == 0 && o.ExplicitAllocations == 0
}

// authFixture is the isolated credential fixture, delivered on stdin so no
// secret reaches a command line, an environment variable, or a file.
type authFixture struct {
	Server, Domain, Username, UPN, OU, Marker string
	Password                                  []byte
}

// readAuthFixture applies the same namespace and non-ASCII requirements the
// explicit-credential qualification applies, so this test cannot be pointed at
// anything but an owned lab fixture.
func readAuthFixture(t *testing.T) authFixture {
	t.Helper()
	payload, err := io.ReadAll(io.LimitReader(os.Stdin, 16385))
	defer clear(payload)
	if err != nil || len(payload) > 16384 {
		t.Fatal("invalid credential fixture input")
	}
	var input authFixture
	decoder := json.NewDecoder(bytes.NewReader(payload))
	decoder.DisallowUnknownFields()
	if err := decoder.Decode(&input); err != nil {
		t.Fatal("invalid credential fixture encoding")
	}
	if !strings.HasSuffix(strings.ToLower(input.Server), ".ad.sdk.test") ||
		!strings.HasPrefix(input.OU, "OU=ADSDK-Auth-") || !strings.HasSuffix(input.OU, ",DC=ad,DC=sdk,DC=test") ||
		!strings.HasPrefix(input.Marker, "ad-sdk-auth:") || input.UPN != input.Username+"@ad.sdk.test" {
		t.Fatal("credential fixture is outside the isolated lab namespace")
	}
	if len(input.Password) == 0 ||
		len(input.Username) == utf8.RuneCountInString(input.Username) ||
		len(input.Password) == utf8.RuneCount(input.Password) {
		t.Fatal("fixture must exercise non-ASCII account and password text")
	}
	return input
}

// The outer harness creates the fixture and supplies it on stdin only inside an
// owned run. This test performs no directory mutation of its own; every call is
// a paged read or a bind attempt. Ordinary go test invocations skip it.
//
// It qualifies authentication-and-permissions: the current identity and
// explicit Negotiate credentials are compared per operation, against simple
// authentication refused before any bind, invalid credentials refused, an
// access-denied diagnostic retained, and signing and sealing left enabled.
func TestDirectoryAuthenticationSweepLab(t *testing.T) {
	if os.Getenv("ADSDK_AUTH_LAB") != "1" {
		t.Skip("requires an isolated credential fixture and redirected input")
	}
	resultPath := os.Getenv("ADSDK_AUTH_RESULT")
	runID := os.Getenv("ADSDK_AUTH_RUN_ID")
	if resultPath == "" || runID == "" {
		t.Fatal("a run identity and a fresh result path are required")
	}
	fixture := readAuthFixture(t)
	defer clear(fixture.Password)

	artifact := struct {
		SchemaVersion        int               `json:"schema_version"`
		Scope                string            `json:"scope"`
		RunID                string            `json:"run_id"`
		Endpoint             string            `json:"endpoint"`
		RuntimeOS            string            `json:"runtime_os"`
		RuntimeArchitecture  string            `json:"runtime_architecture"`
		Started              time.Time         `json:"started"`
		Finished             time.Time         `json:"finished"`
		Passed               bool              `json:"passed"`
		FullTicketComplete   bool              `json:"full_ticket_complete"`
		FailureStage         string            `json:"failure_stage,omitempty"`
		SimpleRefused        bool              `json:"simple_over_plaintext_refused_before_bind"`
		SimpleDetail         string            `json:"simple_refusal_detail,omitempty"`
		InvalidRefused       bool              `json:"invalid_credentials_refused"`
		InvalidDetail        string            `json:"invalid_credentials_detail,omitempty"`
		SigningEnabled       bool              `json:"signing_enabled"`
		SealingEnabled       bool              `json:"sealing_enabled"`
		DeniedRetained       bool              `json:"access_denied_diagnostic_retained"`
		DeniedCode           uint32            `json:"access_denied_ldap_status"`
		DeniedDetail         string            `json:"access_denied_detail,omitempty"`
		DeletedObjectsDetail string            `json:"deleted_objects_detail,omitempty"`
		SecretNotLogged      bool              `json:"secret_absent_from_rendering_and_errors"`
		Operations           []authObservation `json:"operations"`
	}{
		SchemaVersion: 1, Scope: "directory-authentication-and-permissions", RunID: runID,
		Endpoint: fixture.Server, RuntimeOS: runtime.GOOS, RuntimeArchitecture: runtime.GOARCH,
		Started: time.Now().UTC(), Operations: []authObservation{},
	}
	stage := "start"
	failedAt := ""
	fail := func(format string, args ...any) {
		if failedAt == "" {
			failedAt = stage
		}
		t.Errorf(format, args...)
	}
	defer func() {
		artifact.Finished = time.Now().UTC()
		artifact.Passed = !t.Failed()
		if t.Failed() {
			artifact.FailureStage = failedAt
		}
		data, err := json.MarshalIndent(artifact, "", "  ")
		if err != nil {
			t.Error("cannot encode authentication artifact")
			return
		}
		// A secret must never reach the artifact, whatever else went wrong.
		if bytes.Contains(data, fixture.Password) {
			t.Error("the artifact contains credential material")
			return
		}
		file, err := os.OpenFile(resultPath, os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0600)
		if err != nil {
			t.Error("cannot create fresh authentication artifact")
			return
		}
		_, writeErr := file.Write(append(data, '\n'))
		if closeErr := file.Close(); writeErr != nil || closeErr != nil {
			t.Error("cannot finish authentication artifact")
		}
	}()

	ctx, cancel := context.WithTimeout(context.Background(), 15*time.Minute)
	defer cancel()

	explicit := func() *Credentials {
		return &Credentials{Username: fixture.Username, Password: append([]byte(nil), fixture.Password...)}
	}

	// Simple authentication is the insecure Basic equivalent. Over plain LDAP
	// it must be refused by configuration, before any endpoint is contacted.
	stage = "simple-over-plaintext"
	_, err := Dial(ctx, Config{
		Endpoint: Endpoint{Host: fixture.Server, Port: 389}, Timeout: 5 * time.Second,
		Authentication: AuthenticationSimple, Transport: TransportLDAP, Credentials: explicit(),
	})
	artifact.SimpleRefused = errors.Is(err, ErrInvalidConfig)
	if err != nil {
		artifact.SimpleDetail = err.Error()
	}
	if !artifact.SimpleRefused {
		fail("simple authentication over plaintext was not refused as invalid configuration: %v", err)
	}

	// Invalid credentials must fail the bind and keep the diagnostic.
	stage = "invalid-credentials"
	wrong := append([]byte(nil), fixture.Password...)
	wrong = append(wrong, "-not-the-password"...)
	_, err = Dial(ctx, Config{
		Endpoint: Endpoint{Host: fixture.Server, Port: 389}, Timeout: 10 * time.Second,
		Credentials: &Credentials{Username: fixture.Username, Password: wrong},
	})
	artifact.InvalidRefused = err != nil
	if err != nil {
		artifact.InvalidDetail = err.Error()
	} else {
		fail("a wrong password produced a usable session")
	}

	// No secret may appear in the credential's own rendering or in the
	// diagnostics produced above.
	stage = "secret-containment"
	rendered, marshalErr := json.Marshal(explicit())
	secret := string(fixture.Password)
	artifact.SecretNotLogged = marshalErr == nil &&
		!strings.Contains(string(rendered), secret) &&
		!strings.Contains(explicit().String(), secret) &&
		!strings.Contains(explicit().GoString(), secret) &&
		!strings.Contains(artifact.InvalidDetail, secret) &&
		!strings.Contains(artifact.SimpleDetail, secret)
	if !artifact.SecretNotLogged {
		fail("credential material survived rendering or a diagnostic")
	}

	stage = "explicit-identity-session"
	explicitClient, err := Dial(ctx, Config{
		Endpoint: Endpoint{Host: fixture.Server, Port: 389}, Timeout: 30 * time.Second,
		Credentials: explicit(),
	})
	if err != nil {
		t.Fatal("explicit Negotiate credentials did not establish a session")
	}

	// Signing and sealing are set before the bind and must still be on.
	stage = "signing-and-sealing"
	session := explicitClient.session.(*ldapSession)
	for _, option := range []struct {
		code uint32
		into *bool
	}{{ldap.LDAP_OPT_SIGN, &artifact.SigningEnabled}, {ldap.LDAP_OPT_ENCRYPT, &artifact.SealingEnabled}} {
		var value uint32
		if status := session.getRawOption(int32(option.code), unsafe.Pointer(&value)); status == 0 {
			*option.into = value == 1
		}
	}
	if !artifact.SigningEnabled || !artifact.SealingEnabled {
		fail("signing or sealing was not enabled on the explicit session")
	}

	// A denial has to come from a write. An LDAP search omits objects the bound
	// identity cannot read rather than failing, so a read cannot show that an
	// access-denied status survives. This attempts to create a container inside
	// the fixture's own organizational unit under the ordinary identity, which
	// the directory refuses; anything it did manage to create is inside that
	// unit and the collector removes it recursively.
	stage = "access-denied"
	artifact.DeniedCode = credentialPermissionProbe(explicitClient, fixture.OU, "OrdinaryDenied", fixture.Marker)
	artifact.DeniedRetained = artifact.DeniedCode != 0
	if artifact.DeniedRetained {
		// ldapStatus renders the native status, which is what must survive.
		artifact.DeniedDetail = ldapStatus("ldap_add_sW", artifact.DeniedCode).Error()
	}
	if !artifact.DeniedRetained {
		fail("an ordinary identity was permitted to create an object in the fixture unit")
	}

	// Recorded, not asserted: the deleted-objects read is refused here for a
	// capability reason rather than a permission one, because the recycle bin
	// is not enabled in this lab. It belongs to capability errors, not to this
	// scenario.
	if _, deletedErr := explicitClient.DeletedObjects(ctx, DeletedObjectQuery{
		Search: SearchOptions{PageSize: 16},
	}); deletedErr != nil {
		artifact.DeletedObjectsDetail = deletedErr.Error()
	}

	stage = "default-naming-context"
	defaultNC := ""
	if root, rootErr := explicitClient.RootDSE(ctx, RootDSEOptions{}); rootErr == nil && root.DefaultNamingContext != nil {
		defaultNC = *root.DefaultNamingContext
	}
	if defaultNC == "" {
		_ = explicitClient.Close()
		t.Fatal("the explicit session did not report a default naming context")
	}
	if closeErr := explicitClient.Close(); closeErr != nil {
		fail("explicit session cleanup failed: %v", closeErr)
	}

	// Per operation, both identity modes must read. Each gets its own session,
	// which is how a caller scopes a client.
	stage = "operation-sweep"
	read := func(target sweepTarget, credentials *Credentials) (bool, string, int) {
		client, dialErr := Dial(ctx, Config{
			Endpoint: Endpoint{Host: fixture.Server, Port: 389}, Timeout: 30 * time.Second,
			Credentials: credentials,
		})
		if dialErr != nil {
			return false, "dial: " + dialErr.Error(), 0
		}
		var counts searchNativeCounts
		client.session.(*ldapSession).api = countedSearchAPI(&counts)
		options := SearchOptions{PageSize: 64}
		if target.domainScoped {
			// Scope is explicit: the typed reads infer a base but never a
			// scope, and the domain root carries subordinate naming contexts
			// whose references are reported rather than chased.
			options = SearchOptions{Base: "CN=Users," + defaultNC, Scope: ScopeSubtree, PageSize: 64}
		}
		result, readErr := target.read(ctx, client, options)
		closeErr := client.Close()
		detail := sweepDetail(readErr, result)
		if closeErr != nil {
			detail += " close: " + closeErr.Error()
		}
		return readErr == nil && result.Complete && closeErr == nil, detail, sweepAllocations(counts)
	}
	for _, target := range endpointSweepTargets() {
		o := authObservation{Cmdlet: target.cmdlet}
		o.CurrentIdentityRead, o.CurrentDetail, o.CurrentAllocations = read(target, nil)
		o.ExplicitIdentityRead, o.ExplicitDetail, o.ExplicitAllocations = read(target, explicit())
		o.Passed = o.qualifies()
		if !o.Passed {
			fail("%s: authentication observation incomplete: %+v", target.cmdlet, o)
		}
		artifact.Operations = append(artifact.Operations, o)
	}

	if !t.Failed() {
		stage = "complete"
	}
	t.Logf("authentication and permissions sweep over %d operations on %s; full ticket qualification remains incomplete",
		len(artifact.Operations), fixture.Server)
}
