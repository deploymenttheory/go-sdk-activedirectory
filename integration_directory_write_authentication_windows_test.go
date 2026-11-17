//go:build windows && (amd64 || arm64)

package activedirectory

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"runtime"
	"strconv"
	"strings"
	"testing"
	"time"
	"unicode/utf8"
)

// authentication-and-permissions, on the write surface. The read sweep
// qualified it by reading; a denied read returns nothing, while a denied write
// is something a caller meets constantly and must be able to act on.
//
// The design uses one ordinary identity and two containers. The identity is
// granted rights on one of them and none on the other, so the same credential
// produces a successful write in one place and a refusal in the other. That
// isolates the permission from everything else: the endpoint, the session, the
// request and the identity are identical across both halves, so a difference
// can only be the access check.
//
// It reuses lifecycleTargets() so the six mutating harnesses cannot drift.

// writeAuthFixture is the isolated credential and container fixture, delivered
// on stdin so no secret reaches a command line, an environment variable or a
// file.
type writeAuthFixture struct {
	Server, Domain, Username, UPN string
	DelegatedOU, DeniedOU, Marker string
	Password                      []byte
}

// readWriteAuthFixture applies the same namespace and non-ASCII requirements
// the read-side credential qualification applies, so this test cannot be
// pointed at anything but an owned lab fixture.
func readWriteAuthFixture(t *testing.T) writeAuthFixture {
	t.Helper()
	payload, err := io.ReadAll(io.LimitReader(os.Stdin, 16385))
	defer clear(payload)
	if err != nil || len(payload) > 16384 {
		t.Fatal("invalid credential fixture input")
	}
	var input writeAuthFixture
	decoder := json.NewDecoder(bytes.NewReader(payload))
	decoder.DisallowUnknownFields()
	if err := decoder.Decode(&input); err != nil {
		t.Fatal("invalid credential fixture encoding")
	}
	const suffix = ",DC=ad,DC=sdk,DC=test"
	if !strings.HasSuffix(strings.ToLower(input.Server), ".ad.sdk.test") ||
		!strings.HasPrefix(input.DelegatedOU, "OU=Delegated,OU=ADSDK-WriteAuth-") ||
		!strings.HasPrefix(input.DeniedOU, "OU=Denied,OU=ADSDK-WriteAuth-") ||
		!strings.HasSuffix(input.DelegatedOU, suffix) || !strings.HasSuffix(input.DeniedOU, suffix) ||
		!strings.HasPrefix(input.Marker, "ad-sdk-writeauth:") ||
		input.UPN != input.Username+"@ad.sdk.test" {
		t.Fatal("credential fixture is outside the isolated lab namespace")
	}
	if input.DelegatedOU == input.DeniedOU {
		t.Fatal("the two containers must differ for the permission to be the only difference")
	}
	if len(input.Password) == 0 ||
		len(input.Username) == utf8.RuneCountInString(input.Username) ||
		len(input.Password) == utf8.RuneCount(input.Password) {
		t.Fatal("fixture must exercise non-ASCII account and password text")
	}
	return input
}

type writeAuthObservation struct {
	Cmdlet string            `json:"cmdlet"`
	Role   writeEndpointRole `json:"role"`

	// The success half: the operation under explicit Negotiate credentials for
	// an identity delegated rights on the container it writes in.
	DelegatedWrote  bool   `json:"delegated_identity_wrote"`
	DelegatedDetail string `json:"delegated_detail,omitempty"`

	// The failure half: the same operation, the same credentials, the same
	// session, in a container the identity has no rights on.
	DeniedRefused bool   `json:"denied_container_refused"`
	DeniedClass   string `json:"denied_container_error_class"`
	DeniedNoWrite bool   `json:"denied_container_wrote_nothing"`
	DeniedDetail  string `json:"denied_container_detail,omitempty"`
	// DeniedStatus is the LDAP result code the directory returned, or zero if
	// the refusal never reached it. It is what distinguishes a refusal the
	// access check produced from one this SDK produced on its own, and it is
	// required whenever the classification is not denied outright.
	DeniedStatus int `json:"denied_container_ldap_status"`

	Allocations int    `json:"native_allocations_remaining"`
	Detail      string `json:"detail,omitempty"`
	Passed      bool   `json:"passed"`
}

// qualifies requires both halves and the allocation balance.
//
// The refusal is normally a denial. It need not be, and insisting on it would
// make this harness wrong rather than the SDK: Active Directory refuses an
// under-privileged computer creation with a constraint violation, LDAP 19,
// not with access denied. Measured, not assumed.
//
// What the design guarantees is that the permission is the only difference
// between the two halves — same endpoint, same session, same credential, same
// request, two containers — so whatever the directory returns is caused by the
// access check. The refusal therefore qualifies on any classification, but only
// when it carried an LDAP status: that is what distinguishes a refusal the
// directory produced from one this SDK produced before reaching it, and the
// latter would mean the access check was never exercised.
func (o writeAuthObservation) qualifies() bool {
	refused := o.DeniedRefused && o.DeniedNoWrite &&
		(o.DeniedClass == ClassDenied.String() || o.DeniedStatus != 0)
	return o.DelegatedWrote && refused && o.Allocations == 0
}

// writeAuthStatus reports the LDAP result code a refusal carried, or zero when
// it never reached the directory.
func writeAuthStatus(err error) int {
	var ldapErr *LDAPError
	if errors.As(err, &ldapErr) {
		return int(ldapErr.Code)
	}
	return 0
}

// The outer harness supplies the fixture only inside an owned run. This test
// mutates the directory, under an ordinary delegated identity rather than the
// collector's own. Ordinary go test invocations skip it.
func TestDirectoryWriteAuthenticationSweepLab(t *testing.T) {
	if os.Getenv("ADSDK_WRITEAUTH_LAB") != "1" {
		t.Skip("requires the opt-in isolated directory write-authentication harness")
	}
	resultPath := os.Getenv("ADSDK_WRITEAUTH_RESULT")
	runID := os.Getenv("ADSDK_WRITEAUTH_RUN_ID")
	if resultPath == "" || runID == "" {
		t.Fatal("a run identity and a fresh result path are required")
	}
	fixture := readWriteAuthFixture(t)
	defer clear(fixture.Password)

	artifact := struct {
		SchemaVersion       int                    `json:"schema_version"`
		Scope               string                 `json:"scope"`
		RunID               string                 `json:"run_id"`
		Endpoint            string                 `json:"endpoint"`
		RuntimeOS           string                 `json:"runtime_os"`
		RuntimeArchitecture string                 `json:"runtime_architecture"`
		Started             time.Time              `json:"started"`
		Finished            time.Time              `json:"finished"`
		Passed              bool                   `json:"passed"`
		FullTicketComplete  bool                   `json:"full_ticket_complete"`
		FailureStage        string                 `json:"failure_stage,omitempty"`
		Design              string                 `json:"design"`
		DelegatedContainer  string                 `json:"delegated_container"`
		DeniedContainer     string                 `json:"denied_container"`
		Operations          []writeAuthObservation `json:"operations"`
	}{
		SchemaVersion: 1, Scope: "directory-write-authentication-and-permissions", RunID: runID,
		Endpoint: fixture.Server, RuntimeOS: runtime.GOOS, RuntimeArchitecture: runtime.GOARCH,
		Started: time.Now().UTC(),
		Design: "One ordinary identity and two containers. The identity is delegated rights on " +
			"one and has none on the other, so the endpoint, the session, the credentials and the " +
			"request are identical across both halves and the only difference is the access check. " +
			"No secret reaches a command line, an environment variable or a file: the credential " +
			"arrives on standard input and is cleared after use.",
		DelegatedContainer: fixture.DelegatedOU, DeniedContainer: fixture.DeniedOU,
		Operations: []writeAuthObservation{},
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
			t.Error("cannot encode write-authentication artifact")
			return
		}
		file, err := os.OpenFile(resultPath, os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0600)
		if err != nil {
			t.Error("cannot create fresh write-authentication artifact")
			return
		}
		_, writeErr := file.Write(append(data, '\n'))
		if closeErr := file.Close(); writeErr != nil || closeErr != nil {
			t.Error("cannot finish write-authentication artifact")
		}
	}()

	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Minute)
	defer cancel()

	stage = "bind-as-the-delegated-identity"
	client, err := Dial(ctx, Config{
		Endpoint: Endpoint{Host: fixture.Server, Port: 389},
		Timeout:  60 * time.Second,
		Credentials: &Credentials{
			Username: fixture.Username, Domain: fixture.Domain,
			Password: append([]byte(nil), fixture.Password...),
		},
	})
	if err != nil {
		t.Fatalf("could not bind as the delegated identity: %v", err)
	}
	defer func() {
		if closeErr := client.Close(); closeErr != nil {
			t.Error("the client did not close cleanly")
		}
	}()

	delegated, err := IdentityByDN(fixture.DelegatedOU)
	if err != nil {
		t.Fatal("the delegated container is not a usable identity")
	}
	denied, err := IdentityByDN(fixture.DeniedOU)
	if err != nil {
		t.Fatal("the denied container is not a usable identity")
	}

	stage = "write-authentication-sweep"
	for index, target := range lifecycleTargets() {
		name := func(suffix string) string {
			if target.kind == "computer" {
				return "SDKWA" + strconv.Itoa(index) + suffix
			}
			return fmt.Sprintf("sdkwa%d%s", index, suffix)
		}
		observe := ObjectMutationOptions{Properties: []string{lifecycleMultiValued}}

		// --- create ------------------------------------------------------
		create := writeAuthObservation{Cmdlet: target.createCmdlet, Role: writeRoleCreate}
		var counts searchNativeCounts
		client.session.(*ldapSession).api = countedSearchAPI(&counts)

		_, deniedErr := target.create(ctx, client, denied, name("d"), observe)
		create.DeniedRefused = deniedErr != nil
		create.DeniedClass = lifecycleClass(deniedErr)
		create.DeniedStatus = writeAuthStatus(deniedErr)
		create.DeniedDetail = lifecycleDetail(deniedErr)

		made, createErr := target.create(ctx, client, delegated, name("c"), observe)
		create.DelegatedWrote = createErr == nil && made.TargetGUID != nil && made.Verified
		create.DelegatedDetail = lifecycleDetail(createErr)
		// The refused create wrote nothing: the delegated create of the same
		// relative name succeeded, and for a computer the account name is
		// unique domain-wide, so a stray in the denied container would have
		// collided with it.
		create.DeniedNoWrite = createErr == nil
		create.Allocations = sweepAllocations(counts)
		create.Passed = create.qualifies()
		if !create.Passed {
			fail("%s: permission observation incomplete: %+v", target.createCmdlet, create)
		}
		artifact.Operations = append(artifact.Operations, create)
		if made.TargetGUID == nil {
			continue
		}
		subject := objectGUIDIdentity(*made.TargetGUID)

		// A second object, created by the collector's own identity inside the
		// denied container, is what the update and delete halves attempt. The
		// delegated identity can see it and not change it, which is exactly
		// the access check being observed.
		victimName := name("v")
		victim, victimErr := lookupDeniedVictim(ctx, client, fixture.DeniedOU, victimName)
		if victimErr != nil {
			create.Detail = "no denied-container subject: " + victimErr.Error()
		}

		for _, role := range []writeEndpointRole{writeRoleUpdate, writeRoleDelete} {
			o := writeAuthObservation{Role: role}
			if role == writeRoleUpdate {
				o.Cmdlet = target.updateCmdlet
			} else {
				o.Cmdlet = target.removeCmdlet
			}
			counts = searchNativeCounts{}
			client.session.(*ldapSession).api = countedSearchAPI(&counts)

			if victimErr != nil {
				o.Detail = "no subject in the denied container to attempt"
				artifact.Operations = append(artifact.Operations, o)
				continue
			}
			before, readable := writeEndpointUSN(ctx, client, victim)
			var attemptErr error
			change := []AttributeChange{{Attribute: lifecycleMultiValued, Kind: AttributeSet,
				Values: lifecycleRawValues("denied")}}
			if role == writeRoleUpdate {
				_, attemptErr = target.updateRaw(ctx, client, victim, change, observe)
			} else {
				_, attemptErr = target.remove(ctx, client, victim, false, observe)
			}
			o.DeniedRefused = attemptErr != nil
			o.DeniedClass = lifecycleClass(attemptErr)
			o.DeniedStatus = writeAuthStatus(attemptErr)
			o.DeniedDetail = lifecycleDetail(attemptErr)
			after, stillThere := writeEndpointUSN(ctx, client, victim)
			o.DeniedNoWrite = readable && stillThere && after == before

			if role == writeRoleUpdate {
				_, err := target.updateRaw(ctx, client, subject, change, observe)
				o.DelegatedWrote = err == nil
				o.DelegatedDetail = lifecycleDetail(err)
			} else {
				if target.protectedByDefault && target.unprotect != nil {
					if err := target.unprotect(ctx, client, subject, ObjectMutationOptions{}); err != nil {
						o.Detail = "unprotect: " + err.Error()
					}
				}
				removal, err := target.remove(ctx, client, subject, true, ObjectMutationOptions{})
				o.DelegatedWrote = err == nil && removal.AbsentAfter
				o.DelegatedDetail = lifecycleDetail(err)
			}
			o.Allocations = sweepAllocations(counts)
			o.Passed = o.qualifies()
			if !o.Passed {
				fail("%s: permission observation incomplete: %+v", o.Cmdlet, o)
			}
			artifact.Operations = append(artifact.Operations, o)
		}
	}

	if !t.Failed() {
		stage = "complete"
	}
	t.Logf("write authentication and permission sweep over %d operations on %s; full ticket qualification remains incomplete",
		len(artifact.Operations), fixture.Server)
}

// lookupDeniedVictim resolves the object the collector placed in the denied
// container for this class. The delegated identity can read it and must not be
// able to change it; if it cannot even be read, the permission observation
// would be measuring visibility rather than the write access check, so the
// caller records that rather than proceeding.
func lookupDeniedVictim(ctx context.Context, c *Client, container, name string) (Identity, error) {
	for _, prefix := range []string{"CN=", "OU="} {
		identity, err := IdentityByDN(prefix + name + "," + container)
		if err != nil {
			continue
		}
		if observed, err := c.ResolveIdentity(ctx, identity,
			ResolveIdentityOptions{Properties: []string{"objectGUID"}}); err == nil && observed.Object != nil {
			return identity, nil
		}
	}
	return Identity{}, fmt.Errorf("%w: no readable subject named %q in the denied container",
		ErrDirectoryObjectNotFound, name)
}
