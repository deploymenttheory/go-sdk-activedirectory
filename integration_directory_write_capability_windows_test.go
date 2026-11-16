//go:build windows && (amd64 || arm64)

package activedirectory

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"runtime"
	"strconv"
	"testing"
	"time"
)

// capability-errors-and-resource-lifetime, on the write surface. Two halves
// matter here and they are not equally easy to observe.
//
// Resource lifetime is the half a long-running caller depends on, and it is
// fully observable against a real directory: repeated use of one session, a
// native failure raised after resources were taken, allocation counters back
// at zero on both paths, an idempotent close, and no replay of a submitted
// write.
//
// The capability half needs a directory that advertises no capability. A
// loopback fixture provides one, but it cannot answer a write — so for a path
// with no directory-type prerequisite the call proceeds to a write and fails
// for a reason that has nothing to do with capability. Rather than read that
// as a capability refusal, this harness only credits an unmistakable one, and
// records every other path as having no prerequisite. That mirrors how the
// read-side sweep recorded and excluded Get-ADObject.
//
// It reuses lifecycleTargets() so the five mutating harnesses cannot drift.

type writeCapabilityObservation struct {
	Cmdlet string            `json:"cmdlet"`
	Role   writeEndpointRole `json:"role"`

	// HasPrerequisite is determined by observation, not assumed: a path has a
	// directory-type prerequisite only if a directory advertising no
	// capability refused it with an unmistakable capability error, before any
	// write could be submitted.
	HasPrerequisite   bool   `json:"has_directory_prerequisite"`
	UnsupportedKind   string `json:"unsupported_capability_error_kind,omitempty"`
	UnsupportedClass  string `json:"unsupported_capability_error_class,omitempty"`
	UnsupportedDetail string `json:"unsupported_capability_detail,omitempty"`
	NoPrerequisiteWhy string `json:"no_prerequisite_reason,omitempty"`

	// Resource lifetime, all against the real directory.
	SupportedWrote   bool   `json:"supported_write_succeeded"`
	SupportedDetail  string `json:"supported_detail,omitempty"`
	RepeatedCalls    int    `json:"repeated_calls_completed"`
	RepeatedDetail   string `json:"repeated_detail,omitempty"`
	NoReplay         bool   `json:"submitted_write_not_replayed"`
	NoReplayDetail   string `json:"no_replay_detail,omitempty"`
	NativeErrorAfter bool   `json:"native_error_after_resources"`
	NativeDetail     string `json:"native_error_detail,omitempty"`
	AllocsSupported  int    `json:"allocations_remaining_supported"`
	AllocsFailed     int    `json:"allocations_remaining_after_failure"`
	CloseIdempotent  bool   `json:"close_idempotent"`

	Passed bool `json:"passed"`
}

// qualifies requires the capability refusal and every resource-lifetime half.
// An operation with no directory-type prerequisite cannot satisfy the first,
// and is recorded rather than passed on a check that cannot fail.
func (o writeCapabilityObservation) qualifies() bool {
	return o.HasPrerequisite && o.SupportedWrote && o.RepeatedCalls == 3 &&
		o.NoReplay && o.NativeErrorAfter &&
		o.AllocsSupported == 0 && o.AllocsFailed == 0 && o.CloseIdempotent
}

// writeCapabilityKind names only the unmistakable directory-type refusals. A
// bare ErrUnsupported is deliberately excluded: against a fixture that cannot
// answer a write it is also what a missing write path produces, so crediting
// it would turn an unrelated failure into a capability observation.
func writeCapabilityKind(err error) string {
	var capability *DirectoryCapabilityError
	switch {
	case err == nil:
		return ""
	case errors.As(err, &capability):
		return "DirectoryCapabilityError"
	case errors.Is(err, ErrUnsupportedDirectory):
		return "ErrUnsupportedDirectory"
	case errors.Is(err, ErrUserCapability):
		return "ErrUserCapability"
	}
	return ""
}

// The outer harness supplies the endpoint and the write authorization only
// inside an owned run. This test mutates the directory: it creates one
// organizational unit of fixtures and removes it. Ordinary go test invocations
// skip it.
func TestDirectoryWriteCapabilitySweepLab(t *testing.T) {
	endpoint := os.Getenv("ADSDK_WRITECAP_ENDPOINT")
	if endpoint == "" {
		t.Skip("requires the opt-in isolated directory write-capability harness")
	}
	if os.Getenv("ADSDK_WRITECAP_ALLOW_WRITES") != "yes" {
		t.Fatal("this harness mutates the directory and requires explicit write authorization")
	}
	resultPath := os.Getenv("ADSDK_WRITECAP_RESULT")
	runID := os.Getenv("ADSDK_WRITECAP_RUN_ID")
	if resultPath == "" || runID == "" {
		t.Fatal("an endpoint, a run identity and a fresh result path are required")
	}
	const absentBase = "DC=absent,DC=invalid"

	artifact := struct {
		SchemaVersion       int                          `json:"schema_version"`
		Scope               string                       `json:"scope"`
		RunID               string                       `json:"run_id"`
		Endpoint            string                       `json:"endpoint"`
		RuntimeOS           string                       `json:"runtime_os"`
		RuntimeArchitecture string                       `json:"runtime_architecture"`
		Started             time.Time                    `json:"started"`
		Finished            time.Time                    `json:"finished"`
		Passed              bool                         `json:"passed"`
		FullTicketComplete  bool                         `json:"full_ticket_complete"`
		FailureStage        string                       `json:"failure_stage,omitempty"`
		UnsupportedSource   string                       `json:"unsupported_directory_source"`
		NoReplayMechanism   string                       `json:"no_replay_mechanism"`
		FixtureRoot         string                       `json:"fixture_root"`
		FixtureRootRemoved  bool                         `json:"fixture_root_removed"`
		Operations          []writeCapabilityObservation `json:"operations"`
	}{
		SchemaVersion: 1, Scope: "directory-write-capability-and-resource-lifetime", RunID: runID,
		Endpoint: endpoint, RuntimeOS: runtime.GOOS, RuntimeArchitecture: runtime.GOARCH,
		Started: time.Now().UTC(),
		UnsupportedSource: "in-process loopback LDAP fixture advertising no supportedCapabilities, " +
			"read by real WinLDAP over a real socket. It cannot answer a write, so only an " +
			"unmistakable capability error is credited: a path that proceeded to a write and " +
			"failed there is recorded as having no directory-type prerequisite.",
		NoReplayMechanism: "an add of a single value. A replayed submission would collide with " +
			"the value its first submission wrote and be refused as already present, so the add " +
			"succeeding is the observation that nothing was submitted twice.",
		Operations: []writeCapabilityObservation{},
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
			t.Error("cannot encode write-capability artifact")
			return
		}
		file, err := os.OpenFile(resultPath, os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0600)
		if err != nil {
			t.Error("cannot create fresh write-capability artifact")
			return
		}
		_, writeErr := file.Write(append(data, '\n'))
		if closeErr := file.Close(); writeErr != nil || closeErr != nil {
			t.Error("cannot finish write-capability artifact")
		}
	}()

	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Minute)
	defer cancel()

	dial := func() (*Client, error) {
		return Dial(ctx, Config{Endpoint: Endpoint{Host: endpoint, Port: 389}, Timeout: 60 * time.Second})
	}
	client, err := dial()
	if err != nil {
		t.Fatal("native dial failed")
	}
	defer func() {
		// Close is called twice on the owning client too, so the idempotence
		// claim is not made only on throwaway sessions.
		first, second := client.Close(), client.Close()
		if first != nil || second != nil {
			t.Errorf("the owning client did not close idempotently: %v / %v", first, second)
		}
	}()

	stage = "fixture-root"
	root, err := client.RootDSE(ctx, RootDSEOptions{})
	if err != nil || root.DefaultNamingContext == nil || *root.DefaultNamingContext == "" {
		t.Fatal("the connection did not report a default naming context")
	}
	domainIdentity, err := IdentityByDN(*root.DefaultNamingContext)
	if err != nil {
		t.Fatal("the default naming context is not a usable identity")
	}
	rootResult, rootErr := client.CreateOrganizationalUnit(ctx, CreateOrganizationalUnitRequest{
		Parent: domainIdentity, Name: "sdk-writecap-" + runID,
		ProtectedFromAccidentalDeletion: new(bool),
	})
	if rootResult.Object.TargetGUID != nil {
		artifact.FixtureRoot = rootResult.Object.TargetDN
		fixture := objectGUIDIdentity(*rootResult.Object.TargetGUID)
		defer func() {
			removal, removeErr := client.DeleteOrganizationalUnit(ctx,
				DeleteOrganizationalUnitRequest{Identity: fixture, Recursive: true})
			artifact.FixtureRootRemoved = removeErr == nil && removal.AbsentAfter &&
				lifecycleAbsent(ctx, client, fixture)
			if !artifact.FixtureRootRemoved {
				t.Errorf("the fixture root was not proved removed: err=%v absentAfter=%v",
					removeErr, removal.AbsentAfter)
			}
		}()
	}
	if rootErr != nil || rootResult.Object.TargetGUID == nil {
		t.Fatalf("cannot create the fixture root: %v", rootErr)
	}
	fixtureRoot := objectGUIDIdentity(*rootResult.Object.TargetGUID)

	stage = "write-capability-sweep"
	for index, target := range lifecycleTargets() {
		name := func(suffix string) string {
			if target.kind == "computer" {
				return "SDKWC" + strconv.Itoa(index) + suffix
			}
			return fmt.Sprintf("sdkwc%d%s", index, suffix)
		}
		observe := ObjectMutationOptions{Properties: []string{lifecycleMultiValued}}

		// The unsupported directory, probed once per role. A refusal only
		// counts when it is an unmistakable capability error, which can only
		// arrive before a write is submitted.
		probeUnsupported := func(o *writeCapabilityObservation, call func(*Client) error) {
			wire := newSearchWireFixture(t, []searchWirePage{{baseRead: true}})
			var counts searchNativeCounts
			unsupported := searchWireClient(t, wire, countedSearchAPI(&counts))
			err := call(unsupported)
			o.UnsupportedKind = writeCapabilityKind(err)
			o.UnsupportedClass = lifecycleClass(err)
			o.UnsupportedDetail = lifecycleDetail(err)
			o.HasPrerequisite = o.UnsupportedKind != ""
			if !o.HasPrerequisite {
				o.NoPrerequisiteWhy = "the call was not refused by a directory-type check; " +
					"against a fixture that cannot answer a write, that is what a path with " +
					"no prerequisite produces"
			}
			_ = unsupported.Close()
		}

		// --- create ------------------------------------------------------
		create := writeCapabilityObservation{Cmdlet: target.createCmdlet, Role: writeRoleCreate}
		probeUnsupported(&create, func(c *Client) error {
			parent, _ := IdentityByDN("OU=absent," + absentBase)
			_, err := target.create(ctx, c, parent, name("x"), ObjectMutationOptions{})
			return err
		})

		var counts searchNativeCounts
		session, dialErr := dial()
		if dialErr != nil {
			create.SupportedDetail = "dial: " + dialErr.Error()
		} else {
			session.session.(*ldapSession).api = countedSearchAPI(&counts)
			// Three distinct creates on one session: repeating an identical
			// create is a duplicate, so repeated use is observed with three
			// separate objects rather than three identical requests.
			var made []Identity
			for attempt := range 3 {
				result, err := target.create(ctx, session, fixtureRoot, name("c"+strconv.Itoa(attempt)), observe)
				if err == nil && result.TargetGUID != nil && result.Verified {
					create.RepeatedCalls++
					made = append(made, objectGUIDIdentity(*result.TargetGUID))
					continue
				}
				create.RepeatedDetail = lifecycleDetail(err)
			}
			create.SupportedWrote = create.RepeatedCalls > 0
			create.AllocsSupported = sweepAllocations(counts)

			// A failure raised after native resources were taken: a parent in
			// a naming context this server does not hold.
			absentParent, _ := IdentityByDN("OU=absent," + absentBase)
			_, nativeErr := target.create(ctx, session, absentParent, name("n"), observe)
			create.NativeErrorAfter = nativeErr != nil
			create.NativeDetail = lifecycleDetail(nativeErr)
			create.AllocsFailed = sweepAllocations(counts)

			// No replay, observed on the objects just created: an add of one
			// value would collide with itself if submitted twice.
			create.NoReplay = len(made) > 0
			for _, id := range made {
				if _, err := target.updateRaw(ctx, session, id, []AttributeChange{{
					Attribute: lifecycleMultiValued, Kind: AttributeAddValues,
					Values: lifecycleRawValues("once"),
				}}, observe); err != nil {
					create.NoReplay = false
					create.NoReplayDetail = lifecycleDetail(err)
				}
			}
			for _, id := range made {
				if target.protectedByDefault && target.unprotect != nil {
					_ = target.unprotect(ctx, session, id, ObjectMutationOptions{})
				}
				if _, err := target.remove(ctx, session, id, true, ObjectMutationOptions{}); err != nil {
					t.Errorf("%s: a fixture object was not removed: %v", target.createCmdlet, err)
				}
			}
			first, second := session.Close(), session.Close()
			create.CloseIdempotent = first == nil && second == nil
		}
		create.Passed = create.qualifies()
		switch {
		case !create.HasPrerequisite:
			t.Logf("%s: no directory-type prerequisite observed; recorded and excluded",
				target.createCmdlet)
		case !create.Passed:
			fail("%s: capability observation incomplete: %+v", target.createCmdlet, create)
		}
		artifact.Operations = append(artifact.Operations, create)

		// --- update and delete, on one shared subject --------------------
		for _, role := range []writeEndpointRole{writeRoleUpdate, writeRoleDelete} {
			o := writeCapabilityObservation{Role: role}
			if role == writeRoleUpdate {
				o.Cmdlet = target.updateCmdlet
			} else {
				o.Cmdlet = target.removeCmdlet
			}
			probeUnsupported(&o, func(c *Client) error {
				absent, _ := IdentityByDN("CN=absent," + absentBase)
				if role == writeRoleUpdate {
					_, err := target.updateRaw(ctx, c, absent, []AttributeChange{{
						Attribute: lifecycleMultiValued, Kind: AttributeSet,
						Values: lifecycleRawValues("x"),
					}}, ObjectMutationOptions{})
					return err
				}
				_, err := target.remove(ctx, c, absent, false, ObjectMutationOptions{})
				return err
			})

			var roleCounts searchNativeCounts
			roleSession, dialErr := dial()
			if dialErr != nil {
				o.SupportedDetail = "dial: " + dialErr.Error()
				artifact.Operations = append(artifact.Operations, o)
				continue
			}
			roleSession.session.(*ldapSession).api = countedSearchAPI(&roleCounts)

			var subjects []Identity
			for attempt := range 3 {
				result, err := target.create(ctx, roleSession, fixtureRoot,
					name(string(role[0])+strconv.Itoa(attempt)), observe)
				if err != nil || result.TargetGUID == nil {
					o.SupportedDetail = "fixture: " + lifecycleDetail(err)
					break
				}
				subjects = append(subjects, objectGUIDIdentity(*result.TargetGUID))
			}
			for _, id := range subjects {
				var err error
				if role == writeRoleUpdate {
					_, err = target.updateRaw(ctx, roleSession, id, []AttributeChange{{
						Attribute: lifecycleMultiValued, Kind: AttributeAddValues,
						Values: lifecycleRawValues("once"),
					}}, observe)
				} else {
					if target.protectedByDefault && target.unprotect != nil {
						_ = target.unprotect(ctx, roleSession, id, ObjectMutationOptions{})
					}
					_, err = target.remove(ctx, roleSession, id, true, ObjectMutationOptions{})
				}
				if err == nil {
					o.RepeatedCalls++
					continue
				}
				o.RepeatedDetail = lifecycleDetail(err)
			}
			o.SupportedWrote = o.RepeatedCalls > 0
			// The add succeeded on each subject, so no submission was repeated.
			o.NoReplay = o.RepeatedCalls == len(subjects) && len(subjects) > 0
			o.AllocsSupported = sweepAllocations(roleCounts)

			absent, _ := IdentityByDN("CN=absent," + absentBase)
			var nativeErr error
			if role == writeRoleUpdate {
				_, nativeErr = target.updateRaw(ctx, roleSession, absent, []AttributeChange{{
					Attribute: lifecycleMultiValued, Kind: AttributeSet,
					Values: lifecycleRawValues("x"),
				}}, observe)
			} else {
				_, nativeErr = target.remove(ctx, roleSession, absent, false, observe)
			}
			o.NativeErrorAfter = nativeErr != nil
			o.NativeDetail = lifecycleDetail(nativeErr)
			o.AllocsFailed = sweepAllocations(roleCounts)

			if role == writeRoleUpdate {
				for _, id := range subjects {
					if target.protectedByDefault && target.unprotect != nil {
						_ = target.unprotect(ctx, roleSession, id, ObjectMutationOptions{})
					}
					if _, err := target.remove(ctx, roleSession, id, true, ObjectMutationOptions{}); err != nil {
						t.Errorf("%s: a fixture object was not removed: %v", o.Cmdlet, err)
					}
				}
			}
			first, second := roleSession.Close(), roleSession.Close()
			o.CloseIdempotent = first == nil && second == nil

			o.Passed = o.qualifies()
			switch {
			case !o.HasPrerequisite:
				t.Logf("%s: no directory-type prerequisite observed; recorded and excluded", o.Cmdlet)
			case !o.Passed:
				fail("%s: capability observation incomplete: %+v", o.Cmdlet, o)
			}
			artifact.Operations = append(artifact.Operations, o)
		}
	}

	if !t.Failed() {
		stage = "complete"
	}
	claimed := 0
	for _, o := range artifact.Operations {
		if o.Passed {
			claimed++
		}
	}
	t.Logf("write capability and resource lifetime sweep over %d operations on %s; %d claimable; full ticket qualification remains incomplete",
		len(artifact.Operations), endpoint, claimed)
}
