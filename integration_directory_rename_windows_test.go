//go:build windows && (amd64 || arm64)

package activedirectory

import (
	"context"
	"encoding/json"
	"fmt"
	"os"
	"runtime"
	"slices"
	"strings"
	"testing"
	"time"
)

// Rename-ADObject is the one mutating operation the lifecycle and sweep
// harnesses do not cover, because they drive create, update and delete per
// class and a rename is none of those. Three of its four outstanding scenarios
// need no credential fixture, so this harness takes all three in one run and
// the fourth is added to the write-permission sweep.
//
// The load-bearing claim is that a rename keeps the object's identity. Anything
// tracking a renamed resource addresses it by GUID; if a rename produced a new
// GUID, that tracking would silently break and the old entry would look deleted.

// renameRDNObservation covers rdn-rename-and-collision: that a rename moves the
// relative name and nothing else, and that a collision is refused cleanly.
type renameRDNObservation struct {
	BeforeDN string `json:"before_dn"`
	AfterDN  string `json:"after_dn"`

	// The identity claim. GUIDStable is the one a caller cannot do without.
	GUIDStable bool `json:"guid_unchanged_by_rename"`
	Verified   bool `json:"rename_verified"`
	RDNChanged bool `json:"relative_name_changed"`
	ParentKept bool `json:"parent_unchanged"`
	OldDNGone  bool `json:"old_distinguished_name_no_longer_resolves"`
	NewDNFound bool `json:"new_distinguished_name_resolves"`

	// Unrelated state must survive a rename untouched.
	AttributesSurvived bool `json:"unrelated_attribute_survived"`

	// Names that need escaping, and names outside ASCII, must round-trip.
	EscapedRoundTrip bool   `json:"escaped_name_round_tripped"`
	ExoticRoundTrip  bool   `json:"non_ascii_name_round_tripped"`
	RoundTripDetail  string `json:"round_trip_detail,omitempty"`

	// The collision half: a relative name already taken in the same container.
	CollisionRefused  bool   `json:"collision_refused"`
	CollisionClass    string `json:"collision_error_class"`
	CollisionNoChange bool   `json:"collision_left_the_object_unchanged"`
	CollisionDetail   string `json:"collision_detail,omitempty"`

	Detail string `json:"detail,omitempty"`
	Passed bool   `json:"passed"`
}

func (o renameRDNObservation) qualifies() bool {
	identity := o.GUIDStable && o.Verified && o.RDNChanged && o.ParentKept &&
		o.OldDNGone && o.NewDNFound && o.AttributesSurvived
	names := o.EscapedRoundTrip && o.ExoticRoundTrip
	collision := o.CollisionRefused && o.CollisionNoChange &&
		o.CollisionClass == ClassAlreadyExists.String()
	return identity && names && collision
}

// renameIdentityObservation covers identity-forms-and-scope: the generic object
// path documents a distinguished name or a GUID and nothing else, so the other
// two forms must be refused rather than resolved by guesswork.
type renameIdentityObservation struct {
	ByDN         bool   `json:"renamed_by_distinguished_name"`
	ByGUID       bool   `json:"renamed_by_guid"`
	FormsDetail  string `json:"forms_detail,omitempty"`
	SIDClass     string `json:"security_identifier_form_error_class"`
	AccountClass string `json:"account_name_form_error_class"`
	ScopeClass   string `json:"out_of_scope_error_class"`
	ScopeNoWrite bool   `json:"out_of_scope_wrote_nothing"`
	RefusalsKept bool   `json:"every_undocumented_form_refused"`

	Detail string `json:"detail,omitempty"`
	Passed bool   `json:"passed"`
}

func (o renameIdentityObservation) qualifies() bool {
	request := func(class string) bool {
		return class == ClassInvalidRequest.String() || class == ClassUnsupported.String()
	}
	return o.ByDN && o.ByGUID && o.RefusalsKept && o.ScopeNoWrite &&
		request(o.SIDClass) && request(o.AccountClass) && request(o.ScopeClass)
}

// The outer harness supplies the endpoint and the write authorization only
// inside an owned run. This test mutates the directory: it creates one
// organizational unit of fixtures and removes it. Ordinary go test invocations
// skip it.
func TestDirectoryRenameSweepLab(t *testing.T) {
	endpoint := os.Getenv("ADSDK_RENAME_ENDPOINT")
	if endpoint == "" {
		t.Skip("requires the opt-in isolated directory rename harness")
	}
	if os.Getenv("ADSDK_RENAME_ALLOW_WRITES") != "yes" {
		t.Fatal("this harness mutates the directory and requires explicit write authorization")
	}
	resultPath := os.Getenv("ADSDK_RENAME_RESULT")
	runID := os.Getenv("ADSDK_RENAME_RUN_ID")
	if resultPath == "" || runID == "" {
		t.Fatal("an endpoint, a run identity and a fresh result path are required")
	}

	artifact := struct {
		SchemaVersion       int                        `json:"schema_version"`
		Scope               string                     `json:"scope"`
		RunID               string                     `json:"run_id"`
		Endpoint            string                     `json:"endpoint"`
		RuntimeOS           string                     `json:"runtime_os"`
		RuntimeArchitecture string                     `json:"runtime_architecture"`
		Started             time.Time                  `json:"started"`
		Finished            time.Time                  `json:"finished"`
		Passed              bool                       `json:"passed"`
		FullTicketComplete  bool                       `json:"full_ticket_complete"`
		FailureStage        string                     `json:"failure_stage,omitempty"`
		FixtureRoot         string                     `json:"fixture_root"`
		FixtureRootRemoved  bool                       `json:"fixture_root_removed"`
		RDN                 renameRDNObservation       `json:"rdn_rename_and_collision"`
		Identity            renameIdentityObservation  `json:"identity_forms_and_scope"`
		Capability          writeCapabilityObservation `json:"capability_and_resource_lifetime"`
	}{
		SchemaVersion: 1, Scope: "directory-rename-object", RunID: runID,
		Endpoint: endpoint, RuntimeOS: runtime.GOOS, RuntimeArchitecture: runtime.GOARCH,
		Started: time.Now().UTC(),
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
			t.Error("cannot encode rename artifact")
			return
		}
		file, err := os.OpenFile(resultPath, os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0600)
		if err != nil {
			t.Error("cannot create fresh rename artifact")
			return
		}
		_, writeErr := file.Write(append(data, '\n'))
		if closeErr := file.Close(); writeErr != nil || closeErr != nil {
			t.Error("cannot finish rename artifact")
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
		if closeErr := client.Close(); closeErr != nil {
			t.Error("the owning client did not close cleanly")
		}
	}()

	stage = "fixture-root"
	root, err := client.RootDSE(ctx, RootDSEOptions{})
	if err != nil || root.DefaultNamingContext == nil || *root.DefaultNamingContext == "" {
		t.Fatal("the connection did not report a default naming context")
	}
	domain := *root.DefaultNamingContext
	domainIdentity, err := IdentityByDN(domain)
	if err != nil {
		t.Fatal("the default naming context is not a usable identity")
	}
	rootResult, rootErr := client.CreateOrganizationalUnit(ctx, CreateOrganizationalUnitRequest{
		Parent: domainIdentity, Name: "sdk-rename-" + runID,
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
	fixtureRootDN := rootResult.Object.TargetDN
	observe := ObjectMutationOptions{Properties: []string{lifecycleMultiValued}}

	// make creates one container fixture carrying a marker attribute, so a
	// rename can be shown to move the name and leave everything else alone.
	const marker = "sdk-rename-marker"
	make1 := func(name string) (ObjectMutationResult, error) {
		return client.CreateObject(ctx, CreateObjectRequest{
			Parent: fixtureRoot, Class: "container", Name: name,
			Attributes: map[string][]RawValue{lifecycleMultiValued: {NewRawValue([]byte(marker))}},
			Options:    observe,
		})
	}

	// --- rdn-rename-and-collision ------------------------------------------
	stage = "rdn-rename-and-collision"
	rdn := renameRDNObservation{}
	subject, subjectErr := make1("sdkrn-before")
	if subjectErr != nil || subject.TargetGUID == nil {
		rdn.Detail = "fixture: " + lifecycleDetail(subjectErr)
		fail("cannot create the rename subject: %v", subjectErr)
	} else {
		id := objectGUIDIdentity(*subject.TargetGUID)
		rdn.BeforeDN = subject.TargetDN
		renamed, renameErr := client.RenameObject(ctx, RenameObjectRequest{
			Identity: id, Name: "sdkrn-after", Options: observe})
		rdn.AfterDN = renamed.TargetDN
		rdn.Verified = renameErr == nil && renamed.Verified
		rdn.Detail = lifecycleDetail(renameErr)
		if renamed.After != nil {
			rdn.AfterDN = renamed.After.DistinguishedName
		}
		// The object is still the same object.
		rdn.GUIDStable = renamed.TargetGUID != nil && *renamed.TargetGUID == *subject.TargetGUID
		rdn.RDNChanged = !strings.EqualFold(rdn.AfterDN, rdn.BeforeDN) &&
			strings.HasPrefix(strings.ToLower(rdn.AfterDN), "cn=sdkrn-after,")
		rdn.ParentKept = strings.HasSuffix(strings.ToLower(rdn.AfterDN),
			strings.ToLower(","+fixtureRootDN))

		if before, err := IdentityByDN(rdn.BeforeDN); err == nil {
			rdn.OldDNGone = lifecycleAbsent(ctx, client, before)
		}
		if after, err := IdentityByDN(rdn.AfterDN); err == nil {
			rdn.NewDNFound = !lifecycleAbsent(ctx, client, after)
		}
		values, state, _ := lifecycleValues(ctx, client, id, lifecycleMultiValued)
		rdn.AttributesSurvived = state == AttributePresent && slices.Contains(values, marker)

		// A relative name whose comma and plus must be escaped, and one
		// outside ASCII including a supplementary-plane character. Both have
		// to come back as the literal value that was asked for.
		for _, probe := range []struct {
			name  string
			apply func(bool)
		}{
			{`sdkrn\,esc+plus`, func(ok bool) { rdn.EscapedRoundTrip = ok }},
			{"sdkrn-é\U0001f511", func(ok bool) { rdn.ExoticRoundTrip = ok }},
		} {
			result, err := client.RenameObject(ctx, RenameObjectRequest{
				Identity: id, Name: probe.name, Options: observe})
			if err != nil || result.After == nil {
				rdn.RoundTripDetail = strings.TrimSpace(rdn.RoundTripDetail + " " + lifecycleDetail(err))
				probe.apply(false)
				continue
			}
			parsed, parseErr := parseIdentityDN(result.After.DistinguishedName)
			probe.apply(parseErr == nil && len(parsed) > 0 && len(parsed[0]) == 1 &&
				parsed[0][0].value == probe.name)
		}

		// The collision: a second object, then a rename onto its relative
		// name in the same container.
		other, otherErr := make1("sdkrn-taken")
		switch {
		case otherErr != nil || other.TargetGUID == nil:
			rdn.Detail = strings.TrimSpace(rdn.Detail + " collision fixture: " + lifecycleDetail(otherErr))
		default:
			before, readable := writeEndpointUSN(ctx, client, id)
			observed, _ := client.ResolveIdentity(ctx, id,
				ResolveIdentityOptions{Properties: []string{"objectGUID"}})
			beforeDN := ""
			if observed.Object != nil {
				beforeDN = observed.Object.DistinguishedName
			}
			_, collisionErr := client.RenameObject(ctx, RenameObjectRequest{
				Identity: id, Name: "sdkrn-taken", Options: observe})
			rdn.CollisionRefused = collisionErr != nil
			rdn.CollisionClass = lifecycleClass(collisionErr)
			rdn.CollisionDetail = lifecycleDetail(collisionErr)
			after, stillThere := writeEndpointUSN(ctx, client, id)
			observed, _ = client.ResolveIdentity(ctx, id,
				ResolveIdentityOptions{Properties: []string{"objectGUID"}})
			unchangedDN := observed.Object != nil && observed.Object.DistinguishedName == beforeDN
			rdn.CollisionNoChange = readable && stillThere && after == before && unchangedDN
		}
	}
	rdn.Passed = rdn.qualifies()
	if !rdn.Passed {
		fail("rdn-rename-and-collision incomplete: %+v", rdn)
	}
	artifact.RDN = rdn

	// --- identity-forms-and-scope ------------------------------------------
	stage = "identity-forms-and-scope"
	forms := renameIdentityObservation{}
	byForm, formErr := make1("sdkrn-forms")
	if formErr != nil || byForm.TargetGUID == nil {
		forms.Detail = "fixture: " + lifecycleDetail(formErr)
		fail("cannot create the identity-form subject: %v", formErr)
	} else {
		guid := objectGUIDIdentity(*byForm.TargetGUID)
		current := byForm.TargetDN
		// A distinguished name, then a GUID. Both are documented, so both must
		// move the object.
		if dn, err := IdentityByDN(current); err == nil {
			result, renameErr := client.RenameObject(ctx, RenameObjectRequest{
				Identity: dn, Name: "sdkrn-bydn", Options: observe})
			forms.ByDN = renameErr == nil && result.Verified
			forms.FormsDetail = lifecycleDetail(renameErr)
		}
		result, renameErr := client.RenameObject(ctx, RenameObjectRequest{
			Identity: guid, Name: "sdkrn-byguid", Options: observe})
		forms.ByGUID = renameErr == nil && result.Verified
		if renameErr != nil {
			forms.FormsDetail = strings.TrimSpace(forms.FormsDetail + " " + lifecycleDetail(renameErr))
		}

		// The two forms the generic object path does not document. Neither may
		// be resolved by guesswork, and neither may change anything.
		before, readable := writeEndpointUSN(ctx, client, guid)
		sid, sidErr := IdentityBySID("S-1-5-21-1004336348-1177238915-682003330-512")
		account, accountErr := IdentityByAccountName("sdkrnforms")
		if sidErr != nil || accountErr != nil {
			forms.Detail = "cannot build the undocumented identity forms"
		}
		_, bySIDErr := client.RenameObject(ctx, RenameObjectRequest{
			Identity: sid, Name: "sdkrn-bysid", Options: observe})
		forms.SIDClass = lifecycleClass(bySIDErr)
		_, byAccountErr := client.RenameObject(ctx, RenameObjectRequest{
			Identity: account, Name: "sdkrn-byaccount", Options: observe})
		forms.AccountClass = lifecycleClass(byAccountErr)

		// Scope: a documented form, but a partition that does not hold it.
		scoped := observe
		if root.ConfigurationNamingContext != nil {
			scoped.Partition = *root.ConfigurationNamingContext
		}
		dnForScope, _ := IdentityByDN("CN=sdkrn-byguid," + fixtureRootDN)
		_, scopeErr := client.RenameObject(ctx, RenameObjectRequest{
			Identity: dnForScope, Name: "sdkrn-scoped", Options: scoped})
		forms.ScopeClass = lifecycleClass(scopeErr)
		after, stillThere := writeEndpointUSN(ctx, client, guid)
		forms.ScopeNoWrite = readable && stillThere && after == before
		forms.RefusalsKept = bySIDErr != nil && byAccountErr != nil && scopeErr != nil
	}
	forms.Passed = forms.qualifies()
	if !forms.Passed {
		fail("identity-forms-and-scope incomplete: %+v", forms)
	}
	artifact.Identity = forms

	// --- capability-errors-and-resource-lifetime ---------------------------
	stage = "capability-and-resource-lifetime"
	capability := writeCapabilityObservation{Cmdlet: "Rename-ADObject", Role: writeRoleRename}
	wire := newSearchWireFixture(t, []searchWirePage{{baseRead: true}})
	var fixtureCounts searchNativeCounts
	unsupported := searchWireClient(t, wire, countedSearchAPI(&fixtureCounts))
	// A name inside the real domain that no object carries, so resolving it
	// runs a genuine search: native resources are taken and must then be
	// released. A partition the server does not hold would be refused by a
	// scope check first, and the allocation balance after it would be
	// trivially zero rather than evidence of release.
	absentID, _ := IdentityByDN("CN=sdkrn-absent," + fixtureRootDN)
	_, unsupportedErr := unsupported.RenameObject(ctx, RenameObjectRequest{
		Identity: absentID, Name: "sdkrn-nope"})
	capability.UnsupportedKind = writeCapabilityKind(unsupportedErr)
	capability.UnsupportedClass = lifecycleClass(unsupportedErr)
	capability.UnsupportedDetail = lifecycleDetail(unsupportedErr)
	capability.HasPrerequisite = capability.UnsupportedKind != ""
	if !capability.HasPrerequisite {
		capability.NoPrerequisiteWhy = "the call was not refused by a directory-type check"
	}
	_ = unsupported.Close()

	var counts searchNativeCounts
	session, sessionErr := dial()
	if sessionErr != nil {
		capability.SupportedDetail = "dial: " + sessionErr.Error()
	} else {
		session.session.(*ldapSession).api = countedSearchAPI(&counts)
		lifetime, lifetimeErr := client.CreateObject(ctx, CreateObjectRequest{
			Parent: fixtureRoot, Class: "container", Name: "sdkrn-lifetime"})
		if lifetimeErr != nil || lifetime.TargetGUID == nil {
			capability.SupportedDetail = "fixture: " + lifecycleDetail(lifetimeErr)
		} else {
			id := objectGUIDIdentity(*lifetime.TargetGUID)
			// Three renames on one session. Each uses a fresh name, because
			// renaming to the name it already has is not a repeat.
			for attempt := range 3 {
				result, err := session.RenameObject(ctx, RenameObjectRequest{
					Identity: id, Name: fmt.Sprintf("sdkrn-lifetime%d", attempt), Options: observe})
				if err == nil && result.Verified {
					capability.RepeatedCalls++
					continue
				}
				capability.RepeatedDetail = lifecycleDetail(err)
			}
			capability.SupportedWrote = capability.RepeatedCalls > 0
			// Each rename landed, so none was submitted twice: a replayed
			// rename would have been asked to move a name that had already
			// moved and been refused.
			capability.NoReplay = capability.RepeatedCalls == 3
			capability.AllocsSupported = sweepAllocations(counts)

			_, nativeErr := session.RenameObject(ctx, RenameObjectRequest{
				Identity: absentID, Name: "sdkrn-native", Options: observe})
			capability.NativeErrorAfter = nativeErr != nil
			capability.NativeDetail = lifecycleDetail(nativeErr)
			capability.AllocsFailed = sweepAllocations(counts)
		}
		first, second := session.Close(), session.Close()
		capability.CloseIdempotent = first == nil && second == nil
	}
	capability.Passed = capability.qualifies()
	if !capability.Passed {
		fail("capability-errors-and-resource-lifetime incomplete: %+v", capability)
	}
	artifact.Capability = capability

	if !t.Failed() {
		stage = "complete"
	}
	t.Logf("rename qualification on %s; full ticket qualification remains incomplete", endpoint)
}
