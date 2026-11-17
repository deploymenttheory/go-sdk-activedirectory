//go:build windows && (amd64 || arm64)

package acceptance

import (
	"context"
	"encoding/json"
	"fmt"
	"os"
	"runtime"
	"slices"
	"strconv"
	"testing"
	"time"

	adengine "github.com/deploymenttheory/go-sdk-activedirectory/activedirectory/internal/engine"
	admodel "github.com/deploymenttheory/go-sdk-activedirectory/activedirectory/internal/model"
	adservice_organizational_units "github.com/deploymenttheory/go-sdk-activedirectory/activedirectory/services/organizational_units"
)

// attribute-update-intent and instance-update-semantics are attached to the
// New- operations as well as the Set- ones, and the lifecycle sweep qualified
// only the Set- halves: it creates with naming inputs alone.
//
// Setting attributes at create time is the most-used write path there is. A
// caller declaring a resource states its attributes and its typed properties
// in the same breath as its name, so a create that quietly dropped them, or
// that accepted an invalid one and wrote a partial object, would be a defect
// reached on the very first apply.
//
// This is that half. It reuses lifecycleTargets() so the four mutating
// harnesses cannot drift on which operation does what.

// createAttributesObservation is one class's create-time record. The raw and
// typed halves are separate because they are separate scenarios, and each
// records why it failed rather than only that it did.
type InternalCreateAttributesObservation struct {
	Cmdlet string `json:"cmdlet"`
	Class  string `json:"class"`

	// attribute-update-intent, at create: explicit raw attributes.
	RawMultiValued   bool   `json:"raw_multi_valued_applied"`
	RawNonASCIIKept  bool   `json:"raw_non_ascii_preserved"`
	RawVerified      bool   `json:"raw_create_verified"`
	RawDetail        string `json:"raw_detail,omitempty"`
	UndefinedRefused bool   `json:"undefined_attribute_refused"`
	UndefinedClass   string `json:"undefined_attribute_error_class"`
	UndefinedNoWrite bool   `json:"undefined_attribute_created_nothing"`
	UndefinedDetail  string `json:"undefined_attribute_detail,omitempty"`

	// instance-update-semantics, at create: a typed property set, which is the
	// documented replacement for the module's -Instance.
	TypedMechanism string `json:"typed_mechanism"`
	// TypedNotApplicable is set where the path has no typed property layer to
	// exercise, which is only the generic object path. It must carry a reason:
	// an empty escape hatch would wave the half through silently, and the
	// instance scenario is simply not claimed for that operation.
	TypedNotApplicable string `json:"typed_not_applicable,omitempty"`
	TypedApplied       bool   `json:"typed_property_applied"`
	TypedOnlyAsked     bool   `json:"only_the_asked_for_property_was_set"`
	TypedVerified      bool   `json:"typed_create_verified"`
	TypedDetail        string `json:"typed_detail,omitempty"`
	InvalidRefused     bool   `json:"invalid_typed_value_refused"`
	InvalidClass       string `json:"invalid_typed_value_error_class"`
	InvalidNoWrite     bool   `json:"invalid_typed_value_created_nothing"`
	InvalidDetail      string `json:"invalid_typed_value_detail,omitempty"`

	Allocations int    `json:"native_allocations_remaining"`
	Detail      string `json:"detail,omitempty"`
	Passed      bool   `json:"passed"`
}

// qualifies requires both halves of both scenarios. A refusal has to be
// reported as a request to correct — never as a denial or an uncertain write,
// which would mean the create had reached the directory and tried.
func (o InternalCreateAttributesObservation) InternalQualifies() bool {
	requestLevel := func(class string) bool {
		return class == admodel.ClassInvalidRequest.String() ||
			class == admodel.ClassUnsupported.String()
	}
	raw := o.RawMultiValued && o.RawNonASCIIKept && o.RawVerified &&
		o.UndefinedRefused && o.UndefinedNoWrite && requestLevel(o.UndefinedClass)
	typed := o.TypedNotApplicable != "" ||
		(o.TypedApplied && o.TypedOnlyAsked && o.TypedVerified &&
			o.InvalidRefused && o.InvalidNoWrite && requestLevel(o.InvalidClass))
	return raw && typed && o.Allocations == 0
}

// The outer harness supplies the endpoint and the write authorization only
// inside an owned run. This test mutates the directory: it creates one
// organizational unit of fixtures and removes it. Ordinary go test invocations
// skip it.
func TestDirectoryCreateAttributesSweepLab(t *testing.T) {
	endpoint := os.Getenv("ADSDK_CREATEATTR_ENDPOINT")
	if endpoint == "" {
		t.Skip("requires the opt-in isolated directory create-attributes harness")
	}
	if os.Getenv("ADSDK_CREATEATTR_ALLOW_WRITES") != "yes" {
		t.Fatal("this harness mutates the directory and requires explicit write authorization")
	}
	resultPath := os.Getenv("ADSDK_CREATEATTR_RESULT")
	runID := os.Getenv("ADSDK_CREATEATTR_RUN_ID")
	if resultPath == "" || runID == "" {
		t.Fatal("an endpoint, a run identity and a fresh result path are required")
	}

	artifact := struct {
		SchemaVersion       int                                   `json:"schema_version"`
		Scope               string                                `json:"scope"`
		RunID               string                                `json:"run_id"`
		Endpoint            string                                `json:"endpoint"`
		RuntimeOS           string                                `json:"runtime_os"`
		RuntimeArchitecture string                                `json:"runtime_architecture"`
		Started             time.Time                             `json:"started"`
		Finished            time.Time                             `json:"finished"`
		Passed              bool                                  `json:"passed"`
		FullTicketComplete  bool                                  `json:"full_ticket_complete"`
		FailureStage        string                                `json:"failure_stage,omitempty"`
		Coverage            string                                `json:"what_the_create_half_covers"`
		FixtureRoot         string                                `json:"fixture_root"`
		FixtureRootRemoved  bool                                  `json:"fixture_root_removed"`
		Operations          []InternalCreateAttributesObservation `json:"operations"`
	}{
		SchemaVersion: 1, Scope: "directory-create-time-attributes-and-instance", RunID: runID,
		Endpoint: endpoint, RuntimeOS: runtime.GOOS, RuntimeArchitecture: runtime.GOARCH,
		Started: time.Now().UTC(),
		Coverage: "A create has nothing to add to, remove from or clear, so the create half of " +
			"attribute-update-intent is necessarily narrower than the update half: it covers an " +
			"explicit multi-valued set, non-ASCII and supplementary-plane value preservation, and " +
			"an invalid schema value. Binary values at create time are not covered, because no " +
			"writable binary attribute is available on all five classes.",
		Operations: []InternalCreateAttributesObservation{},
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
			t.Error("cannot encode create-attributes artifact")
			return
		}
		file, err := os.OpenFile(resultPath, os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0o600)
		if err != nil {
			t.Error("cannot create fresh create-attributes artifact")
			return
		}
		_, writeErr := file.Write(append(data, '\n'))
		if closeErr := file.Close(); writeErr != nil || closeErr != nil {
			t.Error("cannot finish create-attributes artifact")
		}
	}()

	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Minute)
	defer cancel()

	client, err := adengine.Dial(
		ctx,
		admodel.Config{
			Endpoint: admodel.Endpoint{Host: endpoint, Port: 389},
			Timeout:  60 * time.Second,
		},
	)
	if err != nil {
		t.Fatal("native dial failed")
	}
	defer func() {
		if closeErr := client.Close(); closeErr != nil {
			t.Error("the client did not close cleanly")
		}
	}()

	stage = "default-naming-context"
	root, err := client.RootDSE(ctx, admodel.RootDSEOptions{})
	if err != nil || root.DefaultNamingContext == nil || *root.DefaultNamingContext == "" {
		t.Fatal("the connection did not report a default naming context")
	}

	stage = "fixture-root"
	domainIdentity, err := admodel.IdentityByDN(*root.DefaultNamingContext)
	if err != nil {
		t.Fatal("the default naming context is not a usable identity")
	}
	// An organizational unit, not a container: an organizationalUnit cannot be
	// created inside a container, which the directory refuses with LDAP 64.
	rootResult, rootErr := adservice_organizational_units.New(client).
		CreateOrganizationalUnit(ctx, admodel.CreateOrganizationalUnitRequest{
			Parent: domainIdentity, Name: "sdk-createattr-" + runID,
			ProtectedFromAccidentalDeletion: new(bool),
		})
	if rootResult.Object.TargetGUID != nil {
		artifact.FixtureRoot = rootResult.Object.TargetDN
		fixture := admodel.InternalObjectGUIDIdentity(*rootResult.Object.TargetGUID)
		defer func() {
			removal, removeErr := adservice_organizational_units.New(client).
				DeleteOrganizationalUnit(ctx, admodel.DeleteOrganizationalUnitRequest{Identity: fixture, Recursive: true})
			artifact.FixtureRootRemoved = removeErr == nil && removal.AbsentAfter &&
				InternalLifecycleAbsent(ctx, client, fixture)
			if !artifact.FixtureRootRemoved {
				t.Errorf("the fixture root was not proved removed: err=%v absentAfter=%v",
					removeErr, removal.AbsentAfter)
			}
		}()
	}
	if rootErr != nil || rootResult.Object.TargetGUID == nil {
		t.Fatalf("cannot create the fixture root: %v", rootErr)
	}
	fixtureRoot := admodel.InternalObjectGUIDIdentity(*rootResult.Object.TargetGUID)

	// Non-ASCII plus a supplementary-plane character, so the value is not
	// merely carried but carried byte-exactly through a create.
	const plain = "sdk-create-alpha"
	const exotic = "sdk-create-é\U0001f511"
	const typedValue = "sdk-create-typed-é\U0001f511"

	remove := func(result admodel.ObjectMutationResult) {
		if result.TargetGUID == nil {
			return
		}
		id := admodel.InternalObjectGUIDIdentity(*result.TargetGUID)
		_, _ = adservice_organizational_units.New(client).
			SetOrganizationalUnitProtection(ctx, id, false, admodel.ObjectMutationOptions{})
		if _, err := client.DeleteObject(
			ctx,
			admodel.DeleteObjectRequest{Identity: id, Recursive: true},
		); err != nil {
			t.Errorf("a fixture object was not removed: %v", err)
		}
	}

	stage = "create-attributes-sweep"
	for index, target := range InternalLifecycleTargets() {
		o := InternalCreateAttributesObservation{
			Cmdlet: target.InternalCreateCmdlet,
			Class:  target.InternalClass,
		}
		var counts InternalSearchNativeCounts
		(*adengine.InternalClientSessionPointer(client)).(*adengine.InternalLdapSession).InternalApi = InternalCountedSearchAPI(
			&counts,
		)
		name := func(suffix string) string {
			if target.InternalKind == "computer" {
				return "SDKCA" + strconv.Itoa(index) + suffix
			}
			return fmt.Sprintf("sdkca%d%s", index, suffix)
		}
		observe := admodel.ObjectMutationOptions{
			Properties: []string{InternalLifecycleMultiValued, "description"},
		}

		// --- attribute-update-intent, the create half --------------------
		//
		// The refusal is attempted first, so the successful create that
		// follows is itself the proof that nothing was written: had the
		// refused create written, this one would be a duplicate.
		undefinedName := name("u")
		_, undefinedErr := target.InternalCreateWithAttributes(
			ctx,
			client,
			fixtureRoot,
			undefinedName,
			map[string][]admodel.RawValue{
				InternalLifecycleUndefined:   {admodel.NewRawValue([]byte("x"))},
				InternalLifecycleMultiValued: {admodel.NewRawValue([]byte("must-not-land"))},
			},
			observe,
		)
		o.UndefinedRefused = undefinedErr != nil
		o.UndefinedClass = InternalLifecycleClass(undefinedErr)
		o.UndefinedDetail = InternalLifecycleDetail(undefinedErr)
		recreated, recreateErr := target.InternalCreateWithAttributes(
			ctx,
			client,
			fixtureRoot,
			undefinedName,
			map[string][]admodel.RawValue{
				InternalLifecycleMultiValued: {admodel.NewRawValue([]byte(plain))},
			},
			observe,
		)
		o.UndefinedNoWrite = recreateErr == nil
		remove(recreated)

		rawResult, rawErr := target.InternalCreateWithAttributes(
			ctx,
			client,
			fixtureRoot,
			name("r"),
			map[string][]admodel.RawValue{
				InternalLifecycleMultiValued: {
					admodel.NewRawValue([]byte(plain)),
					admodel.NewRawValue([]byte(exotic)),
				},
			},
			observe,
		)
		o.RawVerified = rawErr == nil && rawResult.Verified
		o.RawDetail = InternalLifecycleDetail(rawErr)
		if rawResult.TargetGUID != nil {
			values, state, _ := InternalLifecycleValues(
				ctx,
				client,
				admodel.InternalObjectGUIDIdentity(*rawResult.TargetGUID),
				InternalLifecycleMultiValued,
			)
			want := []string{plain, exotic}
			slices.Sort(want)
			o.RawMultiValued = state == admodel.AttributePresent && slices.Equal(values, want)
			o.RawNonASCIIKept = slices.Contains(values, exotic)
		}
		remove(rawResult)

		// --- instance-update-semantics, the create half ------------------
		typedCreate := target.InternalCreateWithProperties
		if typedCreate == nil {
			// No typed property layer, so there is no typed instance to
			// exercise and nothing for a typed validation to refuse. An
			// earlier version of this harness built a shim that put the value
			// in the raw attribute map and then demanded typed validation from
			// it — but RawValue is raw bytes by contract, so the NUL passed
			// straight through, correctly. The scenario is not claimed for
			// this operation rather than claimed on an invented observation.
			o.TypedMechanism = "none; this path has no typed property layer, and its " +
				"explicit attribute map is covered by the raw half above"
			o.TypedNotApplicable = "the generic object path exposes no typed properties, so " +
				"instance-update-semantics is not claimed for it at create time"
			o.Allocations = InternalSweepAllocations(counts)
			o.Passed = o.InternalQualifies()
			if !o.Passed {
				fail("%s: create-time observation incomplete: %+v", target.InternalCreateCmdlet, o)
			}
			artifact.Operations = append(artifact.Operations, o)
			continue
		}
		o.TypedMechanism = "a typed property set on the create request"

		invalidName := name("i")
		_, invalidErr := typedCreate(ctx, client, fixtureRoot, invalidName,
			typedValue+string(rune(0)), observe)
		o.InvalidRefused = invalidErr != nil
		o.InvalidClass = InternalLifecycleClass(invalidErr)
		o.InvalidDetail = InternalLifecycleDetail(invalidErr)
		recreated, recreateErr = typedCreate(
			ctx,
			client,
			fixtureRoot,
			invalidName,
			typedValue,
			observe,
		)
		o.InvalidNoWrite = recreateErr == nil
		remove(recreated)

		typedResult, typedErr := typedCreate(
			ctx,
			client,
			fixtureRoot,
			name("t"),
			typedValue,
			observe,
		)
		o.TypedVerified = typedErr == nil && typedResult.Verified
		o.TypedDetail = InternalLifecycleDetail(typedErr)
		if typedResult.TargetGUID != nil {
			id := admodel.InternalObjectGUIDIdentity(*typedResult.TargetGUID)
			values, state, _ := InternalLifecycleValues(ctx, client, id, "description")
			o.TypedApplied = state == admodel.AttributePresent &&
				slices.Contains(values, typedValue)
			// Only what was asked for: the attribute the raw half uses was
			// never mentioned on this request and must be absent.
			_, other, _ := InternalLifecycleValues(ctx, client, id, InternalLifecycleMultiValued)
			o.TypedOnlyAsked = other == admodel.AttributeAbsent
		}
		remove(typedResult)

		o.Allocations = InternalSweepAllocations(counts)
		o.Passed = o.InternalQualifies()
		if !o.Passed {
			fail("%s: create-time observation incomplete: %+v", target.InternalCreateCmdlet, o)
		}
		artifact.Operations = append(artifact.Operations, o)
	}

	if !t.Failed() {
		stage = "complete"
	}
	t.Logf(
		"create-time attribute and instance sweep over %d operations on %s; full ticket qualification remains incomplete",
		len(artifact.Operations),
		endpoint,
	)
}
