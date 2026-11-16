//go:build windows && (amd64 || arm64)

package activedirectory

import (
	"context"
	"encoding/json"
	"fmt"
	"os"
	"runtime"
	"strconv"
	"testing"
	"time"
)

// explicit-go-invocation asks what replaces the shell's preview, confirmation
// and pass-through conventions. For a read the answer is that the read itself
// mutates nothing. For a write there is no preview at all, and the guarantee
// that stands in for one is stronger and easier to check: a request is
// validated and its target resolved before anything is submitted, so an
// invalid call writes nothing.
//
// That is the property a caller applying a bad configuration depends on. A
// half-applied change is worse than a refused one.
//
// It reuses lifecycleTargets() rather than declaring its own table, so the
// mutating harnesses cannot drift apart on which operation does what.

// writeRefusal is one invalid request and what happened to it. Each names the
// shape rather than the sentinel, because the point is that the shape is
// refused, and recording the class separately keeps "refused" from standing in
// for "refused for the right reason".
type writeRefusal struct {
	Shape    string `json:"shape"`
	Refused  bool   `json:"refused"`
	Class    string `json:"error_class"`
	NoWrite  bool   `json:"wrote_nothing"`
	Detail   string `json:"detail,omitempty"`
	Resolved string `json:"not_applicable_reason,omitempty"`
}

// acceptable requires a refusal whose remedy is in the request, or one the
// directory cannot perform. Never a denial, a conflict or an uncertain
// outcome: each of those would mean the call had reached the directory and
// tried, which is the opposite of what this scenario establishes.
func (r writeRefusal) acceptable() bool {
	if r.Resolved != "" {
		return true
	}
	return r.Refused && r.NoWrite &&
		(r.Class == ClassInvalidRequest.String() || r.Class == ClassUnsupported.String())
}

type writeInvocationObservation struct {
	Cmdlet string            `json:"cmdlet"`
	Role   writeEndpointRole `json:"role"`

	// Mechanism names the Go surface that replaces the shell convention, so
	// the artifact says what was observed rather than implying a -WhatIf this
	// SDK does not have.
	Mechanism string `json:"go_mechanism"`

	// Refusals are the invalid shapes. Every one must be refused before
	// anything is submitted.
	Refusals []writeRefusal `json:"refusals"`

	// The pass-through half: the documented typed result carried the object
	// and its observed write state without a separate flag being asked for.
	TypedResult       bool   `json:"typed_result_without_passthru"`
	TypedResultDetail string `json:"typed_result_detail,omitempty"`

	// PromptInvoked is nil throughout: this SDK exposes no prompt or
	// confirmation hook, so there is nothing a call could have invoked. It is
	// recorded as absent rather than as false, because "no hook exists" and
	// "the hook was not called" are different observations.
	PromptInvoked *bool `json:"prompt_invoked"`

	Allocations int    `json:"native_allocations_remaining"`
	Detail      string `json:"detail,omitempty"`
	Passed      bool   `json:"passed"`
}

func (o writeInvocationObservation) qualifies() bool {
	if len(o.Refusals) == 0 {
		return false
	}
	for _, refusal := range o.Refusals {
		if !refusal.acceptable() {
			return false
		}
	}
	return o.TypedResult && o.PromptInvoked == nil && o.Allocations == 0
}

// malformedPartition is not a distinguished name, so every operation must
// refuse it while parsing its options, before resolving anything.
const malformedPartition = "this is not a naming context"

// The outer harness supplies the endpoint and the write authorization only
// inside an owned run. This test mutates the directory: it creates one
// organizational unit of fixtures and removes it. Ordinary go test invocations
// skip it.
//
// It qualifies explicit-go-invocation across the sixteen mutating operations a
// caller would use to manage the five resource classes.
func TestDirectoryWriteInvocationSweepLab(t *testing.T) {
	endpoint := os.Getenv("ADSDK_INVOKE_ENDPOINT")
	if endpoint == "" {
		t.Skip("requires the opt-in isolated directory write-invocation harness")
	}
	if os.Getenv("ADSDK_INVOKE_ALLOW_WRITES") != "yes" {
		t.Fatal("this harness mutates the directory and requires explicit write authorization")
	}
	resultPath := os.Getenv("ADSDK_INVOKE_RESULT")
	runID := os.Getenv("ADSDK_INVOKE_RUN_ID")
	if resultPath == "" || runID == "" {
		t.Fatal("an endpoint, a run identity and a fresh result path are required")
	}

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
		PreviewMechanism    string                       `json:"preview_mechanism"`
		FixtureRoot         string                       `json:"fixture_root"`
		FixtureRootRemoved  bool                         `json:"fixture_root_removed"`
		Operations          []writeInvocationObservation `json:"operations"`
	}{
		SchemaVersion: 1, Scope: "directory-write-explicit-go-invocation", RunID: runID,
		Endpoint: endpoint, RuntimeOS: runtime.GOOS, RuntimeArchitecture: runtime.GOARCH,
		Started: time.Now().UTC(),
		PreviewMechanism: "none; this SDK offers no preview or confirmation call. The " +
			"guarantee that replaces one is that a request is validated and its target " +
			"resolved before anything is submitted, so an invalid call writes nothing.",
		Operations: []writeInvocationObservation{},
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
			t.Error("cannot encode write-invocation artifact")
			return
		}
		file, err := os.OpenFile(resultPath, os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0600)
		if err != nil {
			t.Error("cannot create fresh write-invocation artifact")
			return
		}
		_, writeErr := file.Write(append(data, '\n'))
		if closeErr := file.Close(); writeErr != nil || closeErr != nil {
			t.Error("cannot finish write-invocation artifact")
		}
	}()

	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Minute)
	defer cancel()

	client, err := Dial(ctx, Config{Endpoint: Endpoint{Host: endpoint, Port: 389}, Timeout: 60 * time.Second})
	if err != nil {
		t.Fatal("native dial failed")
	}
	defer func() {
		if closeErr := client.Close(); closeErr != nil {
			t.Error("the client did not close cleanly")
		}
	}()

	stage = "default-naming-context"
	root, err := client.RootDSE(ctx, RootDSEOptions{})
	if err != nil || root.DefaultNamingContext == nil || *root.DefaultNamingContext == "" {
		t.Fatal("the connection did not report a default naming context")
	}
	domain := *root.DefaultNamingContext

	stage = "fixture-root"
	domainIdentity, err := IdentityByDN(domain)
	if err != nil {
		t.Fatal("the default naming context is not a usable identity")
	}
	// An organizational unit, not a container: an organizationalUnit cannot be
	// created inside a container, which the directory refuses with LDAP 64.
	// Cleanup is installed from whatever the create reported, before deciding
	// whether it succeeded, so a create that writes and then fails cannot leak.
	rootResult, rootErr := client.CreateOrganizationalUnit(ctx, CreateOrganizationalUnitRequest{
		Parent: domainIdentity, Name: "sdk-writeinvoke-" + runID,
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
	fixtureVersion := ObjectVersion{GUID: *rootResult.Object.TargetGUID, USNChanged: 1}

	stage = "write-invocation-sweep"
	for index, target := range lifecycleTargets() {
		var counts searchNativeCounts
		client.session.(*ldapSession).api = countedSearchAPI(&counts)
		name := fmt.Sprintf("sdkwi%d", index)
		if target.kind == "computer" {
			name = "SDKWI" + strconv.Itoa(index)
		}
		observe := ObjectMutationOptions{Properties: []string{lifecycleMultiValued}}

		// --- create ------------------------------------------------------
		create := writeInvocationObservation{
			Cmdlet: target.createCmdlet, Role: writeRoleCreate,
			Mechanism: "an explicit request value; validation and parent resolution precede any submission",
		}
		// A zero Parent is deliberately not among these shapes. It is a
		// documented default — it selects Config.Partition or the endpoint's
		// default naming context — so it is a valid request, not an invalid
		// one. An earlier version of this harness treated it as invalid, and
		// the creates duly succeeded into the default containers, outside the
		// fixture root and therefore outside its cleanup.
		for _, shape := range []struct {
			name string
			call func() (ObjectMutationResult, error)
		}{
			{"an empty name", func() (ObjectMutationResult, error) {
				return target.create(ctx, client, fixtureRoot, "", observe)
			}},
			// A NUL, not merely a control character: validDirectoryText rejects
			// invalid UTF-8 and NUL and nothing else, so a control character is
			// legitimately accepted. An earlier version of this harness used
			//  and four of the five creates duly succeeded.
			{"a name carrying a NUL", func() (ObjectMutationResult, error) {
				return target.create(ctx, client, fixtureRoot, name+string(rune(0)), observe)
			}},
			{"a malformed partition", func() (ObjectMutationResult, error) {
				return target.create(ctx, client, fixtureRoot, name,
					ObjectMutationOptions{Partition: malformedPartition})
			}},
			{"an expected version, which no create can guard", func() (ObjectMutationResult, error) {
				return target.create(ctx, client, fixtureRoot, name,
					ObjectMutationOptions{ExpectedVersion: &fixtureVersion})
			}},
		} {
			_, err := shape.call()
			create.Refusals = append(create.Refusals, writeRefusal{
				Shape: shape.name, Refused: err != nil, Class: lifecycleClass(err),
				Detail: lifecycleDetail(err),
			})
		}

		// None of the refused creates wrote anything, proved by this one
		// succeeding: had any of them written, this create would have been
		// refused as a duplicate. Constructing the object's distinguished name
		// to look for it directly would be wrong — an organizational unit's
		// relative name uses ou= rather than cn= — and this proof needs no
		// per-class knowledge at all.
		created, createErr := target.create(ctx, client, fixtureRoot, name, observe)
		for i := range create.Refusals {
			create.Refusals[i].NoWrite = createErr == nil
		}
		create.TypedResult = createErr == nil && created.TargetGUID != nil &&
			created.After != nil && created.TargetDN != "" && created.State == ObjectWriteAccepted
		create.TypedResultDetail = lifecycleDetail(createErr)
		create.Allocations = sweepAllocations(counts)
		create.Passed = create.qualifies()
		if !create.Passed {
			fail("%s: invocation observation incomplete: %+v", target.createCmdlet, create)
		}
		artifact.Operations = append(artifact.Operations, create)
		if created.TargetGUID == nil {
			continue
		}
		subject := objectGUIDIdentity(*created.TargetGUID)

		unchanged := func() func() bool {
			before, readable := writeEndpointUSN(ctx, client, subject)
			return func() bool {
				after, stillThere := writeEndpointUSN(ctx, client, subject)
				return readable && stillThere && after == before
			}
		}

		// --- update ------------------------------------------------------
		counts = searchNativeCounts{}
		update := writeInvocationObservation{
			Cmdlet: target.updateCmdlet, Role: writeRoleUpdate,
			Mechanism: "explicit AttributeChange values; conflicting or empty intent is refused before submission",
		}
		valid := []AttributeChange{{Attribute: lifecycleMultiValued, Kind: AttributeSet,
			Values: lifecycleRawValues("invocation")}}
		for _, shape := range []struct {
			name    string
			changes []AttributeChange
			options ObjectMutationOptions
			id      Identity
		}{
			{"a zero identity", valid, observe, Identity{}},
			{"no changes at all", nil, observe, subject},
			{"overlapping add and remove of one value", []AttributeChange{
				{Attribute: lifecycleMultiValued, Kind: AttributeAddValues, Values: lifecycleRawValues("same")},
				{Attribute: lifecycleMultiValued, Kind: AttributeRemoveValues, Values: lifecycleRawValues("same")},
			}, observe, subject},
			{"a malformed partition", valid, ObjectMutationOptions{Partition: malformedPartition}, subject},
		} {
			witness := unchanged()
			_, err := target.updateRaw(ctx, client, shape.id, shape.changes, shape.options)
			update.Refusals = append(update.Refusals, writeRefusal{
				Shape: shape.name, Refused: err != nil, Class: lifecycleClass(err),
				Detail: lifecycleDetail(err), NoWrite: witness(),
			})
		}
		updated, updateErr := target.updateRaw(ctx, client, subject, valid, observe)
		update.TypedResult = updateErr == nil && updated.After != nil &&
			updated.State == ObjectWriteAccepted && updated.Verified
		update.TypedResultDetail = lifecycleDetail(updateErr)
		update.Allocations = sweepAllocations(counts)
		update.Passed = update.qualifies()
		if !update.Passed {
			fail("%s: invocation observation incomplete: %+v", target.updateCmdlet, update)
		}
		artifact.Operations = append(artifact.Operations, update)

		// --- rename, for the one operation that has it -------------------
		if target.kind == "object" {
			counts = searchNativeCounts{}
			rename := writeInvocationObservation{
				Cmdlet: "Rename-ADObject", Role: writeRoleRename,
				Mechanism: "an explicit literal relative name; it is never a distinguished-name fragment",
			}
			for _, shape := range []struct {
				name    string
				request RenameObjectRequest
			}{
				{"a zero identity", RenameObjectRequest{Name: name + "-r", Options: observe}},
				{"an empty name", RenameObjectRequest{Identity: subject, Options: observe}},
				{"a malformed partition", RenameObjectRequest{Identity: subject, Name: name + "-r",
					Options: ObjectMutationOptions{Partition: malformedPartition}}},
			} {
				witness := unchanged()
				_, err := client.RenameObject(ctx, shape.request)
				rename.Refusals = append(rename.Refusals, writeRefusal{
					Shape: shape.name, Refused: err != nil, Class: lifecycleClass(err),
					Detail: lifecycleDetail(err), NoWrite: witness(),
				})
			}
			renamed, renameErr := client.RenameObject(ctx, RenameObjectRequest{
				Identity: subject, Name: name + "-renamed", Options: observe})
			rename.TypedResult = renameErr == nil && renamed.After != nil &&
				renamed.State == ObjectWriteAccepted && renamed.Verified
			rename.TypedResultDetail = lifecycleDetail(renameErr)
			rename.Allocations = sweepAllocations(counts)
			rename.Passed = rename.qualifies()
			if !rename.Passed {
				fail("Rename-ADObject: invocation observation incomplete: %+v", rename)
			}
			artifact.Operations = append(artifact.Operations, rename)
		}

		// --- delete ------------------------------------------------------
		counts = searchNativeCounts{}
		remove := writeInvocationObservation{
			Cmdlet: target.removeCmdlet, Role: writeRoleDelete,
			Mechanism: "an explicit identity and an explicit recursive intent; a non-leaf is never removed by default",
		}
		if target.protectedByDefault && target.unprotect != nil {
			if err := target.unprotect(ctx, client, subject, ObjectMutationOptions{}); err != nil {
				remove.Detail = "unprotect: " + err.Error()
			}
		}
		for _, shape := range []struct {
			name    string
			id      Identity
			options ObjectMutationOptions
		}{
			{"a zero identity", Identity{}, observe},
			{"a malformed partition", subject, ObjectMutationOptions{Partition: malformedPartition}},
		} {
			witness := unchanged()
			_, err := target.remove(ctx, client, shape.id, false, shape.options)
			remove.Refusals = append(remove.Refusals, writeRefusal{
				Shape: shape.name, Refused: err != nil, Class: lifecycleClass(err),
				Detail: lifecycleDetail(err), NoWrite: witness(),
			})
		}
		deleted, deleteErr := target.remove(ctx, client, subject, false, ObjectMutationOptions{})
		remove.TypedResult = deleteErr == nil && deleted.AbsentAfter &&
			deleted.State == ObjectWriteAccepted && deleted.Verified
		remove.TypedResultDetail = lifecycleDetail(deleteErr)
		remove.Allocations = sweepAllocations(counts)
		remove.Passed = remove.qualifies()
		if !remove.Passed {
			fail("%s: invocation observation incomplete: %+v", target.removeCmdlet, remove)
		}
		artifact.Operations = append(artifact.Operations, remove)
	}

	if !t.Failed() {
		stage = "complete"
	}
	t.Logf("write invocation sweep over %d operations on %s; full ticket qualification remains incomplete",
		len(artifact.Operations), endpoint)
}
