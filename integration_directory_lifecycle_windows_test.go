//go:build windows && (amd64 || arm64)

package activedirectory

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"runtime"
	"slices"
	"strconv"
	"strings"
	"testing"
	"time"
)

// This harness is the mutating counterpart to the read-side sweeps. It takes
// each object class a caller would model as a resource through a full
// create/update/delete cycle against a real directory, and records both halves
// of every lifecycle scenario the coverage contract asks for.
//
// It writes. Every fixture it creates lives under one organizational unit it
// also creates, and the run is not recorded as passing unless that unit and
// everything beneath it is gone at the end — absence proved by a read, not
// assumed from a delete returning no error.

// lifecycleAttribute names the attributes the update scenarios use. They are
// chosen for properties that hold on every class under test rather than for
// convenience, so one table drives all five kinds:
//
//   - description is multi-valued in the AD schema and defined on top, so every
//     object has it and add/remove/clear are all observable on it. PowerShell
//     presents it as single-valued, which is a reason to exercise it here
//     rather than to avoid it.
//   - displayName is single-valued and also on top, so a typed property update
//     has somewhere to land that the raw changes are not touching.
//   - undefined is syntactically valid and not in the schema, so the server
//     refuses it for a schema reason on every class. A per-class attribute
//     would make the failure half mean something different for each kind.
const (
	lifecycleMultiValued = "description"
	lifecycleSingle      = "displayName"
	lifecycleUndefined   = "sdkNoSuchAttributeForQualification"
)

// lifecycleTarget is one object class and the typed entry points that create,
// change and remove it. The closures exist because every class has its own
// request type; the scenarios they evidence are identical, which is the whole
// reason to drive them from one table.
type lifecycleTarget struct {
	kind string
	// The coverage operations whose scenarios these observations evidence.
	createCmdlet, updateCmdlet, removeCmdlet string
	// class is the schema class the create must actually produce. A create that
	// succeeds but produces another class is a failure, not a pass.
	class string
	// container is true for classes that may hold children, which is what makes
	// the non-leaf and recursive delete boundaries observable at all.
	container bool
	// protectedByDefault records classes this SDK protects on creation without
	// being asked. Their first delete attempt must be refused, and that refusal
	// is the deletion scenario's failure half rather than an obstacle.
	protectedByDefault bool

	create      func(context.Context, *Client, Identity, string, ObjectMutationOptions) (ObjectMutationResult, error)
	updateRaw   func(context.Context, *Client, Identity, []AttributeChange, ObjectMutationOptions) (ObjectMutationResult, error)
	updateTyped func(context.Context, *Client, Identity, string, ObjectMutationOptions) (ObjectMutationResult, error)
	unprotect   func(context.Context, *Client, Identity, ObjectMutationOptions) error
	remove      func(context.Context, *Client, Identity, bool, ObjectMutationOptions) (ObjectMutationResult, error)
}

func lifecycleTargets() []lifecycleTarget {
	text := func(value string) *string { return &value }
	return []lifecycleTarget{
		{
			kind: "user", class: "user",
			createCmdlet: "New-ADUser", updateCmdlet: "Set-ADUser", removeCmdlet: "Remove-ADUser",
			create: func(ctx context.Context, c *Client, parent Identity, name string, o ObjectMutationOptions) (ObjectMutationResult, error) {
				result, err := c.CreateUser(ctx, CreateUserRequest{Parent: parent, Name: name, Options: o})
				return result.Creation, err
			},
			updateRaw: func(ctx context.Context, c *Client, id Identity, changes []AttributeChange, o ObjectMutationOptions) (ObjectMutationResult, error) {
				result, err := c.UpdateUser(ctx, UpdateUserRequest{Identity: id, Changes: changes, Options: o})
				return result.Mutation, err
			},
			updateTyped: func(ctx context.Context, c *Client, id Identity, value string, o ObjectMutationOptions) (ObjectMutationResult, error) {
				result, err := c.UpdateUser(ctx, UpdateUserRequest{
					Identity: id, Properties: UserProperties{DisplayName: text(value)}, Options: o})
				return result.Mutation, err
			},
			remove: func(ctx context.Context, c *Client, id Identity, _ bool, o ObjectMutationOptions) (ObjectMutationResult, error) {
				result, err := c.DeleteUser(ctx, DeleteUserRequest{Identity: id, Options: o})
				return result.Mutation, err
			},
		},
		{
			kind: "group", class: "group",
			createCmdlet: "New-ADGroup", updateCmdlet: "Set-ADGroup", removeCmdlet: "Remove-ADGroup",
			create: func(ctx context.Context, c *Client, parent Identity, name string, o ObjectMutationOptions) (ObjectMutationResult, error) {
				result, err := c.CreateGroup(ctx, CreateGroupRequest{
					Parent: parent, Name: name, Category: GroupSecurity, Scope: GroupGlobal, Options: o})
				return result.Mutation, err
			},
			updateRaw: func(ctx context.Context, c *Client, id Identity, changes []AttributeChange, o ObjectMutationOptions) (ObjectMutationResult, error) {
				result, err := c.UpdateGroup(ctx, UpdateGroupRequest{Identity: id, Changes: changes, Options: o})
				return result.Mutation, err
			},
			updateTyped: func(ctx context.Context, c *Client, id Identity, value string, o ObjectMutationOptions) (ObjectMutationResult, error) {
				result, err := c.UpdateGroup(ctx, UpdateGroupRequest{Identity: id, DisplayName: text(value), Options: o})
				return result.Mutation, err
			},
			remove: func(ctx context.Context, c *Client, id Identity, _ bool, o ObjectMutationOptions) (ObjectMutationResult, error) {
				result, err := c.DeleteGroup(ctx, DeleteGroupRequest{Identity: id, Options: o})
				return result.Mutation, err
			},
		},
		{
			kind: "computer", class: "computer",
			createCmdlet: "New-ADComputer", updateCmdlet: "Set-ADComputer", removeCmdlet: "Remove-ADComputer",
			create: func(ctx context.Context, c *Client, parent Identity, name string, o ObjectMutationOptions) (ObjectMutationResult, error) {
				result, err := c.CreateComputer(ctx, CreateComputerRequest{Parent: parent, Name: name, Options: o})
				return result.Creation, err
			},
			updateRaw: func(ctx context.Context, c *Client, id Identity, changes []AttributeChange, o ObjectMutationOptions) (ObjectMutationResult, error) {
				result, err := c.UpdateComputer(ctx, UpdateComputerRequest{Identity: id, Changes: changes, Options: o})
				return result.Mutation, err
			},
			updateTyped: func(ctx context.Context, c *Client, id Identity, value string, o ObjectMutationOptions) (ObjectMutationResult, error) {
				result, err := c.UpdateComputer(ctx, UpdateComputerRequest{
					Identity: id, Properties: ComputerProperties{DisplayName: text(value)}, Options: o})
				return result.Mutation, err
			},
			remove: func(ctx context.Context, c *Client, id Identity, recursive bool, o ObjectMutationOptions) (ObjectMutationResult, error) {
				result, err := c.DeleteComputer(ctx, DeleteComputerRequest{Identity: id, Recursive: recursive, Options: o})
				return result.Mutation, err
			},
		},
		{
			kind: "organizational unit", class: "organizationalUnit",
			createCmdlet: "New-ADOrganizationalUnit", updateCmdlet: "Set-ADOrganizationalUnit",
			removeCmdlet: "Remove-ADOrganizationalUnit",
			container:    true, protectedByDefault: true,
			create: func(ctx context.Context, c *Client, parent Identity, name string, o ObjectMutationOptions) (ObjectMutationResult, error) {
				result, err := c.CreateOrganizationalUnit(ctx, CreateOrganizationalUnitRequest{
					Parent: parent, Name: name, Options: o})
				return result.Object, err
			},
			updateRaw: func(ctx context.Context, c *Client, id Identity, changes []AttributeChange, o ObjectMutationOptions) (ObjectMutationResult, error) {
				result, err := c.UpdateOrganizationalUnit(ctx, UpdateOrganizationalUnitRequest{
					Identity: id, Changes: changes, Options: o})
				return result.Object, err
			},
			updateTyped: func(ctx context.Context, c *Client, id Identity, value string, o ObjectMutationOptions) (ObjectMutationResult, error) {
				result, err := c.UpdateOrganizationalUnit(ctx, UpdateOrganizationalUnitRequest{
					Identity: id, Properties: OUProperties{DisplayName: text(value)}, Options: o})
				return result.Object, err
			},
			unprotect: func(ctx context.Context, c *Client, id Identity, o ObjectMutationOptions) error {
				_, err := c.SetOrganizationalUnitProtection(ctx, id, false, o)
				return err
			},
			remove: func(ctx context.Context, c *Client, id Identity, recursive bool, o ObjectMutationOptions) (ObjectMutationResult, error) {
				return c.DeleteOrganizationalUnit(ctx, DeleteOrganizationalUnitRequest{
					Identity: id, Recursive: recursive, Options: o})
			},
		},
		{
			// The generic path carries the class explicitly, which is what makes
			// schema-class-and-container observable: a container holds children,
			// so the delete boundaries apply to it as they do to the unit.
			kind: "object", class: "container",
			createCmdlet: "New-ADObject", updateCmdlet: "Set-ADObject", removeCmdlet: "Remove-ADObject",
			container: true,
			create: func(ctx context.Context, c *Client, parent Identity, name string, o ObjectMutationOptions) (ObjectMutationResult, error) {
				return c.CreateObject(ctx, CreateObjectRequest{
					Parent: parent, Class: "container", Name: name, Options: o})
			},
			updateRaw: func(ctx context.Context, c *Client, id Identity, changes []AttributeChange, o ObjectMutationOptions) (ObjectMutationResult, error) {
				return c.UpdateObject(ctx, UpdateObjectRequest{Identity: id, Changes: changes, Options: o})
			},
			updateTyped: func(ctx context.Context, c *Client, id Identity, value string, o ObjectMutationOptions) (ObjectMutationResult, error) {
				// The generic path has no typed property layer, so the typed
				// scenario's subject here is an explicit single-valued Set,
				// which is the documented Go replacement for -Instance.
				return c.UpdateObject(ctx, UpdateObjectRequest{Identity: id, Changes: []AttributeChange{{
					Attribute: lifecycleSingle, Kind: AttributeSet,
					Values: []RawValue{NewRawValue([]byte(value))},
				}}, Options: o})
			},
			remove: func(ctx context.Context, c *Client, id Identity, recursive bool, o ObjectMutationOptions) (ObjectMutationResult, error) {
				return c.DeleteObject(ctx, DeleteObjectRequest{Identity: id, Recursive: recursive, Options: o})
			},
		},
	}
}

// lifecycleObservation is one class's complete record. Each field names a half
// of a scenario rather than a step of the harness, so an artifact reader can
// see which half of which scenario an incomplete run is missing.
type lifecycleObservation struct {
	Kind  string `json:"kind"`
	Class string `json:"class"`

	// creation-defaults-and-readback
	CreatedVerified    bool   `json:"created_verified"`
	CreatedClass       string `json:"created_class"`
	CreatedInContainer bool   `json:"created_in_requested_container"`
	CreatedIdentity    string `json:"created_identity"`
	DuplicateRefused   bool   `json:"duplicate_name_refused"`
	DuplicateClass     string `json:"duplicate_name_error_class"`
	DuplicateWroteOnce bool   `json:"duplicate_left_one_object"`

	// attribute-update-intent
	SetApplied    bool `json:"set_applied"`
	AddApplied    bool `json:"add_applied"`
	RemoveApplied bool `json:"remove_applied"`
	// A Clear is accepted but never verified by this SDK: an absent
	// attribute cannot prove emptiness, because omission can equally mean
	// denied visibility. So the two halves are recorded separately — the
	// write was accepted, and a separate read found the attribute absent —
	// along with the class the unverified outcome reports as.
	ClearAccepted          bool   `json:"clear_accepted"`
	ClearReadsAbsent       bool   `json:"clear_reads_absent"`
	ClearClass             string `json:"clear_outcome_class"`
	UnrelatedValueSurvived bool   `json:"unrelated_value_survived"`
	UndefinedRefused       bool   `json:"undefined_attribute_refused"`
	UndefinedClass         string `json:"undefined_attribute_error_class"`
	UndefinedWroteNothing  bool   `json:"undefined_attribute_wrote_nothing"`

	// instance-update-semantics
	TypedApplied       bool   `json:"typed_update_applied"`
	OmittedUntouched   bool   `json:"omitted_attribute_untouched"`
	StaleVersion       string `json:"stale_version_outcome"`
	StaleVersionClass  string `json:"stale_version_error_class"`
	StaleWroteNothing  bool   `json:"stale_version_wrote_nothing"`
	ConcurrentSurvived bool   `json:"concurrent_unrelated_change_survived"`

	// object-deletion-and-reference-constraints
	DeletedAbsentAfter bool   `json:"deleted_absent_after"`
	DeleteVerified     bool   `json:"delete_verified"`
	SecondDeleteClass  string `json:"second_delete_error_class"`
	ProtectedRefused   string `json:"protected_delete_outcome,omitempty"`

	// recursive-delete-boundary; container classes only
	NonLeafRefused    bool   `json:"non_leaf_delete_refused,omitempty"`
	NonLeafClass      string `json:"non_leaf_error_class,omitempty"`
	NonLeafChildKept  bool   `json:"non_leaf_refusal_kept_the_child,omitempty"`
	RecursiveRemoved  bool   `json:"recursive_delete_removed_children,omitempty"`
	RecursiveVerified bool   `json:"recursive_delete_absent_after,omitempty"`

	AllocationsRemaining int    `json:"allocations_remaining"`
	Detail               string `json:"detail,omitempty"`
	Passed               bool   `json:"passed"`
}

// qualifies requires both halves of every scenario this class participates in.
// The container-only fields are required exactly when the class is a container,
// so a leaf is never credited with a boundary it cannot reach and a container is
// never excused from one it can.
func (o lifecycleObservation) qualifies(target lifecycleTarget) bool {
	creation := o.CreatedVerified && o.CreatedClass == target.class && o.CreatedInContainer &&
		o.CreatedIdentity != "" && o.DuplicateRefused &&
		o.DuplicateClass == ClassAlreadyExists.String() && o.DuplicateWroteOnce
	// The clear requirement is the documented behaviour rather than the
	// intuitive one: accepted, read back absent, and reported as uncertain
	// because this SDK will not claim to have verified an omission.
	attribute := o.SetApplied && o.AddApplied && o.RemoveApplied &&
		o.ClearAccepted && o.ClearReadsAbsent && o.ClearClass == ClassUncertain.String() &&
		o.UnrelatedValueSurvived && o.UndefinedRefused && o.UndefinedWroteNothing &&
		(o.UndefinedClass == ClassInvalidRequest.String() || o.UndefinedClass == ClassUnsupported.String())
	// A stale precondition must either be refused as a conflict or be refused
	// as unsupported by this server. Both are honest; silently applying the
	// write is not, and neither is reporting success.
	instance := o.TypedApplied && o.OmittedUntouched && o.ConcurrentSurvived && o.StaleWroteNothing &&
		(o.StaleVersionClass == ClassConflict.String() || o.StaleVersionClass == ClassUnsupported.String())
	deletion := o.DeletedAbsentAfter && o.DeleteVerified &&
		o.SecondDeleteClass == ClassNotFound.String()
	if target.protectedByDefault && o.ProtectedRefused != "refused" {
		deletion = false
	}
	boundary := true
	if target.container {
		boundary = o.NonLeafRefused && o.NonLeafChildKept &&
			(o.NonLeafClass == ClassInvalidRequest.String() || o.NonLeafClass == ClassConflict.String()) &&
			o.RecursiveRemoved && o.RecursiveVerified
	}
	return creation && attribute && instance && deletion && boundary &&
		o.AllocationsRemaining == 0
}

// lifecycleClass reports the error class by name, so the artifact records which
// classification the directory produced rather than only that it refused. A
// refusal for the wrong reason is a different observation and must not pass.
func lifecycleClass(err error) string {
	if err == nil {
		return ""
	}
	return Classify(err).String()
}

// lifecycleValues reads one attribute's current values as text. It distinguishes
// absent from unloaded, because "the attribute is not there" and "we did not ask
// for it" are the two readings a clear must be able to tell apart.
func lifecycleValues(ctx context.Context, c *Client, id Identity, attribute string) ([]string, AttributeState, error) {
	observed, err := c.ResolveIdentity(ctx, id, ResolveIdentityOptions{Properties: []string{attribute}})
	if err != nil {
		return nil, AttributeUnloaded, err
	}
	if observed.Object == nil {
		return nil, AttributeUnloaded, ErrDirectoryObjectNotFound
	}
	raw, state := observed.Object.Attribute(attribute)
	values := make([]string, 0, len(raw))
	for _, value := range raw {
		values = append(values, string(value))
	}
	slices.Sort(values)
	return values, state, nil
}

func lifecycleAbsent(ctx context.Context, c *Client, id Identity) bool {
	_, err := c.ResolveIdentity(ctx, id, ResolveIdentityOptions{Properties: []string{"objectGUID"}})
	return IsNotFound(err)
}

func lifecycleRawValues(values ...string) []RawValue {
	raw := make([]RawValue, 0, len(values))
	for _, value := range values {
		raw = append(raw, NewRawValue([]byte(value)))
	}
	return raw
}

// The outer harness supplies the endpoint and the write authorization only
// inside an owned run. This test mutates the directory: it creates an
// organizational unit and fixtures beneath it, and removes them. Ordinary go
// test invocations skip it.
//
// It qualifies creation-defaults-and-readback, attribute-update-intent,
// instance-update-semantics, object-deletion-and-reference-constraints and
// recursive-delete-boundary across the five classes a caller would model as
// resources, recording both halves of each.
func TestDirectoryLifecycleSweepLab(t *testing.T) {
	endpoint := os.Getenv("ADSDK_LIFECYCLE_ENDPOINT")
	if endpoint == "" {
		t.Skip("requires the opt-in isolated directory lifecycle harness")
	}
	if os.Getenv("ADSDK_LIFECYCLE_ALLOW_WRITES") != "yes" {
		t.Fatal("this harness mutates the directory and requires explicit write authorization")
	}
	resultPath := os.Getenv("ADSDK_LIFECYCLE_RESULT")
	runID := os.Getenv("ADSDK_LIFECYCLE_RUN_ID")
	if resultPath == "" || runID == "" {
		t.Fatal("an endpoint, a run identity and a fresh result path are required")
	}

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
		FixtureRoot         string                 `json:"fixture_root"`
		FixtureRootRemoved  bool                   `json:"fixture_root_removed"`
		Operations          []lifecycleObservation `json:"operations"`
	}{
		SchemaVersion: 1, Scope: "directory-mutation-lifecycle", RunID: runID,
		Endpoint: endpoint, RuntimeOS: runtime.GOOS, RuntimeArchitecture: runtime.GOARCH,
		Started: time.Now().UTC(), Operations: []lifecycleObservation{},
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
			t.Error("cannot encode lifecycle artifact")
			return
		}
		file, err := os.OpenFile(resultPath, os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0600)
		if err != nil {
			t.Error("cannot create fresh lifecycle artifact")
			return
		}
		_, writeErr := file.Write(append(data, '\n'))
		if closeErr := file.Close(); writeErr != nil || closeErr != nil {
			t.Error("cannot finish lifecycle artifact")
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

	// One fixture root for the whole run, named after the run so a leftover is
	// attributable. Creating it is also the first proof that a create works at
	// all; if it fails there is nothing to qualify.
	stage = "fixture-root"
	// A plain container, not an organizational unit. The unit's own lifecycle is
	// qualified below like any other class, but using one as the fixture root
	// would put this harness's cleanup behind the protection machinery, and an
	// OU cannot currently be unprotected at all (issue #146). A container has no
	// protection logic, so the root is always removable.
	rootName := "sdk-lifecycle-" + runID
	domainIdentity, err := IdentityByDN(domain)
	if err != nil {
		t.Fatal("the default naming context is not a usable identity")
	}
	rootResult, rootErr := client.CreateObject(ctx, CreateObjectRequest{
		Parent: domainIdentity, Class: "container", Name: rootName})

	// The cleanup is installed from whatever the create reported, before any
	// decision about whether it succeeded. A create that fails after the object
	// was written is exactly the uncertain case, and the first version of this
	// harness called t.Fatalf on it and so never installed cleanup — leaving a
	// fixture root behind, which the collector's independent check caught.
	// Anything with a GUID is removable and must be removed.
	if rootResult.TargetGUID != nil {
		artifact.FixtureRoot = rootResult.TargetDN
		fixtureRoot := objectGUIDIdentity(*rootResult.TargetGUID)
		defer func() {
			removal, removeErr := client.DeleteObject(ctx, DeleteObjectRequest{
				Identity: fixtureRoot, Recursive: true})
			absent := removal.AbsentAfter && lifecycleAbsent(ctx, client, fixtureRoot)
			artifact.FixtureRootRemoved = removeErr == nil && absent
			if !artifact.FixtureRootRemoved {
				t.Errorf("the fixture root was not proved removed: err=%v absentAfter=%v",
					removeErr, removal.AbsentAfter)
			}
		}()
	}
	if rootErr != nil || rootResult.TargetGUID == nil {
		t.Fatalf("cannot create the fixture root: %v", rootErr)
	}
	fixtureRoot := objectGUIDIdentity(*rootResult.TargetGUID)

	stage = "lifecycle-sweep"
	for _, target := range lifecycleTargets() {
		o := lifecycleObservation{Kind: target.kind, Class: target.class}
		var counts searchNativeCounts
		client.session.(*ldapSession).api = countedSearchAPI(&counts)

		// Non-ASCII and a supplementary-plane character, carried over from the
		// identity qualification, so naming is exercised rather than assumed.
		name := "sdk" + strings.ReplaceAll(target.kind, " ", "") + "é\U0001f511"
		// A computer's name becomes a sAMAccountName, which is bounded and
		// must not carry those characters, so that one class uses plain text.
		if target.kind == "computer" {
			name = "SDKLIFE" + strconv.Itoa(len(artifact.Operations))
		}
		observe := ObjectMutationOptions{Properties: []string{lifecycleMultiValued, lifecycleSingle, "objectClass"}}

		// --- creation-defaults-and-readback -----------------------------
		created, createErr := target.create(ctx, client, fixtureRoot, name, observe)
		if createErr != nil || created.TargetGUID == nil {
			o.Detail = fmt.Sprintf("create: %v", createErr)
			o.Passed = false
			fail("%s: create failed, so nothing downstream is observable: %v", target.kind, createErr)
			artifact.Operations = append(artifact.Operations, o)
			continue
		}
		subject := objectGUIDIdentity(*created.TargetGUID)
		o.CreatedVerified = created.Verified && created.ReadbackComplete
		o.CreatedIdentity, _ = func() (string, error) {
			text, err := subject.MarshalText()
			return string(text), err
		}()
		o.CreatedInContainer = strings.HasSuffix(strings.ToLower(created.TargetDN),
			strings.ToLower(","+artifact.FixtureRoot))
		if created.After != nil {
			if classes, state := created.After.Attribute("objectClass"); state == AttributePresent && len(classes) > 0 {
				// The structural class is the last value; the earlier ones are
				// the inherited chain.
				o.CreatedClass = string(classes[len(classes)-1])
			}
		}

		// The same name again, in the same container. Exactly one object must
		// exist afterwards, so the refusal is proved not to have written.
		_, duplicateErr := target.create(ctx, client, fixtureRoot, name, observe)
		o.DuplicateRefused = duplicateErr != nil
		o.DuplicateClass = lifecycleClass(duplicateErr)
		o.DuplicateWroteOnce = !lifecycleAbsent(ctx, client, subject)

		// --- attribute-update-intent ------------------------------------
		// Set two values, add a third, remove one, and clear the rest. An
		// unrelated single-valued attribute is written first and checked at the
		// end, so "unrelated values survive" is observed rather than asserted.
		const unrelated = "sdk-unrelated-value"
		if _, err := target.updateRaw(ctx, client, subject, []AttributeChange{{
			Attribute: lifecycleSingle, Kind: AttributeSet, Values: lifecycleRawValues(unrelated),
		}}, observe); err != nil {
			o.Detail = fmt.Sprintf("seed unrelated: %v", err)
		}

		_, setErr := target.updateRaw(ctx, client, subject, []AttributeChange{{
			Attribute: lifecycleMultiValued, Kind: AttributeSet, Values: lifecycleRawValues("alpha", "beta"),
		}}, observe)
		values, _, _ := lifecycleValues(ctx, client, subject, lifecycleMultiValued)
		o.SetApplied = setErr == nil && slices.Equal(values, []string{"alpha", "beta"})

		_, addErr := target.updateRaw(ctx, client, subject, []AttributeChange{{
			Attribute: lifecycleMultiValued, Kind: AttributeAddValues, Values: lifecycleRawValues("gamma"),
		}}, observe)
		values, _, _ = lifecycleValues(ctx, client, subject, lifecycleMultiValued)
		o.AddApplied = addErr == nil && slices.Equal(values, []string{"alpha", "beta", "gamma"})

		_, removeErr := target.updateRaw(ctx, client, subject, []AttributeChange{{
			Attribute: lifecycleMultiValued, Kind: AttributeRemoveValues, Values: lifecycleRawValues("beta"),
		}}, observe)
		values, _, _ = lifecycleValues(ctx, client, subject, lifecycleMultiValued)
		o.RemoveApplied = removeErr == nil && slices.Equal(values, []string{"alpha", "gamma"})

		cleared, clearErr := target.updateRaw(ctx, client, subject, []AttributeChange{{
			Attribute: lifecycleMultiValued, Kind: AttributeClear,
		}}, observe)
		// This SDK never verifies a clear, by design: an absent attribute
		// cannot prove emptiness, because omission can equally mean denied
		// visibility. So the write is accepted and the call still reports
		// ErrObjectVerification. Both are recorded, and a separate read is what
		// establishes the attribute actually went away — read as absent, not as
		// present-and-empty, and not as unloaded, since it was requested.
		o.ClearAccepted = cleared.State == ObjectWriteAccepted
		o.ClearClass = lifecycleClass(clearErr)
		values, state, _ := lifecycleValues(ctx, client, subject, lifecycleMultiValued)
		o.ClearReadsAbsent = state == AttributeAbsent && len(values) == 0
		if clearErr != nil && !errors.Is(clearErr, ErrObjectVerification) {
			o.Detail = strings.TrimSpace(o.Detail + " clear: " + clearErr.Error())
		}

		// An attribute the schema does not define. The refusal must come from
		// the directory's schema rather than from a guess, and must write
		// nothing — including not the valid change submitted alongside it.
		_, undefinedErr := target.updateRaw(ctx, client, subject, []AttributeChange{
			{Attribute: lifecycleUndefined, Kind: AttributeSet, Values: lifecycleRawValues("x")},
			{Attribute: lifecycleMultiValued, Kind: AttributeSet, Values: lifecycleRawValues("must-not-land")},
		}, observe)
		o.UndefinedRefused = undefinedErr != nil
		o.UndefinedClass = lifecycleClass(undefinedErr)
		values, state, _ = lifecycleValues(ctx, client, subject, lifecycleMultiValued)
		o.UndefinedWroteNothing = state == AttributeAbsent && !slices.Contains(values, "must-not-land")

		single, _, _ := lifecycleValues(ctx, client, subject, lifecycleSingle)
		o.UnrelatedValueSurvived = slices.Contains(single, unrelated)

		// --- instance-update-semantics ----------------------------------
		// A typed property update must change its own attribute and leave the
		// one the raw changes were using alone.
		const typed = "sdk-typed-display-name"
		typedResult, typedErr := target.updateTyped(ctx, client, subject, typed, observe)
		single, _, _ = lifecycleValues(ctx, client, subject, lifecycleSingle)
		o.TypedApplied = typedErr == nil && typedResult.Verified && slices.Contains(single, typed)
		_, omittedState, _ := lifecycleValues(ctx, client, subject, lifecycleMultiValued)
		o.OmittedUntouched = omittedState == AttributeAbsent

		// A stale precondition. The version is read, the object is then changed
		// by another write, and the stale version is submitted afterwards.
		version, versionErr := lifecycleVersion(ctx, client, subject)
		if versionErr != nil {
			o.StaleVersion = "version unreadable: " + versionErr.Error()
		} else {
			if _, err := target.updateRaw(ctx, client, subject, []AttributeChange{{
				Attribute: lifecycleMultiValued, Kind: AttributeSet, Values: lifecycleRawValues("bumped"),
			}}, observe); err != nil {
				o.Detail = strings.TrimSpace(o.Detail + " bump: " + err.Error())
			}
			stale := observe
			stale.ExpectedVersion = &version
			_, staleErr := target.updateRaw(ctx, client, subject, []AttributeChange{{
				Attribute: lifecycleMultiValued, Kind: AttributeSet, Values: lifecycleRawValues("stale-must-not-land"),
			}}, stale)
			o.StaleVersionClass = lifecycleClass(staleErr)
			switch {
			case staleErr == nil:
				o.StaleVersion = "applied"
			case errors.Is(staleErr, ErrObjectConcurrency):
				o.StaleVersion = "refused as a precondition failure"
			case errors.Is(staleErr, ErrObjectControlUnsupported):
				o.StaleVersion = "refused: the server does not enforce the assertion"
			default:
				o.StaleVersion = "refused: " + staleErr.Error()
			}
			values, _, _ = lifecycleValues(ctx, client, subject, lifecycleMultiValued)
			o.StaleWroteNothing = !slices.Contains(values, "stale-must-not-land")
			o.ConcurrentSurvived = slices.Contains(values, "bumped")
		}

		// --- recursive-delete-boundary ----------------------------------
		if target.container {
			// A class this SDK protects on creation cannot be deleted at all
			// until that protection is lifted, so the boundary has to be
			// reached first or the refusal observed below would be the
			// protection's and not the non-leaf rule's. The protection itself
			// is observed separately, on the deletion fixture.
			if target.protectedByDefault && target.unprotect != nil {
				if err := target.unprotect(ctx, client, subject, ObjectMutationOptions{}); err != nil {
					o.Detail = strings.TrimSpace(o.Detail + " unprotect subject: " + err.Error())
				}
			}
			childResult, childErr := client.CreateObject(ctx, CreateObjectRequest{
				Parent: subject, Class: "container", Name: "sdk-child"})
			if childErr != nil || childResult.TargetGUID == nil {
				o.Detail = strings.TrimSpace(o.Detail + " child: " + fmt.Sprint(childErr))
			} else {
				child := objectGUIDIdentity(*childResult.TargetGUID)
				_, nonLeafErr := target.remove(ctx, client, subject, false, ObjectMutationOptions{})
				o.NonLeafRefused = nonLeafErr != nil
				o.NonLeafClass = lifecycleClass(nonLeafErr)
				o.NonLeafChildKept = !lifecycleAbsent(ctx, client, child) && !lifecycleAbsent(ctx, client, subject)

				recursive, recursiveErr := target.remove(ctx, client, subject, true, ObjectMutationOptions{})
				o.RecursiveRemoved = recursiveErr == nil && lifecycleAbsent(ctx, client, child)
				o.RecursiveVerified = recursive.AbsentAfter && lifecycleAbsent(ctx, client, subject)
			}
		}

		// --- object-deletion-and-reference-constraints ------------------
		// A container class has already been deleted recursively above, so the
		// deletion scenario uses a second, leaf fixture of the same class. That
		// keeps the two boundaries from standing in for each other.
		deleteName := name + "-del"
		if target.kind == "computer" {
			deleteName = name + "D"
		}
		victim, victimErr := target.create(ctx, client, fixtureRoot, deleteName, observe)
		switch {
		case victimErr != nil || victim.TargetGUID == nil:
			o.Detail = strings.TrimSpace(o.Detail + " deletion fixture: " + fmt.Sprint(victimErr))
		default:
			id := objectGUIDIdentity(*victim.TargetGUID)
			if target.protectedByDefault {
				// Created protected by this SDK without being asked, so the
				// first delete must be refused. That refusal is the scenario's
				// failure half: a reference constraint the directory holds.
				_, protectedErr := target.remove(ctx, client, id, false, ObjectMutationOptions{})
				if protectedErr != nil && !lifecycleAbsent(ctx, client, id) {
					o.ProtectedRefused = "refused"
				} else {
					o.ProtectedRefused = "not refused"
				}
				if target.unprotect != nil {
					if err := target.unprotect(ctx, client, id, ObjectMutationOptions{}); err != nil {
						o.Detail = strings.TrimSpace(o.Detail + " unprotect: " + err.Error())
					}
				}
			}
			removal, removalErr := target.remove(ctx, client, id, false, ObjectMutationOptions{})
			o.DeletedAbsentAfter = removalErr == nil && removal.AbsentAfter && lifecycleAbsent(ctx, client, id)
			o.DeleteVerified = removal.Verified
			// Deleting it again must report absence, not an error a caller
			// cannot classify. A provider converges on this every time it
			// retries a destroy.
			_, secondErr := target.remove(ctx, client, id, false, ObjectMutationOptions{})
			o.SecondDeleteClass = lifecycleClass(secondErr)
		}

		o.AllocationsRemaining = sweepAllocations(counts)
		o.Passed = o.qualifies(target)
		if !o.Passed {
			fail("%s: lifecycle observation incomplete: %+v", target.kind, o)
		}
		artifact.Operations = append(artifact.Operations, o)
	}

	if !t.Failed() {
		stage = "complete"
	}
	t.Logf("mutation lifecycle sweep over %d classes on %s; full ticket qualification remains incomplete",
		len(artifact.Operations), endpoint)
}

// lifecycleVersion reads the precondition an optimistic update needs. It is
// separate because uSNChanged is a counter the server owns: reading it through
// the typed value layer is the only way to be sure the harness is asserting the
// same number the SDK would send.
func lifecycleVersion(ctx context.Context, c *Client, id Identity) (ObjectVersion, error) {
	var version ObjectVersion
	observed, err := c.ResolveIdentity(ctx, id, ResolveIdentityOptions{
		Properties: []string{"objectGUID", "uSNChanged"}})
	if err != nil {
		return version, err
	}
	if observed.Object == nil {
		return version, ErrDirectoryObjectNotFound
	}
	guidValue, err := observed.Object.Values("objectGUID").Single()
	if err != nil {
		return version, err
	}
	guid, err := guidValue.GUID()
	if err != nil {
		return version, err
	}
	usnValue, err := observed.Object.Values("uSNChanged").Single()
	if err != nil {
		return version, err
	}
	// uSNChanged is an LDAP LargeInteger, so the typed layer reads it signed,
	// while ObjectVersion carries it unsigned. A negative value is a server
	// anomaly rather than a counter, and must not wrap into a huge uint64.
	usn, err := usnValue.Int64()
	if err != nil {
		return version, err
	}
	if usn < 0 {
		return version, fmt.Errorf("%w: uSNChanged is negative", ErrInvalidResult)
	}
	return ObjectVersion{Source: observed.Source, GUID: guid, USNChanged: uint64(usn)}, nil
}
