//go:build windows && (amd64 || arm64)

package acceptance

import (
	"encoding/json"
	"os"
	"testing"

	admodel "github.com/deploymenttheory/go-sdk-activedirectory/activedirectory/internal/model"
)

// The lifecycle sweep's decision logic runs only inside an opt-in lab harness,
// so without these tests nothing exercises it. An aggregation that silently
// became permissive would make every future run report success regardless of
// what the directory did, and the lab artifact would look like evidence.

func InternalPassingLifecycleObservation() InternalLifecycleObservation {
	return InternalLifecycleObservation{
		Kind:                   "user",
		Class:                  "user",
		CreatedVerified:        true,
		CreatedClass:           "user",
		CreatedInContainer:     true,
		CreatedIdentity:        "guid:6a2ba0f0-4a2e-4f6d-9f1b-0c3d5e7a9b11",
		DuplicateRefused:       true,
		DuplicateClass:         admodel.ClassAlreadyExists.String(),
		DuplicateWroteOnce:     true,
		SetApplied:             true,
		AddApplied:             true,
		RemoveApplied:          true,
		ClearAccepted:          true,
		ClearReadsAbsent:       true,
		ClearClass:             admodel.ClassUncertain.String(),
		UnrelatedValueSurvived: true,
		UndefinedRefused:       true,
		UndefinedClass:         admodel.ClassInvalidRequest.String(),
		UndefinedWroteNothing:  true,
		TypedApplied:           true,
		OmittedUntouched:       true,
		StaleVersion:           "refused as a precondition failure",
		StaleVersionClass:      admodel.ClassConflict.String(),
		StaleWroteNothing:      true,
		ConcurrentSurvived:     true,
		DeletedAbsentAfter:     true,
		DeleteVerified:         true,
		SecondDeleteClass:      admodel.ClassNotFound.String(),
		AllocationsRemaining:   0,
	}
}

func InternalLeafLifecycleTarget() InternalLifecycleTarget {
	return InternalLifecycleTarget{InternalKind: "user", InternalClass: "user"}
}

// Every input must be load-bearing. Flipping any single one must withhold the
// qualification, including the native allocation balance and the error
// classifications — a refusal for the wrong reason is a different observation.
func TestLifecycleObservationRequiresEveryHalf(t *testing.T) {
	target := InternalLeafLifecycleTarget()
	if !InternalPassingLifecycleObservation().InternalQualifies(target) {
		t.Fatal("the fully satisfied observation does not qualify")
	}
	for _, mutation := range []struct {
		InternalName  string
		InternalApply func(*InternalLifecycleObservation)
	}{
		{"create verified", func(o *InternalLifecycleObservation) { o.CreatedVerified = false }},
		{"create produced the requested class", func(o *InternalLifecycleObservation) { o.CreatedClass = "contact" }},
		{"create landed in the requested container", func(o *InternalLifecycleObservation) { o.CreatedInContainer = false }},
		{"create reported an identity", func(o *InternalLifecycleObservation) { o.CreatedIdentity = "" }},
		{"duplicate name refused", func(o *InternalLifecycleObservation) { o.DuplicateRefused = false }},
		{"duplicate refused as already-exists", func(o *InternalLifecycleObservation) {
			o.DuplicateClass = admodel.ClassDenied.String()
		}},
		{"duplicate left exactly one object", func(o *InternalLifecycleObservation) { o.DuplicateWroteOnce = false }},
		{"set applied", func(o *InternalLifecycleObservation) { o.SetApplied = false }},
		{"add applied", func(o *InternalLifecycleObservation) { o.AddApplied = false }},
		{"remove applied", func(o *InternalLifecycleObservation) { o.RemoveApplied = false }},
		{"clear accepted", func(o *InternalLifecycleObservation) { o.ClearAccepted = false }},
		{"clear read back absent", func(o *InternalLifecycleObservation) { o.ClearReadsAbsent = false }},
		// This SDK never verifies a clear. A clear that reported success would
		// mean the verification had been loosened, which is the change this
		// case exists to catch.
		{"clear reported as unverified", func(o *InternalLifecycleObservation) {
			o.ClearClass = admodel.ClassUnclassified.String()
		}},
		{"unrelated value survived", func(o *InternalLifecycleObservation) { o.UnrelatedValueSurvived = false }},
		{"undefined attribute refused", func(o *InternalLifecycleObservation) { o.UndefinedRefused = false }},
		{"undefined refusal wrote nothing", func(o *InternalLifecycleObservation) { o.UndefinedWroteNothing = false }},
		{"undefined refused for a schema reason", func(o *InternalLifecycleObservation) {
			o.UndefinedClass = admodel.ClassDenied.String()
		}},
		{"typed update applied", func(o *InternalLifecycleObservation) { o.TypedApplied = false }},
		{"omitted attribute untouched", func(o *InternalLifecycleObservation) { o.OmittedUntouched = false }},
		{"stale precondition wrote nothing", func(o *InternalLifecycleObservation) { o.StaleWroteNothing = false }},
		{"concurrent unrelated change survived", func(o *InternalLifecycleObservation) { o.ConcurrentSurvived = false }},
		{"deleted object absent after", func(o *InternalLifecycleObservation) { o.DeletedAbsentAfter = false }},
		{"delete verified", func(o *InternalLifecycleObservation) { o.DeleteVerified = false }},
		{"second delete reports absence", func(o *InternalLifecycleObservation) {
			o.SecondDeleteClass = admodel.ClassInvalidRequest.String()
		}},
		{"native allocations balanced", func(o *InternalLifecycleObservation) { o.AllocationsRemaining = 1 }},
	} {
		t.Run(mutation.InternalName, func(t *testing.T) {
			o := InternalPassingLifecycleObservation()
			mutation.InternalApply(&o)
			if o.InternalQualifies(target) {
				t.Fatalf("the observation still qualified without %q", mutation.InternalName)
			}
		})
	}
}

// A stale precondition has two honest outcomes: refused as a conflict, or
// refused because this server does not enforce the assertion. Applying the
// write is not one of them, and neither is reporting success.
func TestLifecycleAcceptsEitherHonestStalePreconditionOutcome(t *testing.T) {
	target := InternalLeafLifecycleTarget()
	for _, class := range []admodel.ErrorClass{admodel.ClassConflict, admodel.ClassUnsupported} {
		o := InternalPassingLifecycleObservation()
		o.StaleVersionClass = class.String()
		if !o.InternalQualifies(target) {
			t.Errorf("a stale precondition refused as %s was not accepted", class)
		}
	}
	for _, class := range []admodel.ErrorClass{admodel.ClassUnclassified, admodel.ClassDenied, admodel.ClassNotFound, admodel.ClassUncertain} {
		o := InternalPassingLifecycleObservation()
		o.StaleVersionClass = class.String()
		if o.InternalQualifies(target) {
			t.Errorf("a stale precondition reported as %s was accepted", class)
		}
	}
}

// A leaf class has no delete boundary to observe, so the container-only fields
// must neither qualify it by default nor disqualify it. A container must be
// held to all of them.
func TestLifecycleBoundaryAppliesOnlyToContainers(t *testing.T) {
	leaf, container := InternalLeafLifecycleTarget(), InternalLifecycleTarget{
		InternalKind:      "object",
		InternalClass:     "container",
		InternalContainer: true,
	}

	o := InternalPassingLifecycleObservation()
	if !o.InternalQualifies(leaf) {
		t.Fatal("a leaf was disqualified for having no delete boundary")
	}
	if o.InternalQualifies(container) {
		t.Fatal("a container qualified without observing its delete boundary")
	}

	o.Class, o.CreatedClass = container.InternalClass, container.InternalClass
	o.NonLeafRefused, o.NonLeafChildKept = true, true
	o.NonLeafClass = admodel.ClassInvalidRequest.String()
	o.RecursiveRemoved, o.RecursiveVerified = true, true
	if !o.InternalQualifies(container) {
		t.Fatal("a fully observed container did not qualify")
	}
	for _, mutation := range []struct {
		InternalName  string
		InternalApply func(*InternalLifecycleObservation)
	}{
		{"non-leaf delete refused", func(o *InternalLifecycleObservation) { o.NonLeafRefused = false }},
		{"the refusal kept the child", func(o *InternalLifecycleObservation) { o.NonLeafChildKept = false }},
		{"refused for a boundary reason", func(o *InternalLifecycleObservation) { o.NonLeafClass = admodel.ClassDenied.String() }},
		{"recursive delete removed the children", func(o *InternalLifecycleObservation) { o.RecursiveRemoved = false }},
		{"recursive delete proved absence", func(o *InternalLifecycleObservation) { o.RecursiveVerified = false }},
	} {
		t.Run(mutation.InternalName, func(t *testing.T) {
			observation := o
			mutation.InternalApply(&observation)
			if observation.InternalQualifies(container) {
				t.Fatalf("a container still qualified without %q", mutation.InternalName)
			}
		})
	}
}

// A class this SDK protects on creation must have that protection observed. The
// first delete being refused is the deletion scenario's failure half, so an
// unprotected outcome cannot pass as one.
func TestLifecycleRequiresTheProtectionRefusalWhereItApplies(t *testing.T) {
	protected := InternalLifecycleTarget{
		InternalKind: "organizational unit", InternalClass: "organizationalUnit",
		InternalContainer: true, InternalProtectedByDefault: true,
	}
	o := InternalPassingLifecycleObservation()
	o.Class, o.CreatedClass = protected.InternalClass, protected.InternalClass
	o.NonLeafRefused, o.NonLeafChildKept = true, true
	o.NonLeafClass = admodel.ClassInvalidRequest.String()
	o.RecursiveRemoved, o.RecursiveVerified = true, true

	o.ProtectedRefused = "refused"
	if !o.InternalQualifies(protected) {
		t.Fatal("a protected class with its refusal observed did not qualify")
	}
	for _, outcome := range []string{"", "not refused", "unknown"} {
		observation := o
		observation.ProtectedRefused = outcome
		if observation.InternalQualifies(protected) {
			t.Errorf("a protected class qualified with protection outcome %q", outcome)
		}
	}
	// The same field must not be demanded of a class this SDK does not protect.
	leaf := InternalPassingLifecycleObservation()
	if !leaf.InternalQualifies(InternalLeafLifecycleTarget()) {
		t.Fatal("an unprotected class was held to the protection refusal")
	}
}

// The table is a claim about the coverage contract: each row says it observes
// one class's create, update and delete operations. A row naming an operation
// the contract does not carry, or missing one of the lifecycle scenarios, would
// make the artifact cite evidence for something never asked for.
func TestLifecycleTableMatchesCoverageContract(t *testing.T) {
	data, err := os.ReadFile(repositoryFile("coverage/inventory.json"))
	if err != nil {
		t.Fatal(err)
	}
	// Windows PowerShell UTF8 output may include the BOM.
	if len(data) >= 3 && string(data[:3]) == "\xef\xbb\xbf" {
		data = data[3:]
	}
	var inventory struct {
		Operations []struct {
			Cmdlet    string `json:"cmdlet"`
			Scenarios []struct {
				Name string `json:"name"`
			} `json:"scenarios"`
		} `json:"operations"`
	}
	if err := json.Unmarshal(data, &inventory); err != nil {
		t.Fatal(err)
	}
	scenarios := map[string]map[string]bool{}
	for _, operation := range inventory.Operations {
		names := map[string]bool{}
		for _, scenario := range operation.Scenarios {
			names[scenario.Name] = true
		}
		scenarios[operation.Cmdlet] = names
	}

	// Each role is claimed to evidence a specific scenario, so the pairing is
	// checked rather than merely the operation's existence.
	required := map[string]string{
		"create": "creation-defaults-and-readback",
		"update": "attribute-update-intent",
		"remove": "object-deletion-and-reference-constraints",
	}
	seen := map[string]bool{}
	for _, target := range InternalLifecycleTargets() {
		for role, cmdlet := range map[string]string{
			"create": target.InternalCreateCmdlet, "update": target.InternalUpdateCmdlet, "remove": target.InternalRemoveCmdlet,
		} {
			if cmdlet == "" {
				t.Errorf("%s names no %s operation", target.InternalKind, role)
				continue
			}
			if seen[cmdlet] {
				t.Errorf("%s appears twice in the lifecycle table", cmdlet)
			}
			seen[cmdlet] = true
			names, ok := scenarios[cmdlet]
			if !ok {
				t.Errorf("%s is not in the coverage contract", cmdlet)
				continue
			}
			if !names[required[role]] {
				t.Errorf("%s has no %s scenario, so the %s role cannot evidence it",
					cmdlet, required[role], role)
			}
		}
		// Only a container class claims the recursive boundary, and the
		// contract has to agree that its remove operation carries it.
		if target.InternalContainer &&
			!scenarios[target.InternalRemoveCmdlet]["recursive-delete-boundary"] {
			t.Errorf("%s is driven as a container but %s has no recursive-delete-boundary scenario",
				target.InternalKind, target.InternalRemoveCmdlet)
		}
		if !target.InternalContainer &&
			scenarios[target.InternalRemoveCmdlet]["recursive-delete-boundary"] {
			t.Errorf("%s carries a recursive-delete-boundary scenario the table does not observe",
				target.InternalRemoveCmdlet)
		}
	}
	if len(seen) != 15 {
		t.Errorf("the table covers %d operations; the five classes have 15 between them", len(seen))
	}
}

// Every class must be distinct and fully wired, or one row would silently
// stand in for another.
func TestLifecycleTargetsAreCompleteAndDistinct(t *testing.T) {
	kinds, classes := map[string]bool{}, map[string]bool{}
	for _, target := range InternalLifecycleTargets() {
		if kinds[target.InternalKind] {
			t.Errorf("%s appears twice", target.InternalKind)
		}
		kinds[target.InternalKind] = true
		if classes[target.InternalClass] {
			t.Errorf("class %s appears twice", target.InternalClass)
		}
		classes[target.InternalClass] = true
		if target.InternalCreate == nil || target.InternalUpdateRaw == nil ||
			target.InternalUpdateTyped == nil ||
			target.InternalRemove == nil {
			t.Errorf("%s does not supply every lifecycle call", target.InternalKind)
		}
		// The create-time halves of the update scenarios need their own
		// closures. Every class must offer the raw one; only the generic path
		// may omit the typed one, because it has no typed property layer.
		if target.InternalCreateWithAttributes == nil {
			t.Errorf("%s cannot be created with explicit attributes", target.InternalKind)
		}
		if target.InternalCreateWithProperties == nil && target.InternalKind != "object" {
			t.Errorf("%s cannot be created from typed properties", target.InternalKind)
		}
		if target.InternalCreateWithProperties != nil && target.InternalKind == "object" {
			t.Error("the generic object path has no typed property layer to exercise")
		}
		// A class this SDK protects on creation needs a way to lift that
		// protection, or the harness cannot reach its ordinary delete.
		if target.InternalProtectedByDefault && target.InternalUnprotect == nil {
			t.Errorf(
				"%s is protected by default but supplies no way to unprotect it",
				target.InternalKind,
			)
		}
	}
	if len(kinds) != 5 {
		t.Errorf("the table drives %d classes, want 5", len(kinds))
	}
}
