//go:build windows && (amd64 || arm64)

package activedirectory

import (
	"encoding/json"
	"os"
	"testing"
)

// The lifecycle sweep's decision logic runs only inside an opt-in lab harness,
// so without these tests nothing exercises it. An aggregation that silently
// became permissive would make every future run report success regardless of
// what the directory did, and the lab artifact would look like evidence.

func passingLifecycleObservation() lifecycleObservation {
	return lifecycleObservation{
		Kind: "user", Class: "user",
		CreatedVerified: true, CreatedClass: "user", CreatedInContainer: true,
		CreatedIdentity:  "guid:6a2ba0f0-4a2e-4f6d-9f1b-0c3d5e7a9b11",
		DuplicateRefused: true, DuplicateClass: ClassAlreadyExists.String(), DuplicateWroteOnce: true,
		SetApplied: true, AddApplied: true, RemoveApplied: true,
		ClearAccepted: true, ClearReadsAbsent: true, ClearClass: ClassUncertain.String(),
		UnrelatedValueSurvived: true, UndefinedRefused: true,
		UndefinedClass: ClassInvalidRequest.String(), UndefinedWroteNothing: true,
		TypedApplied: true, OmittedUntouched: true,
		StaleVersion: "refused as a precondition failure", StaleVersionClass: ClassConflict.String(),
		StaleWroteNothing: true, ConcurrentSurvived: true,
		DeletedAbsentAfter: true, DeleteVerified: true, SecondDeleteClass: ClassNotFound.String(),
		AllocationsRemaining: 0,
	}
}

func leafLifecycleTarget() lifecycleTarget {
	return lifecycleTarget{kind: "user", class: "user"}
}

// Every input must be load-bearing. Flipping any single one must withhold the
// qualification, including the native allocation balance and the error
// classifications — a refusal for the wrong reason is a different observation.
func TestLifecycleObservationRequiresEveryHalf(t *testing.T) {
	target := leafLifecycleTarget()
	if !passingLifecycleObservation().qualifies(target) {
		t.Fatal("the fully satisfied observation does not qualify")
	}
	for _, mutation := range []struct {
		name  string
		apply func(*lifecycleObservation)
	}{
		{"create verified", func(o *lifecycleObservation) { o.CreatedVerified = false }},
		{"create produced the requested class", func(o *lifecycleObservation) { o.CreatedClass = "contact" }},
		{"create landed in the requested container", func(o *lifecycleObservation) { o.CreatedInContainer = false }},
		{"create reported an identity", func(o *lifecycleObservation) { o.CreatedIdentity = "" }},
		{"duplicate name refused", func(o *lifecycleObservation) { o.DuplicateRefused = false }},
		{"duplicate refused as already-exists", func(o *lifecycleObservation) {
			o.DuplicateClass = ClassDenied.String()
		}},
		{"duplicate left exactly one object", func(o *lifecycleObservation) { o.DuplicateWroteOnce = false }},
		{"set applied", func(o *lifecycleObservation) { o.SetApplied = false }},
		{"add applied", func(o *lifecycleObservation) { o.AddApplied = false }},
		{"remove applied", func(o *lifecycleObservation) { o.RemoveApplied = false }},
		{"clear accepted", func(o *lifecycleObservation) { o.ClearAccepted = false }},
		{"clear read back absent", func(o *lifecycleObservation) { o.ClearReadsAbsent = false }},
		// This SDK never verifies a clear. A clear that reported success would
		// mean the verification had been loosened, which is the change this
		// case exists to catch.
		{"clear reported as unverified", func(o *lifecycleObservation) {
			o.ClearClass = ClassUnclassified.String()
		}},
		{"unrelated value survived", func(o *lifecycleObservation) { o.UnrelatedValueSurvived = false }},
		{"undefined attribute refused", func(o *lifecycleObservation) { o.UndefinedRefused = false }},
		{"undefined refusal wrote nothing", func(o *lifecycleObservation) { o.UndefinedWroteNothing = false }},
		{"undefined refused for a schema reason", func(o *lifecycleObservation) {
			o.UndefinedClass = ClassDenied.String()
		}},
		{"typed update applied", func(o *lifecycleObservation) { o.TypedApplied = false }},
		{"omitted attribute untouched", func(o *lifecycleObservation) { o.OmittedUntouched = false }},
		{"stale precondition wrote nothing", func(o *lifecycleObservation) { o.StaleWroteNothing = false }},
		{"concurrent unrelated change survived", func(o *lifecycleObservation) { o.ConcurrentSurvived = false }},
		{"deleted object absent after", func(o *lifecycleObservation) { o.DeletedAbsentAfter = false }},
		{"delete verified", func(o *lifecycleObservation) { o.DeleteVerified = false }},
		{"second delete reports absence", func(o *lifecycleObservation) {
			o.SecondDeleteClass = ClassInvalidRequest.String()
		}},
		{"native allocations balanced", func(o *lifecycleObservation) { o.AllocationsRemaining = 1 }},
	} {
		t.Run(mutation.name, func(t *testing.T) {
			o := passingLifecycleObservation()
			mutation.apply(&o)
			if o.qualifies(target) {
				t.Fatalf("the observation still qualified without %q", mutation.name)
			}
		})
	}
}

// A stale precondition has two honest outcomes: refused as a conflict, or
// refused because this server does not enforce the assertion. Applying the
// write is not one of them, and neither is reporting success.
func TestLifecycleAcceptsEitherHonestStalePreconditionOutcome(t *testing.T) {
	target := leafLifecycleTarget()
	for _, class := range []ErrorClass{ClassConflict, ClassUnsupported} {
		o := passingLifecycleObservation()
		o.StaleVersionClass = class.String()
		if !o.qualifies(target) {
			t.Errorf("a stale precondition refused as %s was not accepted", class)
		}
	}
	for _, class := range []ErrorClass{ClassUnclassified, ClassDenied, ClassNotFound, ClassUncertain} {
		o := passingLifecycleObservation()
		o.StaleVersionClass = class.String()
		if o.qualifies(target) {
			t.Errorf("a stale precondition reported as %s was accepted", class)
		}
	}
}

// A leaf class has no delete boundary to observe, so the container-only fields
// must neither qualify it by default nor disqualify it. A container must be
// held to all of them.
func TestLifecycleBoundaryAppliesOnlyToContainers(t *testing.T) {
	leaf, container := leafLifecycleTarget(), lifecycleTarget{kind: "object", class: "container", container: true}

	o := passingLifecycleObservation()
	if !o.qualifies(leaf) {
		t.Fatal("a leaf was disqualified for having no delete boundary")
	}
	if o.qualifies(container) {
		t.Fatal("a container qualified without observing its delete boundary")
	}

	o.Class, o.CreatedClass = container.class, container.class
	o.NonLeafRefused, o.NonLeafChildKept = true, true
	o.NonLeafClass = ClassInvalidRequest.String()
	o.RecursiveRemoved, o.RecursiveVerified = true, true
	if !o.qualifies(container) {
		t.Fatal("a fully observed container did not qualify")
	}
	for _, mutation := range []struct {
		name  string
		apply func(*lifecycleObservation)
	}{
		{"non-leaf delete refused", func(o *lifecycleObservation) { o.NonLeafRefused = false }},
		{"the refusal kept the child", func(o *lifecycleObservation) { o.NonLeafChildKept = false }},
		{"refused for a boundary reason", func(o *lifecycleObservation) { o.NonLeafClass = ClassDenied.String() }},
		{"recursive delete removed the children", func(o *lifecycleObservation) { o.RecursiveRemoved = false }},
		{"recursive delete proved absence", func(o *lifecycleObservation) { o.RecursiveVerified = false }},
	} {
		t.Run(mutation.name, func(t *testing.T) {
			observation := o
			mutation.apply(&observation)
			if observation.qualifies(container) {
				t.Fatalf("a container still qualified without %q", mutation.name)
			}
		})
	}
}

// A class this SDK protects on creation must have that protection observed. The
// first delete being refused is the deletion scenario's failure half, so an
// unprotected outcome cannot pass as one.
func TestLifecycleRequiresTheProtectionRefusalWhereItApplies(t *testing.T) {
	protected := lifecycleTarget{kind: "organizational unit", class: "organizationalUnit",
		container: true, protectedByDefault: true}
	o := passingLifecycleObservation()
	o.Class, o.CreatedClass = protected.class, protected.class
	o.NonLeafRefused, o.NonLeafChildKept = true, true
	o.NonLeafClass = ClassInvalidRequest.String()
	o.RecursiveRemoved, o.RecursiveVerified = true, true

	o.ProtectedRefused = "refused"
	if !o.qualifies(protected) {
		t.Fatal("a protected class with its refusal observed did not qualify")
	}
	for _, outcome := range []string{"", "not refused", "unknown"} {
		observation := o
		observation.ProtectedRefused = outcome
		if observation.qualifies(protected) {
			t.Errorf("a protected class qualified with protection outcome %q", outcome)
		}
	}
	// The same field must not be demanded of a class this SDK does not protect.
	leaf := passingLifecycleObservation()
	if !leaf.qualifies(leafLifecycleTarget()) {
		t.Fatal("an unprotected class was held to the protection refusal")
	}
}

// The table is a claim about the coverage contract: each row says it observes
// one class's create, update and delete operations. A row naming an operation
// the contract does not carry, or missing one of the lifecycle scenarios, would
// make the artifact cite evidence for something never asked for.
func TestLifecycleTableMatchesCoverageContract(t *testing.T) {
	data, err := os.ReadFile("coverage/inventory.json")
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
	for _, target := range lifecycleTargets() {
		for role, cmdlet := range map[string]string{
			"create": target.createCmdlet, "update": target.updateCmdlet, "remove": target.removeCmdlet,
		} {
			if cmdlet == "" {
				t.Errorf("%s names no %s operation", target.kind, role)
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
		if target.container && !scenarios[target.removeCmdlet]["recursive-delete-boundary"] {
			t.Errorf("%s is driven as a container but %s has no recursive-delete-boundary scenario",
				target.kind, target.removeCmdlet)
		}
		if !target.container && scenarios[target.removeCmdlet]["recursive-delete-boundary"] {
			t.Errorf("%s carries a recursive-delete-boundary scenario the table does not observe",
				target.removeCmdlet)
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
	for _, target := range lifecycleTargets() {
		if kinds[target.kind] {
			t.Errorf("%s appears twice", target.kind)
		}
		kinds[target.kind] = true
		if classes[target.class] {
			t.Errorf("class %s appears twice", target.class)
		}
		classes[target.class] = true
		if target.create == nil || target.updateRaw == nil || target.updateTyped == nil || target.remove == nil {
			t.Errorf("%s does not supply every lifecycle call", target.kind)
		}
		// A class this SDK protects on creation needs a way to lift that
		// protection, or the harness cannot reach its ordinary delete.
		if target.protectedByDefault && target.unprotect == nil {
			t.Errorf("%s is protected by default but supplies no way to unprotect it", target.kind)
		}
	}
	if len(kinds) != 5 {
		t.Errorf("the table drives %d classes, want 5", len(kinds))
	}
}
