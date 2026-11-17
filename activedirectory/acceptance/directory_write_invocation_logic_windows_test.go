//go:build windows && (amd64 || arm64)

package acceptance

import (
	"testing"

	admodel "github.com/deploymenttheory/go-sdk-activedirectory/activedirectory/internal/model"
)

func InternalPassingWriteRefusal(shape string) InternalWriteRefusal {
	return InternalWriteRefusal{
		Shape:   shape,
		Refused: true,
		Class:   admodel.ClassInvalidRequest.String(),
		NoWrite: true,
	}
}

func InternalPassingWriteInvocationObservation() InternalWriteInvocationObservation {
	return InternalWriteInvocationObservation{
		Cmdlet:    "Set-ADUser",
		Role:      InternalWriteRoleUpdate,
		Mechanism: "explicit AttributeChange values",
		Refusals: []InternalWriteRefusal{
			InternalPassingWriteRefusal("a zero identity"),
			InternalPassingWriteRefusal("no changes at all"),
		},
		TypedResult: true,
		Allocations: 0,
	}
}

func TestWriteInvocationObservationRequiresEveryHalf(t *testing.T) {
	if !InternalPassingWriteInvocationObservation().InternalQualifies() {
		t.Fatal("the fully satisfied observation does not qualify")
	}
	yes := true
	for _, mutation := range []struct {
		InternalName  string
		InternalApply func(*InternalWriteInvocationObservation)
	}{
		{"at least one refusal was exercised", func(o *InternalWriteInvocationObservation) { o.Refusals = nil }},
		{"every refusal was refused", func(o *InternalWriteInvocationObservation) { o.Refusals[1].Refused = false }},
		{"every refusal wrote nothing", func(o *InternalWriteInvocationObservation) { o.Refusals[1].NoWrite = false }},
		{"the typed result carried the state", func(o *InternalWriteInvocationObservation) { o.TypedResult = false }},
		{"native allocations balanced", func(o *InternalWriteInvocationObservation) { o.Allocations = 1 }},
		// A prompt hook that was invoked would be an implicit confirmation,
		// which is precisely what this scenario says the Go surface replaces.
		{"no prompt was invoked", func(o *InternalWriteInvocationObservation) { o.PromptInvoked = &yes }},
	} {
		t.Run(mutation.InternalName, func(t *testing.T) {
			o := InternalPassingWriteInvocationObservation()
			o.Refusals = append([]InternalWriteRefusal(nil), o.Refusals...)
			mutation.InternalApply(&o)
			if o.InternalQualifies() {
				t.Fatalf("the observation still qualified without %q", mutation.InternalName)
			}
		})
	}
}

// A refusal must be reported as a request to correct, or as something the
// directory cannot do. A denial, a conflict or an uncertain outcome would mean
// the call reached the directory and tried — which is the opposite of the
// claim, so none of those may pass.
func TestWriteRefusalRejectsOutcomesThatMeanItTried(t *testing.T) {
	for _, class := range []admodel.ErrorClass{admodel.ClassInvalidRequest, admodel.ClassUnsupported} {
		refusal := InternalPassingWriteRefusal("shape")
		refusal.Class = class.String()
		if !refusal.InternalAcceptable() {
			t.Errorf("a refusal reported as %s was not accepted", class)
		}
	}
	for _, class := range []admodel.ErrorClass{admodel.ClassUnclassified, admodel.ClassDenied, admodel.ClassUncertain, admodel.ClassConflict, admodel.ClassNotFound, admodel.ClassAlreadyExists, admodel.ClassUnverified, admodel.ClassIncomplete, admodel.ClassTransport} {
		refusal := InternalPassingWriteRefusal("shape")
		refusal.Class = class.String()
		if refusal.InternalAcceptable() {
			t.Errorf("a refusal reported as %s was accepted; that class means the call "+
				"reached the directory", class)
		}
	}
}

// A shape an operation cannot express is recorded as not applicable rather
// than passed on a check that cannot fail. The escape hatch must require a
// stated reason, so it cannot be used to wave a shape through silently.
func TestWriteRefusalNotApplicableNeedsAReason(t *testing.T) {
	skipped := InternalWriteRefusal{
		Shape:    "a shape this operation has no parameter for",
		Resolved: "the request type carries no such field",
	}
	if !skipped.InternalAcceptable() {
		t.Error("a documented inapplicable shape was treated as a failure")
	}
	// Without a reason it is just an unrefused shape, and must fail.
	bare := InternalWriteRefusal{Shape: "a shape"}
	if bare.InternalAcceptable() {
		t.Error("an unrefused shape with no stated reason was accepted")
	}
}

// Every refusal in an observation is load-bearing, not just the first. A loop
// that returned on the first acceptable one would pass an observation whose
// later shapes were never refused.
func TestWriteInvocationChecksEveryRefusalNotJustTheFirst(t *testing.T) {
	for position := range 3 {
		o := InternalPassingWriteInvocationObservation()
		o.Refusals = []InternalWriteRefusal{
			InternalPassingWriteRefusal(
				"first",
			),
			InternalPassingWriteRefusal("second"),
			InternalPassingWriteRefusal("third"),
		}
		o.Refusals[position].Refused = false
		if o.InternalQualifies() {
			t.Errorf("an observation qualified with refusal %d unrefused", position)
		}
	}
}
