//go:build windows && (amd64 || arm64)

package activedirectory

import "testing"

// The write-invocation sweep's decision logic runs only inside the lab. The
// claim it makes is that an invalid request writes nothing, so a permissive
// aggregation here would turn the artifact into a statement that a caller's
// bad configuration is safe when it is not.

func passingWriteRefusal(shape string) writeRefusal {
	return writeRefusal{Shape: shape, Refused: true, Class: ClassInvalidRequest.String(), NoWrite: true}
}

func passingWriteInvocationObservation() writeInvocationObservation {
	return writeInvocationObservation{
		Cmdlet: "Set-ADUser", Role: writeRoleUpdate, Mechanism: "explicit AttributeChange values",
		Refusals: []writeRefusal{
			passingWriteRefusal("a zero identity"),
			passingWriteRefusal("no changes at all"),
		},
		TypedResult: true, Allocations: 0,
	}
}

func TestWriteInvocationObservationRequiresEveryHalf(t *testing.T) {
	if !passingWriteInvocationObservation().qualifies() {
		t.Fatal("the fully satisfied observation does not qualify")
	}
	yes := true
	for _, mutation := range []struct {
		name  string
		apply func(*writeInvocationObservation)
	}{
		{"at least one refusal was exercised", func(o *writeInvocationObservation) { o.Refusals = nil }},
		{"every refusal was refused", func(o *writeInvocationObservation) { o.Refusals[1].Refused = false }},
		{"every refusal wrote nothing", func(o *writeInvocationObservation) { o.Refusals[1].NoWrite = false }},
		{"the typed result carried the state", func(o *writeInvocationObservation) { o.TypedResult = false }},
		{"native allocations balanced", func(o *writeInvocationObservation) { o.Allocations = 1 }},
		// A prompt hook that was invoked would be an implicit confirmation,
		// which is precisely what this scenario says the Go surface replaces.
		{"no prompt was invoked", func(o *writeInvocationObservation) { o.PromptInvoked = &yes }},
	} {
		t.Run(mutation.name, func(t *testing.T) {
			o := passingWriteInvocationObservation()
			o.Refusals = append([]writeRefusal(nil), o.Refusals...)
			mutation.apply(&o)
			if o.qualifies() {
				t.Fatalf("the observation still qualified without %q", mutation.name)
			}
		})
	}
}

// A refusal must be reported as a request to correct, or as something the
// directory cannot do. A denial, a conflict or an uncertain outcome would mean
// the call reached the directory and tried — which is the opposite of the
// claim, so none of those may pass.
func TestWriteRefusalRejectsOutcomesThatMeanItTried(t *testing.T) {
	for _, class := range []ErrorClass{ClassInvalidRequest, ClassUnsupported} {
		refusal := passingWriteRefusal("shape")
		refusal.Class = class.String()
		if !refusal.acceptable() {
			t.Errorf("a refusal reported as %s was not accepted", class)
		}
	}
	for _, class := range []ErrorClass{
		ClassUnclassified, ClassDenied, ClassUncertain, ClassConflict, ClassNotFound,
		ClassAlreadyExists, ClassUnverified, ClassIncomplete, ClassTransport,
	} {
		refusal := passingWriteRefusal("shape")
		refusal.Class = class.String()
		if refusal.acceptable() {
			t.Errorf("a refusal reported as %s was accepted; that class means the call "+
				"reached the directory", class)
		}
	}
}

// A shape an operation cannot express is recorded as not applicable rather
// than passed on a check that cannot fail. The escape hatch must require a
// stated reason, so it cannot be used to wave a shape through silently.
func TestWriteRefusalNotApplicableNeedsAReason(t *testing.T) {
	skipped := writeRefusal{Shape: "a shape this operation has no parameter for",
		Resolved: "the request type carries no such field"}
	if !skipped.acceptable() {
		t.Error("a documented inapplicable shape was treated as a failure")
	}
	// Without a reason it is just an unrefused shape, and must fail.
	bare := writeRefusal{Shape: "a shape"}
	if bare.acceptable() {
		t.Error("an unrefused shape with no stated reason was accepted")
	}
}

// Every refusal in an observation is load-bearing, not just the first. A loop
// that returned on the first acceptable one would pass an observation whose
// later shapes were never refused.
func TestWriteInvocationChecksEveryRefusalNotJustTheFirst(t *testing.T) {
	for position := range 3 {
		o := passingWriteInvocationObservation()
		o.Refusals = []writeRefusal{
			passingWriteRefusal("first"), passingWriteRefusal("second"), passingWriteRefusal("third"),
		}
		o.Refusals[position].Refused = false
		if o.qualifies() {
			t.Errorf("an observation qualified with refusal %d unrefused", position)
		}
	}
}
