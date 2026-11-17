//go:build windows && (amd64 || arm64)

package acceptance

import (
	"errors"
	"testing"

	admodel "github.com/deploymenttheory/go-sdk-activedirectory/activedirectory/internal/model"
)

// The write-capability sweep's decision logic runs only inside the lab. Its
// riskiest part is the prerequisite determination: a refusal for the wrong
// reason, credited as a capability refusal, would turn an unrelated failure
// into evidence.

func InternalPassingWriteCapabilityObservation() InternalWriteCapabilityObservation {
	return InternalWriteCapabilityObservation{
		Cmdlet: "New-ADComputer", Role: InternalWriteRoleCreate,
		HasPrerequisite: true, UnsupportedKind: "DirectoryCapabilityError",
		UnsupportedClass: admodel.ClassUnsupported.String(),
		SupportedWrote:   true, RepeatedCalls: 3, NoReplay: true,
		NativeErrorAfter: true, AllocsSupported: 0, AllocsFailed: 0, CloseIdempotent: true,
	}
}

func TestWriteCapabilityObservationRequiresEveryHalf(t *testing.T) {
	if !InternalPassingWriteCapabilityObservation().InternalQualifies() {
		t.Fatal("the fully satisfied observation does not qualify")
	}
	for _, mutation := range []struct {
		InternalName  string
		InternalApply func(*InternalWriteCapabilityObservation)
	}{
		{"a directory-type prerequisite was observed", func(o *InternalWriteCapabilityObservation) { o.HasPrerequisite = false }},
		{"the supported write succeeded", func(o *InternalWriteCapabilityObservation) { o.SupportedWrote = false }},
		{"three repeated calls completed", func(o *InternalWriteCapabilityObservation) { o.RepeatedCalls = 2 }},
		{"no submission was replayed", func(o *InternalWriteCapabilityObservation) { o.NoReplay = false }},
		{"a native error was raised after resources", func(o *InternalWriteCapabilityObservation) { o.NativeErrorAfter = false }},
		{"allocations balanced on the success path", func(o *InternalWriteCapabilityObservation) { o.AllocsSupported = 1 }},
		{"allocations balanced on the failure path", func(o *InternalWriteCapabilityObservation) { o.AllocsFailed = 1 }},
		{"close was idempotent", func(o *InternalWriteCapabilityObservation) { o.CloseIdempotent = false }},
	} {
		t.Run(mutation.InternalName, func(t *testing.T) {
			o := InternalPassingWriteCapabilityObservation()
			mutation.InternalApply(&o)
			if o.InternalQualifies() {
				t.Fatalf("the observation still qualified without %q", mutation.InternalName)
			}
		})
	}
}

// Three is the minimum that distinguishes a reusable session from one that
// happened to survive a second call, so more is fine and fewer is not.
func TestWriteCapabilityNeedsThreeRepeatedCalls(t *testing.T) {
	for _, count := range []int{0, 1, 2} {
		o := InternalPassingWriteCapabilityObservation()
		o.RepeatedCalls = count
		if o.InternalQualifies() {
			t.Errorf("%d repeated calls qualified", count)
		}
	}
	o := InternalPassingWriteCapabilityObservation()
	o.RepeatedCalls = 3
	if !o.InternalQualifies() {
		t.Error("three repeated calls did not qualify")
	}
}

// This is the load-bearing judgement. Only an unmistakable directory-type
// refusal counts. A bare ErrUnsupported must not, because against a fixture
// that cannot answer a write it is equally what a missing write path produces
// — crediting it would manufacture evidence from an unrelated failure.
func TestWriteCapabilityKindCreditsOnlyUnmistakableRefusals(t *testing.T) {
	for _, test := range []struct {
		InternalName string
		InternalErr  error
		InternalWant string
	}{
		{"a directory capability error", &admodel.DirectoryCapabilityError{Operation: "create", Required: admodel.DirectoryADDS}, "DirectoryCapabilityError"},
		{"the wrong directory type", admodel.ErrUnsupportedDirectory, "ErrUnsupportedDirectory"},
		{"a user property capability", admodel.ErrUserCapability, "ErrUserCapability"},
		{"a bare unsupported", admodel.ErrUnsupported, ""},
		{"a transport failure", admodel.ErrClosed, ""},
		{"an invalid request", admodel.ErrInvalidIdentity, ""},
		{"a denial", admodel.ErrObjectWritePermission, ""},
		{"no error at all", nil, ""},
	} {
		t.Run(test.InternalName, func(t *testing.T) {
			if got := InternalWriteCapabilityKind(test.InternalErr); got != test.InternalWant {
				t.Fatalf("writeCapabilityKind = %q, want %q", got, test.InternalWant)
			}
		})
	}
	// Wrapped still counts: the refusal travels through the mutation paths.
	wrapped := errors.Join(admodel.ErrObjectWriteTarget, admodel.ErrUserCapability)
	if InternalWriteCapabilityKind(wrapped) != "ErrUserCapability" {
		t.Error("a joined capability refusal was not recognised")
	}
}

// An operation with no prerequisite must not qualify, however complete its
// resource-lifetime halves are. It is recorded and excluded, not passed.
func TestWriteCapabilityExcludesRatherThanPassesWithoutAPrerequisite(t *testing.T) {
	o := InternalPassingWriteCapabilityObservation()
	o.HasPrerequisite = false
	o.UnsupportedKind = ""
	o.NoPrerequisiteWhy = "the call was not refused by a directory-type check"
	if o.InternalQualifies() {
		t.Fatal("an operation with no prerequisite qualified on its lifetime halves alone")
	}
	if o.NoPrerequisiteWhy == "" {
		t.Fatal("the exclusion carries no stated reason")
	}
}
