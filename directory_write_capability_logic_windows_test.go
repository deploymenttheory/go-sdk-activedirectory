//go:build windows && (amd64 || arm64)

package activedirectory

import (
	"errors"
	"testing"
)

// The write-capability sweep's decision logic runs only inside the lab. Its
// riskiest part is the prerequisite determination: a refusal for the wrong
// reason, credited as a capability refusal, would turn an unrelated failure
// into evidence.

func passingWriteCapabilityObservation() writeCapabilityObservation {
	return writeCapabilityObservation{
		Cmdlet: "New-ADComputer", Role: writeRoleCreate,
		HasPrerequisite: true, UnsupportedKind: "DirectoryCapabilityError",
		UnsupportedClass: ClassUnsupported.String(),
		SupportedWrote:   true, RepeatedCalls: 3, NoReplay: true,
		NativeErrorAfter: true, AllocsSupported: 0, AllocsFailed: 0, CloseIdempotent: true,
	}
}

func TestWriteCapabilityObservationRequiresEveryHalf(t *testing.T) {
	if !passingWriteCapabilityObservation().qualifies() {
		t.Fatal("the fully satisfied observation does not qualify")
	}
	for _, mutation := range []struct {
		name  string
		apply func(*writeCapabilityObservation)
	}{
		{"a directory-type prerequisite was observed", func(o *writeCapabilityObservation) { o.HasPrerequisite = false }},
		{"the supported write succeeded", func(o *writeCapabilityObservation) { o.SupportedWrote = false }},
		{"three repeated calls completed", func(o *writeCapabilityObservation) { o.RepeatedCalls = 2 }},
		{"no submission was replayed", func(o *writeCapabilityObservation) { o.NoReplay = false }},
		{"a native error was raised after resources", func(o *writeCapabilityObservation) { o.NativeErrorAfter = false }},
		{"allocations balanced on the success path", func(o *writeCapabilityObservation) { o.AllocsSupported = 1 }},
		{"allocations balanced on the failure path", func(o *writeCapabilityObservation) { o.AllocsFailed = 1 }},
		{"close was idempotent", func(o *writeCapabilityObservation) { o.CloseIdempotent = false }},
	} {
		t.Run(mutation.name, func(t *testing.T) {
			o := passingWriteCapabilityObservation()
			mutation.apply(&o)
			if o.qualifies() {
				t.Fatalf("the observation still qualified without %q", mutation.name)
			}
		})
	}
}

// Three is the minimum that distinguishes a reusable session from one that
// happened to survive a second call, so more is fine and fewer is not.
func TestWriteCapabilityNeedsThreeRepeatedCalls(t *testing.T) {
	for _, count := range []int{0, 1, 2} {
		o := passingWriteCapabilityObservation()
		o.RepeatedCalls = count
		if o.qualifies() {
			t.Errorf("%d repeated calls qualified", count)
		}
	}
	o := passingWriteCapabilityObservation()
	o.RepeatedCalls = 3
	if !o.qualifies() {
		t.Error("three repeated calls did not qualify")
	}
}

// This is the load-bearing judgement. Only an unmistakable directory-type
// refusal counts. A bare ErrUnsupported must not, because against a fixture
// that cannot answer a write it is equally what a missing write path produces
// — crediting it would manufacture evidence from an unrelated failure.
func TestWriteCapabilityKindCreditsOnlyUnmistakableRefusals(t *testing.T) {
	for _, test := range []struct {
		name string
		err  error
		want string
	}{
		{"a directory capability error", &DirectoryCapabilityError{Operation: "create", Required: DirectoryADDS}, "DirectoryCapabilityError"},
		{"the wrong directory type", ErrUnsupportedDirectory, "ErrUnsupportedDirectory"},
		{"a user property capability", ErrUserCapability, "ErrUserCapability"},
		{"a bare unsupported", ErrUnsupported, ""},
		{"a transport failure", ErrClosed, ""},
		{"an invalid request", ErrInvalidIdentity, ""},
		{"a denial", ErrObjectWritePermission, ""},
		{"no error at all", nil, ""},
	} {
		t.Run(test.name, func(t *testing.T) {
			if got := writeCapabilityKind(test.err); got != test.want {
				t.Fatalf("writeCapabilityKind = %q, want %q", got, test.want)
			}
		})
	}
	// Wrapped still counts: the refusal travels through the mutation paths.
	wrapped := errors.Join(ErrObjectWriteTarget, ErrUserCapability)
	if writeCapabilityKind(wrapped) != "ErrUserCapability" {
		t.Error("a joined capability refusal was not recognised")
	}
}

// An operation with no prerequisite must not qualify, however complete its
// resource-lifetime halves are. It is recorded and excluded, not passed.
func TestWriteCapabilityExcludesRatherThanPassesWithoutAPrerequisite(t *testing.T) {
	o := passingWriteCapabilityObservation()
	o.HasPrerequisite = false
	o.UnsupportedKind = ""
	o.NoPrerequisiteWhy = "the call was not refused by a directory-type check"
	if o.qualifies() {
		t.Fatal("an operation with no prerequisite qualified on its lifetime halves alone")
	}
	if o.NoPrerequisiteWhy == "" {
		t.Fatal("the exclusion carries no stated reason")
	}
}
