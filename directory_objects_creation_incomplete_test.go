package activedirectory

import (
	"errors"
	"testing"
)

// A multi-stage create reports partial completion so a caller knows an object
// may exist in an unfinished shape, and those sentinels classify as uncertain.
// The first stage failing cleanly is not partial completion, and reporting it
// as such hid the one thing a caller most needs from a failed create: that the
// object is already there and can be adopted.
//
// Measured live before this fix: a duplicate name classified as already-exists
// through the group, organizational-unit and generic-object paths, and as
// uncertain through the user and computer paths, for the identical condition.
func TestCreationIncompleteOnlyWhenSomethingLanded(t *testing.T) {
	duplicate := errors.Join(ErrObjectAlreadyExists, &LDAPError{Operation: "LDAP add", Code: 68})
	for _, test := range []struct {
		name  string
		state ObjectWriteState
		cause error
		want  ErrorClass
		joins bool
		why   string
	}{
		{
			name:  "a rejected first write passes its own class through",
			state: ObjectWriteRejected, cause: duplicate,
			want: ClassAlreadyExists, joins: false,
			why: "nothing was written, so a caller may adopt the existing object",
		},
		{
			name:  "a never-attempted write passes through",
			state: ObjectWriteNotAttempted, cause: ErrObjectWriteTarget,
			want: ClassUnsupported, joins: false,
			why: "no request reached the directory",
		},
		{
			name:  "a refused first write stays a refusal",
			state: ObjectWriteRejected, cause: ErrObjectWritePermission,
			want: ClassDenied, joins: false,
			why: "a denial with nothing written is not an unfinished object",
		},
		{
			name:  "an accepted write that then failed is incomplete",
			state: ObjectWriteAccepted, cause: ErrObjectReadback,
			want: ClassUncertain, joins: true,
			why: "the object exists and its shape is unknown",
		},
		{
			name:  "an uncertain write is incomplete",
			state: ObjectWriteUncertain, cause: ErrObjectWriteUncertain,
			want: ClassUncertain, joins: true,
			why: "the write may have landed",
		},
	} {
		t.Run(test.name, func(t *testing.T) {
			creation := ObjectMutationResult{State: test.state}
			got := creationIncomplete(ErrUserCreationIncomplete, creation, test.cause)
			if errors.Is(got, ErrUserCreationIncomplete) != test.joins {
				t.Errorf("stage-incomplete joined = %v, want %v: %s",
					!test.joins, test.joins, test.why)
			}
			if class := Classify(got); class != test.want {
				t.Errorf("Classify = %s, want %s: %s", class, test.want, test.why)
			}
			// The originating failure must survive either way.
			if !errors.Is(got, test.cause) && !errors.Is(got, errors.Unwrap(test.cause)) {
				t.Errorf("the cause was lost from %v", got)
			}
		})
	}
}

// A successful create must not acquire a sentinel from this helper.
func TestCreationIncompleteIgnoresSuccess(t *testing.T) {
	for _, state := range []ObjectWriteState{
		ObjectWriteNotAttempted, ObjectWriteAccepted, ObjectWriteRejected, ObjectWriteUncertain,
	} {
		if got := creationIncomplete(ErrUserCreationIncomplete, ObjectMutationResult{State: state}, nil); got != nil {
			t.Errorf("state %d turned a success into %v", state, got)
		}
	}
}

// All three multi-stage creation paths share the helper, so the sentinel they
// pass must behave identically. A path that kept its own inline join would
// drift back to masking its first-stage failures.
func TestCreationIncompleteAppliesToEveryStagedCreate(t *testing.T) {
	duplicate := errors.Join(ErrObjectAlreadyExists, &LDAPError{Operation: "LDAP add", Code: 68})
	for _, sentinel := range []error{
		ErrUserCreationIncomplete, ErrComputerCreationIncomplete, ErrServiceAccountCreationIncomplete,
	} {
		rejected := creationIncomplete(sentinel, ObjectMutationResult{State: ObjectWriteRejected}, duplicate)
		if !IsAlreadyExists(rejected) {
			t.Errorf("%v masked a clean duplicate-name rejection: %v", sentinel, rejected)
		}
		accepted := creationIncomplete(sentinel, ObjectMutationResult{State: ObjectWriteAccepted}, ErrObjectReadback)
		if !IsUncertain(accepted) || !errors.Is(accepted, sentinel) {
			t.Errorf("%v did not report an accepted-then-failed create as incomplete", sentinel)
		}
	}
}
