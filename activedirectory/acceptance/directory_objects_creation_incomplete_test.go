package acceptance

import (
	"errors"
	"testing"

	admodel "github.com/deploymenttheory/go-sdk-activedirectory/activedirectory/internal/model"
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
	duplicate := errors.Join(
		admodel.ErrObjectAlreadyExists,
		&admodel.LDAPError{Operation: "LDAP add", Code: 68},
	)
	for _, test := range []struct {
		InternalName  string
		InternalState admodel.ObjectWriteState
		InternalCause error
		InternalWant  admodel.ErrorClass
		InternalJoins bool
		InternalWhy   string
	}{
		{
			InternalName:  "a rejected first write passes its own class through",
			InternalState: admodel.ObjectWriteRejected, InternalCause: duplicate,
			InternalWant: admodel.ClassAlreadyExists, InternalJoins: false,
			InternalWhy: "nothing was written, so a caller may adopt the existing object",
		},
		{
			InternalName:  "a never-attempted write passes through",
			InternalState: admodel.ObjectWriteNotAttempted, InternalCause: admodel.ErrObjectWriteTarget,
			InternalWant: admodel.ClassUnsupported, InternalJoins: false,
			InternalWhy: "no request reached the directory",
		},
		{
			InternalName:  "a refused first write stays a refusal",
			InternalState: admodel.ObjectWriteRejected, InternalCause: admodel.ErrObjectWritePermission,
			InternalWant: admodel.ClassDenied, InternalJoins: false,
			InternalWhy: "a denial with nothing written is not an unfinished object",
		},
		{
			InternalName:  "an accepted write that then failed is incomplete",
			InternalState: admodel.ObjectWriteAccepted, InternalCause: admodel.ErrObjectReadback,
			InternalWant: admodel.ClassUncertain, InternalJoins: true,
			InternalWhy: "the object exists and its shape is unknown",
		},
		{
			InternalName:  "an uncertain write is incomplete",
			InternalState: admodel.ObjectWriteUncertain, InternalCause: admodel.ErrObjectWriteUncertain,
			InternalWant: admodel.ClassUncertain, InternalJoins: true,
			InternalWhy: "the write may have landed",
		},
	} {
		t.Run(test.InternalName, func(t *testing.T) {
			creation := admodel.ObjectMutationResult{State: test.InternalState}
			got := admodel.InternalCreationIncomplete(
				admodel.ErrUserCreationIncomplete,
				creation,
				test.InternalCause,
			)
			if errors.Is(got, admodel.ErrUserCreationIncomplete) != test.InternalJoins {
				t.Errorf("stage-incomplete joined = %v, want %v: %s",
					!test.InternalJoins, test.InternalJoins, test.InternalWhy)
			}
			if class := admodel.Classify(got); class != test.InternalWant {
				t.Errorf("Classify = %s, want %s: %s", class, test.InternalWant, test.InternalWhy)
			}
			// The originating failure must survive either way.
			if !errors.Is(got, test.InternalCause) &&
				!errors.Is(got, errors.Unwrap(test.InternalCause)) {
				t.Errorf("the cause was lost from %v", got)
			}
		})
	}
}

// A successful create must not acquire a sentinel from this helper.
func TestCreationIncompleteIgnoresSuccess(t *testing.T) {
	for _, state := range []admodel.ObjectWriteState{admodel.ObjectWriteNotAttempted, admodel.ObjectWriteAccepted, admodel.ObjectWriteRejected, admodel.ObjectWriteUncertain} {
		if got := admodel.InternalCreationIncomplete(
			admodel.ErrUserCreationIncomplete,
			admodel.ObjectMutationResult{State: state},
			nil,
		); got != nil {
			t.Errorf("state %d turned a success into %v", state, got)
		}
	}
}

// All three multi-stage creation paths share the helper, so the sentinel they
// pass must behave identically. A path that kept its own inline join would
// drift back to masking its first-stage failures.
func TestCreationIncompleteAppliesToEveryStagedCreate(t *testing.T) {
	duplicate := errors.Join(
		admodel.ErrObjectAlreadyExists,
		&admodel.LDAPError{Operation: "LDAP add", Code: 68},
	)
	for _, sentinel := range []error{admodel.ErrUserCreationIncomplete, admodel.ErrComputerCreationIncomplete, admodel.ErrServiceAccountCreationIncomplete} {
		rejected := admodel.InternalCreationIncomplete(
			sentinel,
			admodel.ObjectMutationResult{State: admodel.ObjectWriteRejected},
			duplicate,
		)
		if !admodel.IsAlreadyExists(rejected) {
			t.Errorf("%v masked a clean duplicate-name rejection: %v", sentinel, rejected)
		}
		accepted := admodel.InternalCreationIncomplete(
			sentinel,
			admodel.ObjectMutationResult{State: admodel.ObjectWriteAccepted},
			admodel.ErrObjectReadback,
		)
		if !admodel.IsUncertain(accepted) || !errors.Is(accepted, sentinel) {
			t.Errorf("%v did not report an accepted-then-failed create as incomplete", sentinel)
		}
	}
}
