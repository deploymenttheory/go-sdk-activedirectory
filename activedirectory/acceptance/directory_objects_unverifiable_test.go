package acceptance

import (
	"errors"
	"testing"

	admodel "github.com/deploymenttheory/go-sdk-activedirectory/activedirectory/internal/model"
)

// verifyObjectWrite answers two different questions with one result, and before
// this split it gave them one answer. "The readback disagreed with what was
// asked for" means the directory may not hold the change. "No readback could
// settle this" means it does and only the proof is missing.
//
// Both leave Verified false. Only the first is uncertain, and conflating them
// made every successful attribute clear report as uncertain — so the one
// predicate a caller cannot afford to ignore fired on the happy path.

func InternalUnverifiableTestObject(attributes map[string][][]byte) *admodel.Object {
	return &admodel.Object{
		DistinguishedName: "CN=sample,DC=example", Attributes: attributes,
		RequestedProperties: []string{"description", "otherTelephone"},
	}
}

func InternalUnverifiableTestResult(attributes map[string][][]byte) *admodel.ObjectMutationResult {
	return &admodel.ObjectMutationResult{
		State: admodel.ObjectWriteAccepted, ReadbackComplete: true,
		After: InternalUnverifiableTestObject(attributes),
	}
}

func TestVerifyObjectWriteSeparatesUnprovableFromContradicted(t *testing.T) {
	const attribute = "description"
	clear := admodel.InternalLdapAttributeModification{
		InternalAttribute: attribute,
		InternalOperation: 1,
	}
	remove := admodel.InternalLdapAttributeModification{
		InternalAttribute: attribute, InternalOperation: 1,
		InternalValues: [][]byte{[]byte("gone")},
	}
	set := admodel.InternalLdapAttributeModification{
		InternalAttribute: attribute, InternalOperation: 2,
		InternalValues: [][]byte{[]byte("wanted")},
	}

	for _, test := range []struct {
		InternalName       string
		InternalMods       []admodel.InternalLdapAttributeModification
		InternalAttributes map[string][][]byte
		InternalWant       error
		InternalVerified   bool
		InternalWhy        string
	}{
		{
			InternalName:       "a clear whose attribute came back absent is unprovable",
			InternalMods:       []admodel.InternalLdapAttributeModification{clear},
			InternalAttributes: map[string][][]byte{},
			InternalWant:       admodel.ErrObjectUnverifiable,
			InternalWhy:        "absence is what success looks like and equally what denied visibility looks like",
		},
		{
			InternalName:       "a clear whose attribute came back present is contradicted",
			InternalMods:       []admodel.InternalLdapAttributeModification{clear},
			InternalAttributes: map[string][][]byte{attribute: {[]byte("still here")}},
			InternalWant:       admodel.ErrObjectVerification,
			InternalWhy:        "emptiness was requested and a value came back; that is a disagreement",
		},
		{
			InternalName:       "a remove whose attribute came back absent is unprovable",
			InternalMods:       []admodel.InternalLdapAttributeModification{remove},
			InternalAttributes: map[string][][]byte{},
			InternalWant:       admodel.ErrObjectUnverifiable,
			InternalWhy:        "an emptied attribute is indistinguishable from an unreadable one",
		},
		{
			InternalName:       "a remove whose value is gone from a present attribute verifies",
			InternalMods:       []admodel.InternalLdapAttributeModification{remove},
			InternalAttributes: map[string][][]byte{attribute: {[]byte("kept")}},
			InternalWant:       nil, InternalVerified: true,
			InternalWhy: "the attribute is readable and the value is absent from it",
		},
		{
			InternalName:       "a remove whose value is still there is contradicted",
			InternalMods:       []admodel.InternalLdapAttributeModification{remove},
			InternalAttributes: map[string][][]byte{attribute: {[]byte("gone")}},
			InternalWant:       admodel.ErrObjectVerification,
			InternalWhy:        "the value was asked to go and did not",
		},
		{
			InternalName:       "a set whose attribute came back absent is contradicted, not unprovable",
			InternalMods:       []admodel.InternalLdapAttributeModification{set},
			InternalAttributes: map[string][][]byte{},
			InternalWant:       admodel.ErrObjectVerification,
			InternalWhy:        "a value was asked for; absence cannot be success here",
		},
		{
			InternalName:       "a set that came back verifies",
			InternalMods:       []admodel.InternalLdapAttributeModification{set},
			InternalAttributes: map[string][][]byte{attribute: {[]byte("wanted")}},
			InternalWant:       nil, InternalVerified: true,
			InternalWhy: "the requested value is the returned value",
		},
	} {
		t.Run(test.InternalName, func(t *testing.T) {
			result := InternalUnverifiableTestResult(test.InternalAttributes)
			err := admodel.InternalVerifyObjectWrite(result, test.InternalMods, "")
			switch {
			case test.InternalWant == nil && err != nil:
				t.Fatalf("got %v, want success: %s", err, test.InternalWhy)
			case test.InternalWant != nil && !errors.Is(err, test.InternalWant):
				t.Fatalf("got %v, want %v: %s", err, test.InternalWant, test.InternalWhy)
			}
			if result.Verified != test.InternalVerified {
				t.Errorf("Verified = %v, want %v", result.Verified, test.InternalVerified)
			}
		})
	}
}

// A contradiction anywhere in the request outranks an unprovable change
// elsewhere in it. Reporting the weaker outcome would tell a caller the
// directory holds a change it may not.
func TestVerifyObjectWritePrefersTheContradictionWhenBothOccur(t *testing.T) {
	mods := []admodel.InternalLdapAttributeModification{
		{
			InternalAttribute: "description",
			InternalOperation: 1,
		}, // a clear: unprovable
		{
			InternalAttribute: "otherTelephone",
			InternalOperation: 2,
			InternalValues:    [][]byte{[]byte("wanted")},
		}, // contradicted
	}
	result := InternalUnverifiableTestResult(map[string][][]byte{})
	err := admodel.InternalVerifyObjectWrite(result, mods, "")
	if !errors.Is(err, admodel.ErrObjectVerification) {
		t.Fatalf("got %v, want the contradiction to win", err)
	}
	if errors.Is(err, admodel.ErrObjectUnverifiable) {
		t.Error("the unprovable change masked a real disagreement")
	}
	if admodel.Classify(err) != admodel.ClassUncertain {
		t.Errorf("Classify = %s, want uncertain", admodel.Classify(err))
	}
}

// The two sentinels must stay distinct under errors.Is. If the new one wrapped
// the old, precedence would put uncertain first and the whole split would be
// undone while still looking correct.
func TestUnverifiableAndVerificationAreDistinct(t *testing.T) {
	if errors.Is(admodel.ErrObjectUnverifiable, admodel.ErrObjectVerification) {
		t.Error(
			"ErrObjectUnverifiable wraps ErrObjectVerification, so uncertain would win on precedence",
		)
	}
	if errors.Is(admodel.ErrObjectVerification, admodel.ErrObjectUnverifiable) {
		t.Error("ErrObjectVerification wraps ErrObjectUnverifiable")
	}
	if admodel.Classify(admodel.ErrObjectUnverifiable) != admodel.ClassUnverified {
		t.Errorf(
			"ErrObjectUnverifiable classifies as %s",
			admodel.Classify(admodel.ErrObjectUnverifiable),
		)
	}
	if admodel.Classify(admodel.ErrObjectVerification) != admodel.ClassUncertain {
		t.Errorf(
			"ErrObjectVerification classifies as %s",
			admodel.Classify(admodel.ErrObjectVerification),
		)
	}
	// The whole point: a clear no longer trips the predicate a caller uses to
	// decide whether its state is trustworthy.
	if admodel.IsUncertain(admodel.ErrObjectUnverifiable) {
		t.Error("an unprovable write still reports as uncertain")
	}
	if !admodel.IsUnverified(admodel.ErrObjectUnverifiable) {
		t.Error("an unprovable write does not report as unverified")
	}
}

// Precedence is a safety claim here too: an unprovable write must not mask any
// class that says the directory might not hold the change.
func TestUnverifiedYieldsToEveryWorseOutcome(t *testing.T) {
	for _, test := range []struct {
		InternalName string
		InternalErr  error
		InternalWant admodel.ErrorClass
	}{
		{"uncertain wins", errors.Join(admodel.ErrObjectUnverifiable, admodel.ErrObjectWriteUncertain), admodel.ClassUncertain},
		{"denied wins", errors.Join(admodel.ErrObjectUnverifiable, admodel.ErrObjectWritePermission), admodel.ClassDenied},
		{"conflict wins", errors.Join(admodel.ErrObjectUnverifiable, admodel.ErrObjectConcurrency), admodel.ClassConflict},
		{"unverified beats a short read", errors.Join(admodel.ErrObjectUnverifiable, admodel.ErrIncompleteResult), admodel.ClassUnverified},
		{"unverified beats an invalid request", errors.Join(admodel.ErrObjectUnverifiable, admodel.ErrInvalidProperty), admodel.ClassUnverified},
	} {
		t.Run(test.InternalName, func(t *testing.T) {
			if got := admodel.Classify(test.InternalErr); got != test.InternalWant {
				t.Fatalf("Classify = %s, want %s", got, test.InternalWant)
			}
		})
	}
}
