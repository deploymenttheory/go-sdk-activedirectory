package activedirectory

import (
	"errors"
	"testing"
)

// verifyObjectWrite answers two different questions with one result, and before
// this split it gave them one answer. "The readback disagreed with what was
// asked for" means the directory may not hold the change. "No readback could
// settle this" means it does and only the proof is missing.
//
// Both leave Verified false. Only the first is uncertain, and conflating them
// made every successful attribute clear report as uncertain — so the one
// predicate a caller cannot afford to ignore fired on the happy path.

func unverifiableTestObject(attributes map[string][][]byte) *Object {
	return &Object{DistinguishedName: "CN=sample,DC=example", Attributes: attributes,
		RequestedProperties: []string{"description", "otherTelephone"}}
}

func unverifiableTestResult(attributes map[string][][]byte) *ObjectMutationResult {
	return &ObjectMutationResult{
		State: ObjectWriteAccepted, ReadbackComplete: true,
		After: unverifiableTestObject(attributes),
	}
}

func TestVerifyObjectWriteSeparatesUnprovableFromContradicted(t *testing.T) {
	const attribute = "description"
	clear := ldapAttributeModification{attribute: attribute, operation: 1}
	remove := ldapAttributeModification{attribute: attribute, operation: 1,
		values: [][]byte{[]byte("gone")}}
	set := ldapAttributeModification{attribute: attribute, operation: 2,
		values: [][]byte{[]byte("wanted")}}

	for _, test := range []struct {
		name       string
		mods       []ldapAttributeModification
		attributes map[string][][]byte
		want       error
		verified   bool
		why        string
	}{
		{
			name:       "a clear whose attribute came back absent is unprovable",
			mods:       []ldapAttributeModification{clear},
			attributes: map[string][][]byte{},
			want:       ErrObjectUnverifiable,
			why:        "absence is what success looks like and equally what denied visibility looks like",
		},
		{
			name:       "a clear whose attribute came back present is contradicted",
			mods:       []ldapAttributeModification{clear},
			attributes: map[string][][]byte{attribute: {[]byte("still here")}},
			want:       ErrObjectVerification,
			why:        "emptiness was requested and a value came back; that is a disagreement",
		},
		{
			name:       "a remove whose attribute came back absent is unprovable",
			mods:       []ldapAttributeModification{remove},
			attributes: map[string][][]byte{},
			want:       ErrObjectUnverifiable,
			why:        "an emptied attribute is indistinguishable from an unreadable one",
		},
		{
			name:       "a remove whose value is gone from a present attribute verifies",
			mods:       []ldapAttributeModification{remove},
			attributes: map[string][][]byte{attribute: {[]byte("kept")}},
			want:       nil, verified: true,
			why: "the attribute is readable and the value is absent from it",
		},
		{
			name:       "a remove whose value is still there is contradicted",
			mods:       []ldapAttributeModification{remove},
			attributes: map[string][][]byte{attribute: {[]byte("gone")}},
			want:       ErrObjectVerification,
			why:        "the value was asked to go and did not",
		},
		{
			name:       "a set whose attribute came back absent is contradicted, not unprovable",
			mods:       []ldapAttributeModification{set},
			attributes: map[string][][]byte{},
			want:       ErrObjectVerification,
			why:        "a value was asked for; absence cannot be success here",
		},
		{
			name:       "a set that came back verifies",
			mods:       []ldapAttributeModification{set},
			attributes: map[string][][]byte{attribute: {[]byte("wanted")}},
			want:       nil, verified: true,
			why: "the requested value is the returned value",
		},
	} {
		t.Run(test.name, func(t *testing.T) {
			result := unverifiableTestResult(test.attributes)
			err := verifyObjectWrite(result, test.mods, "")
			switch {
			case test.want == nil && err != nil:
				t.Fatalf("got %v, want success: %s", err, test.why)
			case test.want != nil && !errors.Is(err, test.want):
				t.Fatalf("got %v, want %v: %s", err, test.want, test.why)
			}
			if result.Verified != test.verified {
				t.Errorf("Verified = %v, want %v", result.Verified, test.verified)
			}
		})
	}
}

// A contradiction anywhere in the request outranks an unprovable change
// elsewhere in it. Reporting the weaker outcome would tell a caller the
// directory holds a change it may not.
func TestVerifyObjectWritePrefersTheContradictionWhenBothOccur(t *testing.T) {
	mods := []ldapAttributeModification{
		{attribute: "description", operation: 1},                                        // a clear: unprovable
		{attribute: "otherTelephone", operation: 2, values: [][]byte{[]byte("wanted")}}, // contradicted
	}
	result := unverifiableTestResult(map[string][][]byte{})
	err := verifyObjectWrite(result, mods, "")
	if !errors.Is(err, ErrObjectVerification) {
		t.Fatalf("got %v, want the contradiction to win", err)
	}
	if errors.Is(err, ErrObjectUnverifiable) {
		t.Error("the unprovable change masked a real disagreement")
	}
	if Classify(err) != ClassUncertain {
		t.Errorf("Classify = %s, want uncertain", Classify(err))
	}
}

// The two sentinels must stay distinct under errors.Is. If the new one wrapped
// the old, precedence would put uncertain first and the whole split would be
// undone while still looking correct.
func TestUnverifiableAndVerificationAreDistinct(t *testing.T) {
	if errors.Is(ErrObjectUnverifiable, ErrObjectVerification) {
		t.Error("ErrObjectUnverifiable wraps ErrObjectVerification, so uncertain would win on precedence")
	}
	if errors.Is(ErrObjectVerification, ErrObjectUnverifiable) {
		t.Error("ErrObjectVerification wraps ErrObjectUnverifiable")
	}
	if Classify(ErrObjectUnverifiable) != ClassUnverified {
		t.Errorf("ErrObjectUnverifiable classifies as %s", Classify(ErrObjectUnverifiable))
	}
	if Classify(ErrObjectVerification) != ClassUncertain {
		t.Errorf("ErrObjectVerification classifies as %s", Classify(ErrObjectVerification))
	}
	// The whole point: a clear no longer trips the predicate a caller uses to
	// decide whether its state is trustworthy.
	if IsUncertain(ErrObjectUnverifiable) {
		t.Error("an unprovable write still reports as uncertain")
	}
	if !IsUnverified(ErrObjectUnverifiable) {
		t.Error("an unprovable write does not report as unverified")
	}
}

// Precedence is a safety claim here too: an unprovable write must not mask any
// class that says the directory might not hold the change.
func TestUnverifiedYieldsToEveryWorseOutcome(t *testing.T) {
	for _, test := range []struct {
		name string
		err  error
		want ErrorClass
	}{
		{"uncertain wins", errors.Join(ErrObjectUnverifiable, ErrObjectWriteUncertain), ClassUncertain},
		{"denied wins", errors.Join(ErrObjectUnverifiable, ErrObjectWritePermission), ClassDenied},
		{"conflict wins", errors.Join(ErrObjectUnverifiable, ErrObjectConcurrency), ClassConflict},
		{"unverified beats a short read", errors.Join(ErrObjectUnverifiable, ErrIncompleteResult), ClassUnverified},
		{"unverified beats an invalid request", errors.Join(ErrObjectUnverifiable, ErrInvalidProperty), ClassUnverified},
	} {
		t.Run(test.name, func(t *testing.T) {
			if got := Classify(test.err); got != test.want {
				t.Fatalf("Classify = %s, want %s", got, test.want)
			}
		})
	}
}
