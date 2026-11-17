//go:build windows && (amd64 || arm64)

package activedirectory

import "testing"

// The rename sweep's decision logic runs only inside the lab. Its central claim
// is that a rename keeps the object's identity, so a permissive aggregation
// here would turn the artifact into a statement that anything tracking a
// renamed resource is safe when it is not.

func passingRenameRDNObservation() renameRDNObservation {
	return renameRDNObservation{
		BeforeDN:   "CN=sdkrn-before,OU=sdk-rename-x,DC=ad,DC=sdk,DC=test",
		AfterDN:    "CN=sdkrn-after,OU=sdk-rename-x,DC=ad,DC=sdk,DC=test",
		GUIDStable: true, Verified: true, RDNChanged: true, ParentKept: true,
		OldDNGone: true, NewDNFound: true, AttributesSurvived: true,
		EscapedRoundTrip: true, ExoticRoundTrip: true,
		CollisionRefused: true, CollisionClass: ClassAlreadyExists.String(),
		CollisionNoChange: true,
	}
}

func TestRenameRDNObservationRequiresEveryHalf(t *testing.T) {
	if !passingRenameRDNObservation().qualifies() {
		t.Fatal("the fully satisfied observation does not qualify")
	}
	for _, mutation := range []struct {
		name  string
		apply func(*renameRDNObservation)
	}{
		// The identity claim. Without this one the scenario is worthless: a
		// rename that changed the GUID would make a tracked resource look
		// deleted and a new one appear.
		{"the GUID survived the rename", func(o *renameRDNObservation) { o.GUIDStable = false }},
		{"the rename was verified", func(o *renameRDNObservation) { o.Verified = false }},
		{"the relative name changed", func(o *renameRDNObservation) { o.RDNChanged = false }},
		{"the parent did not change", func(o *renameRDNObservation) { o.ParentKept = false }},
		{"the old name stopped resolving", func(o *renameRDNObservation) { o.OldDNGone = false }},
		{"the new name resolves", func(o *renameRDNObservation) { o.NewDNFound = false }},
		{"an unrelated attribute survived", func(o *renameRDNObservation) { o.AttributesSurvived = false }},
		{"an escaped name round-tripped", func(o *renameRDNObservation) { o.EscapedRoundTrip = false }},
		{"a non-ASCII name round-tripped", func(o *renameRDNObservation) { o.ExoticRoundTrip = false }},
		{"a collision was refused", func(o *renameRDNObservation) { o.CollisionRefused = false }},
		{"the collision changed nothing", func(o *renameRDNObservation) { o.CollisionNoChange = false }},
	} {
		t.Run(mutation.name, func(t *testing.T) {
			o := passingRenameRDNObservation()
			mutation.apply(&o)
			if o.qualifies() {
				t.Fatalf("the observation still qualified without %q", mutation.name)
			}
		})
	}
}

// A collision must be reported as the name being taken. Any other class means
// the rename failed for a different reason and the collision rule was never
// exercised.
func TestRenameCollisionMustReportTheNameAsTaken(t *testing.T) {
	o := passingRenameRDNObservation()
	o.CollisionClass = ClassAlreadyExists.String()
	if !o.qualifies() {
		t.Fatal("already-exists was not accepted for a collision")
	}
	for _, class := range []ErrorClass{
		ClassUnclassified, ClassInvalidRequest, ClassDenied, ClassUncertain,
		ClassConflict, ClassNotFound, ClassUnsupported, ClassUnverified,
		ClassIncomplete, ClassTransport,
	} {
		o := passingRenameRDNObservation()
		o.CollisionClass = class.String()
		if o.qualifies() {
			t.Errorf("a collision reported as %s was accepted", class)
		}
	}
}

func passingRenameIdentityObservation() renameIdentityObservation {
	return renameIdentityObservation{
		ByDN: true, ByGUID: true, RefusalsKept: true, ScopeNoWrite: true,
		SIDClass:     ClassInvalidRequest.String(),
		AccountClass: ClassInvalidRequest.String(),
		ScopeClass:   ClassInvalidRequest.String(),
	}
}

// The generic object path documents a distinguished name and a GUID. The other
// two forms must be refused rather than resolved by guesswork, which is the
// whole reason Identity carries an explicit form.
func TestRenameIdentityObservationRequiresEveryHalf(t *testing.T) {
	if !passingRenameIdentityObservation().qualifies() {
		t.Fatal("the fully satisfied observation does not qualify")
	}
	for _, mutation := range []struct {
		name  string
		apply func(*renameIdentityObservation)
	}{
		{"a distinguished name resolved", func(o *renameIdentityObservation) { o.ByDN = false }},
		{"a GUID resolved", func(o *renameIdentityObservation) { o.ByGUID = false }},
		{"every undocumented form was refused", func(o *renameIdentityObservation) { o.RefusalsKept = false }},
		{"the out-of-scope attempt wrote nothing", func(o *renameIdentityObservation) { o.ScopeNoWrite = false }},
		{"the security-identifier form was refused as a request", func(o *renameIdentityObservation) {
			o.SIDClass = ClassNotFound.String()
		}},
		{"the account-name form was refused as a request", func(o *renameIdentityObservation) {
			o.AccountClass = ClassDenied.String()
		}},
		{"the out-of-scope refusal was request-level", func(o *renameIdentityObservation) {
			o.ScopeClass = ClassUncertain.String()
		}},
	} {
		t.Run(mutation.name, func(t *testing.T) {
			o := passingRenameIdentityObservation()
			mutation.apply(&o)
			if o.qualifies() {
				t.Fatalf("the observation still qualified without %q", mutation.name)
			}
		})
	}
}
