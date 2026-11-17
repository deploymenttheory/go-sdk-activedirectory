//go:build windows && (amd64 || arm64)

package acceptance

import (
	"testing"

	admodel "github.com/deploymenttheory/go-sdk-activedirectory/activedirectory/internal/model"
)

func InternalPassingRenameRDNObservation() InternalRenameRDNObservation {
	return InternalRenameRDNObservation{
		BeforeDN:   "CN=sdkrn-before,OU=sdk-rename-x,DC=ad,DC=sdk,DC=test",
		AfterDN:    "CN=sdkrn-after,OU=sdk-rename-x,DC=ad,DC=sdk,DC=test",
		GUIDStable: true, Verified: true, RDNChanged: true, ParentKept: true,
		OldDNGone: true, NewDNFound: true, AttributesSurvived: true,
		EscapedRoundTrip: true, ExoticRoundTrip: true,
		CollisionRefused: true, CollisionClass: admodel.ClassAlreadyExists.String(),
		CollisionNoChange: true,
	}
}

func TestRenameRDNObservationRequiresEveryHalf(t *testing.T) {
	if !InternalPassingRenameRDNObservation().InternalQualifies() {
		t.Fatal("the fully satisfied observation does not qualify")
	}
	for _, mutation := range []struct {
		InternalName  string
		InternalApply func(*InternalRenameRDNObservation)
	}{
		// The identity claim. Without this one the scenario is worthless: a
		// rename that changed the GUID would make a tracked resource look
		// deleted and a new one appear.
		{"the GUID survived the rename", func(o *InternalRenameRDNObservation) { o.GUIDStable = false }},
		{"the rename was verified", func(o *InternalRenameRDNObservation) { o.Verified = false }},
		{"the relative name changed", func(o *InternalRenameRDNObservation) { o.RDNChanged = false }},
		{"the parent did not change", func(o *InternalRenameRDNObservation) { o.ParentKept = false }},
		{"the old name stopped resolving", func(o *InternalRenameRDNObservation) { o.OldDNGone = false }},
		{"the new name resolves", func(o *InternalRenameRDNObservation) { o.NewDNFound = false }},
		{"an unrelated attribute survived", func(o *InternalRenameRDNObservation) { o.AttributesSurvived = false }},
		{"an escaped name round-tripped", func(o *InternalRenameRDNObservation) { o.EscapedRoundTrip = false }},
		{"a non-ASCII name round-tripped", func(o *InternalRenameRDNObservation) { o.ExoticRoundTrip = false }},
		{"a collision was refused", func(o *InternalRenameRDNObservation) { o.CollisionRefused = false }},
		{"the collision changed nothing", func(o *InternalRenameRDNObservation) { o.CollisionNoChange = false }},
	} {
		t.Run(mutation.InternalName, func(t *testing.T) {
			o := InternalPassingRenameRDNObservation()
			mutation.InternalApply(&o)
			if o.InternalQualifies() {
				t.Fatalf("the observation still qualified without %q", mutation.InternalName)
			}
		})
	}
}

// A collision must be reported as the name being taken. Any other class means
// the rename failed for a different reason and the collision rule was never
// exercised.
func TestRenameCollisionMustReportTheNameAsTaken(t *testing.T) {
	o := InternalPassingRenameRDNObservation()
	o.CollisionClass = admodel.ClassAlreadyExists.String()
	if !o.InternalQualifies() {
		t.Fatal("already-exists was not accepted for a collision")
	}
	for _, class := range []admodel.ErrorClass{admodel.ClassUnclassified, admodel.ClassInvalidRequest, admodel.ClassDenied, admodel.ClassUncertain, admodel.ClassConflict, admodel.ClassNotFound, admodel.ClassUnsupported, admodel.ClassUnverified, admodel.ClassIncomplete, admodel.ClassTransport} {
		o := InternalPassingRenameRDNObservation()
		o.CollisionClass = class.String()
		if o.InternalQualifies() {
			t.Errorf("a collision reported as %s was accepted", class)
		}
	}
}

func InternalPassingRenameIdentityObservation() InternalRenameIdentityObservation {
	return InternalRenameIdentityObservation{
		ByDN: true, ByGUID: true, RefusalsKept: true, ScopeNoWrite: true,
		SIDClass:     admodel.ClassInvalidRequest.String(),
		AccountClass: admodel.ClassInvalidRequest.String(),
		ScopeClass:   admodel.ClassInvalidRequest.String(),
	}
}

// The generic object path documents a distinguished name and a GUID. The other
// two forms must be refused rather than resolved by guesswork, which is the
// whole reason Identity carries an explicit form.
func TestRenameIdentityObservationRequiresEveryHalf(t *testing.T) {
	if !InternalPassingRenameIdentityObservation().InternalQualifies() {
		t.Fatal("the fully satisfied observation does not qualify")
	}
	for _, mutation := range []struct {
		InternalName  string
		InternalApply func(*InternalRenameIdentityObservation)
	}{
		{"a distinguished name resolved", func(o *InternalRenameIdentityObservation) { o.ByDN = false }},
		{"a GUID resolved", func(o *InternalRenameIdentityObservation) { o.ByGUID = false }},
		{"every undocumented form was refused", func(o *InternalRenameIdentityObservation) { o.RefusalsKept = false }},
		{"the out-of-scope attempt wrote nothing", func(o *InternalRenameIdentityObservation) { o.ScopeNoWrite = false }},
		{"the security-identifier form was refused as a request", func(o *InternalRenameIdentityObservation) {
			o.SIDClass = admodel.ClassNotFound.String()
		}},
		{"the account-name form was refused as a request", func(o *InternalRenameIdentityObservation) {
			o.AccountClass = admodel.ClassDenied.String()
		}},
		{"the out-of-scope refusal was request-level", func(o *InternalRenameIdentityObservation) {
			o.ScopeClass = admodel.ClassUncertain.String()
		}},
	} {
		t.Run(mutation.InternalName, func(t *testing.T) {
			o := InternalPassingRenameIdentityObservation()
			mutation.InternalApply(&o)
			if o.InternalQualifies() {
				t.Fatalf("the observation still qualified without %q", mutation.InternalName)
			}
		})
	}
}
