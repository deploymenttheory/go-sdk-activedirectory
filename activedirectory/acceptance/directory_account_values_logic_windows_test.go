//go:build windows && (amd64 || arm64)

package acceptance

import (
	"testing"

	admodel "github.com/deploymenttheory/go-sdk-activedirectory/activedirectory/internal/model"
)

func InternalPassingExpirationCreate() InternalExpirationObservation {
	return InternalExpirationObservation{
		Cmdlet: "New-ADUser", Role: InternalWriteRoleCreate,
		FiniteRoundTrip: true, ZoneAgnostic: true, NeverZero: true, NeverMax: true,
		NeverNoInstant: true, UnreadIsNotNever: true, OmittedDefault: true,
	}
}

func InternalPassingExpirationUpdate() InternalExpirationObservation {
	o := InternalPassingExpirationCreate()
	o.Cmdlet, o.Role = "Set-ADUser", InternalWriteRoleUpdate
	// Deliberately left false: the create-only half must not be required of an
	// update, or the update role could never pass honestly.
	o.OmittedDefault, o.OmittedDefaultStamp = false, ""
	o.ClearedIsNever, o.ClearedPresent, o.OmittedUnchanged = true, true, true
	o.SentinelRefused, o.SentinelClass = true, admodel.ClassInvalidRequest.String()
	o.PrecisionRefused, o.PrecisionClass = true, admodel.ClassInvalidRequest.String()
	return o
}

func TestExpirationObservationRequiresEveryHalf(t *testing.T) {
	for _, role := range []struct {
		InternalName      string
		InternalPassing   func() InternalExpirationObservation
		InternalMutations map[string]func(*InternalExpirationObservation)
	}{
		{
			InternalName: "create", InternalPassing: InternalPassingExpirationCreate,
			InternalMutations: map[string]func(*InternalExpirationObservation){
				"a finite instant round-tripped":                func(o *InternalExpirationObservation) { o.FiniteRoundTrip = false },
				"a non-UTC zone produced the same stamp":        func(o *InternalExpirationObservation) { o.ZoneAgnostic = false },
				"zero read as never":                            func(o *InternalExpirationObservation) { o.NeverZero = false },
				"MaxInt64 read as never":                        func(o *InternalExpirationObservation) { o.NeverMax = false },
				"a never value carried no instant":              func(o *InternalExpirationObservation) { o.NeverNoInstant = false },
				"an unread attribute was not reported as never": func(o *InternalExpirationObservation) { o.UnreadIsNotNever = false },
				"an omitted create left the directory default":  func(o *InternalExpirationObservation) { o.OmittedDefault = false },
			},
		},
		{
			InternalName: "update", InternalPassing: InternalPassingExpirationUpdate,
			InternalMutations: map[string]func(*InternalExpirationObservation){
				"a finite instant round-tripped":    func(o *InternalExpirationObservation) { o.FiniteRoundTrip = false },
				"zero read as never":                func(o *InternalExpirationObservation) { o.NeverZero = false },
				"clearing read as never":            func(o *InternalExpirationObservation) { o.ClearedIsNever = false },
				"the cleared attribute was present": func(o *InternalExpirationObservation) { o.ClearedPresent = false },
				"an omitted update changed nothing": func(o *InternalExpirationObservation) { o.OmittedUnchanged = false },
				"a sentinel instant was refused":    func(o *InternalExpirationObservation) { o.SentinelRefused = false },
				"a sub-100ns instant was refused":   func(o *InternalExpirationObservation) { o.PrecisionRefused = false },
			},
		},
	} {
		t.Run(role.InternalName, func(t *testing.T) {
			if !role.InternalPassing().InternalQualifies() {
				t.Fatal("the fully satisfied observation does not qualify")
			}
			for name, apply := range role.InternalMutations {
				t.Run(name, func(t *testing.T) {
					o := role.InternalPassing()
					apply(&o)
					if o.InternalQualifies() {
						t.Fatalf("the observation still qualified without %q", name)
					}
				})
			}
		})
	}
}

// A refusal reported as a denial means permissions, and one reported as
// uncertain means the write may have landed. Neither is evidence that the typed
// surface refused the input, so neither may pass.
func TestExpirationRefusalsMustBeInvalidRequests(t *testing.T) {
	for _, class := range []admodel.ErrorClass{admodel.ClassUnclassified, admodel.ClassDenied, admodel.ClassUncertain, admodel.ClassConflict, admodel.ClassNotFound, admodel.ClassAlreadyExists, admodel.ClassUnsupported, admodel.ClassUnverified, admodel.ClassIncomplete, admodel.ClassTransport} {
		o := InternalPassingExpirationUpdate()
		o.SentinelClass = class.String()
		if o.InternalQualifies() {
			t.Errorf("a sentinel refusal reported as %s was accepted", class)
		}
		o = InternalPassingExpirationUpdate()
		o.PrecisionClass = class.String()
		if o.InternalQualifies() {
			t.Errorf("a precision refusal reported as %s was accepted", class)
		}
	}
}

// An unrecognised role must not pass. A role this harness does not drive has
// had none of its halves measured, so an aggregation that fell through to true
// would claim a scenario nothing exercised.
func TestExpirationObservationRejectsAnUnknownRole(t *testing.T) {
	for _, role := range []InternalWriteEndpointRole{"", InternalWriteRoleDelete, InternalWriteRoleRename, "whatever"} {
		o := InternalPassingExpirationUpdate()
		o.Role = role
		if o.InternalQualifies() {
			t.Errorf("an observation with role %q qualified", role)
		}
	}
}

func InternalPassingCertificateObservation() InternalCertificateObservation {
	return InternalCertificateObservation{
		Cmdlet: "New-ADUser", Role: InternalWriteRoleCreate,
		ByteExact: true, ValueCount: 2,
		Digests:         []string{"aa", "bb"},
		ReadDigests:     []string{"aa", "bb"},
		TextPathRefused: true, TextPathClass: admodel.ClassInvalidRequest.String(),
		ClearedState: "absent", UnloadedState: "unloaded", StatesDistinct: true,
	}
}

func TestCertificateObservationRequiresEveryHalf(t *testing.T) {
	if !InternalPassingCertificateObservation().InternalQualifies() {
		t.Fatal("the fully satisfied observation does not qualify")
	}
	for name, apply := range map[string]func(*InternalCertificateObservation){
		"every byte survived":         func(o *InternalCertificateObservation) { o.ByteExact = false },
		"both values were written":    func(o *InternalCertificateObservation) { o.ValueCount = 1 },
		"the text path refused them":  func(o *InternalCertificateObservation) { o.TextPathRefused = false },
		"the retrieval states differ": func(o *InternalCertificateObservation) { o.StatesDistinct = false },
	} {
		t.Run(name, func(t *testing.T) {
			o := InternalPassingCertificateObservation()
			apply(&o)
			if o.InternalQualifies() {
				t.Fatalf("the observation still qualified without %q", name)
			}
		})
	}
}

// The digests are the byte-exact claim. A readback that differs from what was
// written must fail even when the harness also set ByteExact, because the two
// are computed from the same bytes and disagreeing is a harness bug rather than
// a passing measurement.
func TestCertificateObservationComparesTheDigests(t *testing.T) {
	o := InternalPassingCertificateObservation()
	o.ReadDigests = []string{"aa", "cc"}
	if o.InternalQualifies() {
		t.Error("an observation qualified with readback digests that do not match")
	}
	o = InternalPassingCertificateObservation()
	o.ReadDigests = []string{"aa"}
	if o.InternalQualifies() {
		t.Error("an observation qualified with a readback of the wrong length")
	}
}

// A cleared field and an unrequested field reading the same is exactly the
// confusion this family exists to rule out: a provider that cannot tell them
// apart deletes certificates it was never told about.
func TestCertificateObservationRejectsIndistinguishableStates(t *testing.T) {
	for _, state := range []string{"absent", "unloaded", "present"} {
		o := InternalPassingCertificateObservation()
		o.ClearedState, o.UnloadedState = state, state
		if o.InternalQualifies() {
			t.Errorf("an observation qualified with both states reading %q", state)
		}
	}
	o := InternalPassingCertificateObservation()
	o.ClearedState, o.UnloadedState = "", ""
	if o.InternalQualifies() {
		t.Error("an observation qualified with no retrieval states recorded at all")
	}
}

func InternalPassingSPNObservation() InternalSpnObservation {
	return InternalSpnObservation{
		Cmdlet: "Set-ADUser", Role: InternalWriteRoleUpdate,
		Path: InternalSpnPathExplicit, Semantics: InternalSpnSemanticsValues,
		AddKeptOthers: true, ReplaceSetExactly: true, RemoveKeptOthers: true,
		ClearEmptied: true, NonASCIIRoundTrip: true,
		ForeignRefused: true, ForeignClass: admodel.ClassConflict.String(), ForeignNoWrite: true,
		DuplicateRefused: true, DuplicateClass: admodel.ClassInvalidRequest.String(),
	}
}

func TestSPNObservationRequiresEveryHalf(t *testing.T) {
	if !InternalPassingSPNObservation().InternalQualifies() {
		t.Fatal("the fully satisfied observation does not qualify")
	}
	for name, apply := range map[string]func(*InternalSpnObservation){
		"adding kept the other values":      func(o *InternalSpnObservation) { o.AddKeptOthers = false },
		"replacing set exactly the request": func(o *InternalSpnObservation) { o.ReplaceSetExactly = false },
		"removing kept the other values":    func(o *InternalSpnObservation) { o.RemoveKeptOthers = false },
		"clearing emptied the attribute":    func(o *InternalSpnObservation) { o.ClearEmptied = false },
		"a non-ASCII value round-tripped":   func(o *InternalSpnObservation) { o.NonASCIIRoundTrip = false },
		"a foreign-owned value was refused": func(o *InternalSpnObservation) { o.ForeignRefused = false },
		"the refused write changed nothing": func(o *InternalSpnObservation) { o.ForeignNoWrite = false },
		"a duplicate value was refused":     func(o *InternalSpnObservation) { o.DuplicateRefused = false },
		"a known modification path":         func(o *InternalSpnObservation) { o.Path = "somehow" },
		"the semantics that path offers":    func(o *InternalSpnObservation) { o.Semantics = "" },
	} {
		t.Run(name, func(t *testing.T) {
			o := InternalPassingSPNObservation()
			apply(&o)
			if o.InternalQualifies() {
				t.Fatalf("the observation still qualified without %q", name)
			}
		})
	}
}

// Only the directory refusing the value evidences the constraint. A denial is
// about permissions and an uncertain outcome means the value may have been
// written, so neither may stand in for uniqueness being enforced.
func TestSPNRefusalsMustComeFromTheDirectory(t *testing.T) {
	for _, class := range []admodel.ErrorClass{admodel.ClassInvalidRequest, admodel.ClassConflict, admodel.ClassAlreadyExists} {
		if !InternalDirectoryRefusal(class.String()) {
			t.Errorf("a refusal reported as %s was not accepted", class)
		}
	}
	for _, class := range []admodel.ErrorClass{admodel.ClassUnclassified, admodel.ClassDenied, admodel.ClassUncertain, admodel.ClassNotFound, admodel.ClassUnsupported, admodel.ClassUnverified, admodel.ClassIncomplete, admodel.ClassTransport} {
		if InternalDirectoryRefusal(class.String()) {
			t.Errorf("a refusal reported as %s was accepted; that class is not the "+
				"directory rejecting a value", class)
		}
		o := InternalPassingSPNObservation()
		o.ForeignClass = class.String()
		if o.InternalQualifies() {
			t.Errorf("an observation qualified with a foreign-owner refusal reported as %s", class)
		}
		o = InternalPassingSPNObservation()
		o.DuplicateClass = class.String()
		if o.InternalQualifies() {
			t.Errorf("an observation qualified with a duplicate refusal reported as %s", class)
		}
	}
}

func InternalPassingUserPropertyField(property string) InternalUserPropertyField {
	return InternalUserPropertyField{
		Property: property, Attribute: "attr-" + property, Path: InternalSpnPathTyped,
		RoundTrip: true, OmittedUnchanged: true, UnrelatedKept: true,
	}
}

func InternalPassingUserPropertyObservation() InternalUserPropertyObservation {
	return InternalUserPropertyObservation{
		Cmdlet: "Set-ADUser",
		Role:   InternalWriteRoleUpdate,
		Fields: []InternalUserPropertyField{
			InternalPassingUserPropertyField("HomeDirectory"),
			InternalPassingUserPropertyField("Country"),
		},
		TargetDNCanonical:  true,
		NonCanonicalLanded: true,
		NonCanonicalClass:  admodel.ClassUncertain.String(),
		ManagerRefused:     true,
		ManagerClass:       admodel.ClassInvalidRequest.String(),
		ManagerNoWrite:     true,
	}
}

func TestUserPropertyObservationRequiresEveryHalf(t *testing.T) {
	if !InternalPassingUserPropertyObservation().InternalQualifies() {
		t.Fatal("the fully satisfied observation does not qualify")
	}
	for name, apply := range map[string]func(*InternalUserPropertyObservation){
		"at least one property was measured": func(o *InternalUserPropertyObservation) { o.Fields = nil },
		"an invalid manager was refused":     func(o *InternalUserPropertyObservation) { o.ManagerRefused = false },
		"the refused manager wrote nothing":  func(o *InternalUserPropertyObservation) { o.ManagerNoWrite = false },
		"the target name matching the directory": func(o *InternalUserPropertyObservation) {
			o.TargetDNCanonical = false
		},
		"a non-canonical name still landing": func(o *InternalUserPropertyObservation) {
			o.NonCanonicalLanded = false
		},
		"a recorded reading for the non-canonical name": func(o *InternalUserPropertyObservation) {
			o.NonCanonicalClass = ""
		},
		"the manager refusal was a bad request": func(o *InternalUserPropertyObservation) {
			o.ManagerClass = admodel.ClassDenied.String()
		},
	} {
		t.Run(name, func(t *testing.T) {
			o := InternalPassingUserPropertyObservation()
			apply(&o)
			if o.InternalQualifies() {
				t.Fatalf("the observation still qualified without %q", name)
			}
		})
	}
}

// Every property in the set is load-bearing, not just the first. A loop that
// returned on the first acceptable field would pass an observation whose later
// properties went to the wrong attribute.
func TestUserPropertyObservationChecksEveryFieldNotJustTheFirst(t *testing.T) {
	for position := range 3 {
		o := InternalPassingUserPropertyObservation()
		o.Fields = []InternalUserPropertyField{
			InternalPassingUserPropertyField("first"),
			InternalPassingUserPropertyField("second"),
			InternalPassingUserPropertyField("third"),
		}
		o.Fields[position].RoundTrip = false
		if o.InternalQualifies() {
			t.Errorf("an observation qualified with property %d not round-tripping", position)
		}
	}
}

// A field must name the attribute it reached and the door it went through. An
// unnamed attribute would make the mapping claim unverifiable, which is the
// whole point of this family.
func TestUserPropertyFieldRequiresItsMapping(t *testing.T) {
	for name, apply := range map[string]func(*InternalUserPropertyField){
		"a property name":                     func(f *InternalUserPropertyField) { f.Property = "" },
		"the attribute it reached":            func(f *InternalUserPropertyField) { f.Attribute = "" },
		"a known path":                        func(f *InternalUserPropertyField) { f.Path = "magic" },
		"an unrecorded path":                  func(f *InternalUserPropertyField) { f.Path = "" },
		"the unrelated properties surviving":  func(f *InternalUserPropertyField) { f.UnrelatedKept = false },
		"the omitted update changing nothing": func(f *InternalUserPropertyField) { f.OmittedUnchanged = false },
	} {
		t.Run(name, func(t *testing.T) {
			field := InternalPassingUserPropertyField("HomeDrive")
			apply(&field)
			if field.InternalAcceptable() {
				t.Fatalf("a field was accepted without %q", name)
			}
		})
	}
}

// The two doors do not offer the same guarantee, and an observation that
// recorded one door's semantics against the other has mislabelled what it
// measured. Both mislabellings must fail, in both directions.
func TestSPNObservationRejectsMismatchedSemantics(t *testing.T) {
	typed := InternalPassingSPNObservation()
	typed.Path, typed.Semantics = InternalSpnPathTyped, InternalSpnSemanticsValues
	if typed.InternalQualifies() {
		t.Error("the typed property qualified while claiming add/remove semantics")
	}
	explicit := InternalPassingSPNObservation()
	explicit.Path, explicit.Semantics = InternalSpnPathExplicit, InternalSpnSemanticsReplace
	if explicit.InternalQualifies() {
		t.Error("the explicit change path qualified while claiming replace semantics")
	}
	// And the correctly labelled typed path must still be able to pass, or the
	// service account could never evidence this family at all.
	ok := InternalPassingSPNObservation()
	ok.Path, ok.Semantics = InternalSpnPathTyped, InternalSpnSemanticsReplace
	if !ok.InternalQualifies() {
		t.Error("a correctly labelled typed-property observation did not qualify")
	}
	if InternalSpnSemantics("neither") != "" {
		t.Error("an unknown path was given semantics")
	}
}

// A clear that leaves an attribute absent is unprovable by readback, so the SDK
// reports it unverifiable and the harness proves the effect with a read of its
// own. The report must never stand in for that read: an observation that only
// knows the SDK declined to prove the clear knows nothing about whether the
// values went.
func TestAnUnverifiableClearDoesNotProveTheClear(t *testing.T) {
	cert := InternalPassingCertificateObservation()
	cert.ClearedUnverifiable, cert.ClearedState = true, ""
	if cert.InternalQualifies() {
		t.Error("a certificate observation qualified on an unverifiable report with no readback")
	}
	spn := InternalPassingSPNObservation()
	spn.ClearUnverifiable, spn.ClearEmptied = true, false
	if spn.InternalQualifies() {
		t.Error("an SPN observation qualified on an unverifiable report without the values going")
	}
	// And the independent readback alone is enough, whether or not the write
	// was reported unverifiable, because the readback is the thing that settles
	// it either way.
	for _, reported := range []bool{true, false} {
		ok := InternalPassingSPNObservation()
		ok.ClearUnverifiable = reported
		if !ok.InternalQualifies() {
			t.Errorf("a proved clear did not qualify with unverifiable=%v", reported)
		}
	}
}
