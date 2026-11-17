//go:build windows && (amd64 || arm64)

package activedirectory

import "testing"

// The account-value sweep's decision logic runs only inside the lab, so these
// tests are the only place its aggregation can be falsified. Each family makes
// a claim about what a value *means*, and a permissive aggregation would turn
// the artifact into a statement that a provider can trust a reading it cannot.

func passingExpirationCreate() expirationObservation {
	return expirationObservation{
		Cmdlet: "New-ADUser", Role: writeRoleCreate,
		FiniteRoundTrip: true, ZoneAgnostic: true, NeverZero: true, NeverMax: true,
		NeverNoInstant: true, UnreadIsNotNever: true, OmittedDefault: true,
	}
}

func passingExpirationUpdate() expirationObservation {
	o := passingExpirationCreate()
	o.Cmdlet, o.Role = "Set-ADUser", writeRoleUpdate
	// Deliberately left false: the create-only half must not be required of an
	// update, or the update role could never pass honestly.
	o.OmittedDefault, o.OmittedDefaultStamp = false, ""
	o.ClearedIsNever, o.ClearedPresent, o.OmittedUnchanged = true, true, true
	o.SentinelRefused, o.SentinelClass = true, ClassInvalidRequest.String()
	o.PrecisionRefused, o.PrecisionClass = true, ClassInvalidRequest.String()
	return o
}

func TestExpirationObservationRequiresEveryHalf(t *testing.T) {
	for _, role := range []struct {
		name      string
		passing   func() expirationObservation
		mutations map[string]func(*expirationObservation)
	}{
		{
			name: "create", passing: passingExpirationCreate,
			mutations: map[string]func(*expirationObservation){
				"a finite instant round-tripped":                func(o *expirationObservation) { o.FiniteRoundTrip = false },
				"a non-UTC zone produced the same stamp":        func(o *expirationObservation) { o.ZoneAgnostic = false },
				"zero read as never":                            func(o *expirationObservation) { o.NeverZero = false },
				"MaxInt64 read as never":                        func(o *expirationObservation) { o.NeverMax = false },
				"a never value carried no instant":              func(o *expirationObservation) { o.NeverNoInstant = false },
				"an unread attribute was not reported as never": func(o *expirationObservation) { o.UnreadIsNotNever = false },
				"an omitted create left the directory default":  func(o *expirationObservation) { o.OmittedDefault = false },
			},
		},
		{
			name: "update", passing: passingExpirationUpdate,
			mutations: map[string]func(*expirationObservation){
				"a finite instant round-tripped":    func(o *expirationObservation) { o.FiniteRoundTrip = false },
				"zero read as never":                func(o *expirationObservation) { o.NeverZero = false },
				"clearing read as never":            func(o *expirationObservation) { o.ClearedIsNever = false },
				"the cleared attribute was present": func(o *expirationObservation) { o.ClearedPresent = false },
				"an omitted update changed nothing": func(o *expirationObservation) { o.OmittedUnchanged = false },
				"a sentinel instant was refused":    func(o *expirationObservation) { o.SentinelRefused = false },
				"a sub-100ns instant was refused":   func(o *expirationObservation) { o.PrecisionRefused = false },
			},
		},
	} {
		t.Run(role.name, func(t *testing.T) {
			if !role.passing().qualifies() {
				t.Fatal("the fully satisfied observation does not qualify")
			}
			for name, apply := range role.mutations {
				t.Run(name, func(t *testing.T) {
					o := role.passing()
					apply(&o)
					if o.qualifies() {
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
	for _, class := range []ErrorClass{
		ClassUnclassified, ClassDenied, ClassUncertain, ClassConflict, ClassNotFound,
		ClassAlreadyExists, ClassUnsupported, ClassUnverified, ClassIncomplete, ClassTransport,
	} {
		o := passingExpirationUpdate()
		o.SentinelClass = class.String()
		if o.qualifies() {
			t.Errorf("a sentinel refusal reported as %s was accepted", class)
		}
		o = passingExpirationUpdate()
		o.PrecisionClass = class.String()
		if o.qualifies() {
			t.Errorf("a precision refusal reported as %s was accepted", class)
		}
	}
}

// An unrecognised role must not pass. A role this harness does not drive has
// had none of its halves measured, so an aggregation that fell through to true
// would claim a scenario nothing exercised.
func TestExpirationObservationRejectsAnUnknownRole(t *testing.T) {
	for _, role := range []writeEndpointRole{"", writeRoleDelete, writeRoleRename, "whatever"} {
		o := passingExpirationUpdate()
		o.Role = role
		if o.qualifies() {
			t.Errorf("an observation with role %q qualified", role)
		}
	}
}

func passingCertificateObservation() certificateObservation {
	return certificateObservation{
		Cmdlet: "New-ADUser", Role: writeRoleCreate,
		ByteExact: true, ValueCount: 2,
		Digests:         []string{"aa", "bb"},
		ReadDigests:     []string{"aa", "bb"},
		TextPathRefused: true, TextPathClass: ClassInvalidRequest.String(),
		ClearedState: "absent", UnloadedState: "unloaded", StatesDistinct: true,
	}
}

func TestCertificateObservationRequiresEveryHalf(t *testing.T) {
	if !passingCertificateObservation().qualifies() {
		t.Fatal("the fully satisfied observation does not qualify")
	}
	for name, apply := range map[string]func(*certificateObservation){
		"every byte survived":         func(o *certificateObservation) { o.ByteExact = false },
		"both values were written":    func(o *certificateObservation) { o.ValueCount = 1 },
		"the text path refused them":  func(o *certificateObservation) { o.TextPathRefused = false },
		"the retrieval states differ": func(o *certificateObservation) { o.StatesDistinct = false },
	} {
		t.Run(name, func(t *testing.T) {
			o := passingCertificateObservation()
			apply(&o)
			if o.qualifies() {
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
	o := passingCertificateObservation()
	o.ReadDigests = []string{"aa", "cc"}
	if o.qualifies() {
		t.Error("an observation qualified with readback digests that do not match")
	}
	o = passingCertificateObservation()
	o.ReadDigests = []string{"aa"}
	if o.qualifies() {
		t.Error("an observation qualified with a readback of the wrong length")
	}
}

// A cleared field and an unrequested field reading the same is exactly the
// confusion this family exists to rule out: a provider that cannot tell them
// apart deletes certificates it was never told about.
func TestCertificateObservationRejectsIndistinguishableStates(t *testing.T) {
	for _, state := range []string{"absent", "unloaded", "present"} {
		o := passingCertificateObservation()
		o.ClearedState, o.UnloadedState = state, state
		if o.qualifies() {
			t.Errorf("an observation qualified with both states reading %q", state)
		}
	}
	o := passingCertificateObservation()
	o.ClearedState, o.UnloadedState = "", ""
	if o.qualifies() {
		t.Error("an observation qualified with no retrieval states recorded at all")
	}
}

func passingSPNObservation() spnObservation {
	return spnObservation{
		Cmdlet: "Set-ADUser", Role: writeRoleUpdate,
		Path: spnPathExplicit, Semantics: spnSemanticsValues,
		AddKeptOthers: true, ReplaceSetExactly: true, RemoveKeptOthers: true,
		ClearEmptied: true, NonASCIIRoundTrip: true,
		ForeignRefused: true, ForeignClass: ClassConflict.String(), ForeignNoWrite: true,
		DuplicateRefused: true, DuplicateClass: ClassInvalidRequest.String(),
	}
}

func TestSPNObservationRequiresEveryHalf(t *testing.T) {
	if !passingSPNObservation().qualifies() {
		t.Fatal("the fully satisfied observation does not qualify")
	}
	for name, apply := range map[string]func(*spnObservation){
		"adding kept the other values":      func(o *spnObservation) { o.AddKeptOthers = false },
		"replacing set exactly the request": func(o *spnObservation) { o.ReplaceSetExactly = false },
		"removing kept the other values":    func(o *spnObservation) { o.RemoveKeptOthers = false },
		"clearing emptied the attribute":    func(o *spnObservation) { o.ClearEmptied = false },
		"a non-ASCII value round-tripped":   func(o *spnObservation) { o.NonASCIIRoundTrip = false },
		"a foreign-owned value was refused": func(o *spnObservation) { o.ForeignRefused = false },
		"the refused write changed nothing": func(o *spnObservation) { o.ForeignNoWrite = false },
		"a duplicate value was refused":     func(o *spnObservation) { o.DuplicateRefused = false },
		"a known modification path":         func(o *spnObservation) { o.Path = "somehow" },
		"the semantics that path offers":    func(o *spnObservation) { o.Semantics = "" },
	} {
		t.Run(name, func(t *testing.T) {
			o := passingSPNObservation()
			apply(&o)
			if o.qualifies() {
				t.Fatalf("the observation still qualified without %q", name)
			}
		})
	}
}

// Only the directory refusing the value evidences the constraint. A denial is
// about permissions and an uncertain outcome means the value may have been
// written, so neither may stand in for uniqueness being enforced.
func TestSPNRefusalsMustComeFromTheDirectory(t *testing.T) {
	for _, class := range []ErrorClass{ClassInvalidRequest, ClassConflict, ClassAlreadyExists} {
		if !directoryRefusal(class.String()) {
			t.Errorf("a refusal reported as %s was not accepted", class)
		}
	}
	for _, class := range []ErrorClass{
		ClassUnclassified, ClassDenied, ClassUncertain, ClassNotFound, ClassUnsupported,
		ClassUnverified, ClassIncomplete, ClassTransport,
	} {
		if directoryRefusal(class.String()) {
			t.Errorf("a refusal reported as %s was accepted; that class is not the "+
				"directory rejecting a value", class)
		}
		o := passingSPNObservation()
		o.ForeignClass = class.String()
		if o.qualifies() {
			t.Errorf("an observation qualified with a foreign-owner refusal reported as %s", class)
		}
		o = passingSPNObservation()
		o.DuplicateClass = class.String()
		if o.qualifies() {
			t.Errorf("an observation qualified with a duplicate refusal reported as %s", class)
		}
	}
}

func passingUserPropertyField(property string) userPropertyField {
	return userPropertyField{
		Property: property, Attribute: "attr-" + property, Path: spnPathTyped,
		RoundTrip: true, OmittedUnchanged: true, UnrelatedKept: true,
	}
}

func passingUserPropertyObservation() userPropertyObservation {
	return userPropertyObservation{
		Cmdlet: "Set-ADUser", Role: writeRoleUpdate,
		Fields: []userPropertyField{
			passingUserPropertyField("HomeDirectory"),
			passingUserPropertyField("Country"),
		},
		TargetDNCanonical: true, NonCanonicalLanded: true,
		NonCanonicalClass: ClassUncertain.String(),
		ManagerRefused:    true, ManagerClass: ClassInvalidRequest.String(), ManagerNoWrite: true,
	}
}

func TestUserPropertyObservationRequiresEveryHalf(t *testing.T) {
	if !passingUserPropertyObservation().qualifies() {
		t.Fatal("the fully satisfied observation does not qualify")
	}
	for name, apply := range map[string]func(*userPropertyObservation){
		"at least one property was measured": func(o *userPropertyObservation) { o.Fields = nil },
		"an invalid manager was refused":     func(o *userPropertyObservation) { o.ManagerRefused = false },
		"the refused manager wrote nothing":  func(o *userPropertyObservation) { o.ManagerNoWrite = false },
		"the target name matching the directory": func(o *userPropertyObservation) {
			o.TargetDNCanonical = false
		},
		"a non-canonical name still landing": func(o *userPropertyObservation) {
			o.NonCanonicalLanded = false
		},
		"a recorded reading for the non-canonical name": func(o *userPropertyObservation) {
			o.NonCanonicalClass = ""
		},
		"the manager refusal was a bad request": func(o *userPropertyObservation) {
			o.ManagerClass = ClassDenied.String()
		},
	} {
		t.Run(name, func(t *testing.T) {
			o := passingUserPropertyObservation()
			apply(&o)
			if o.qualifies() {
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
		o := passingUserPropertyObservation()
		o.Fields = []userPropertyField{
			passingUserPropertyField("first"),
			passingUserPropertyField("second"),
			passingUserPropertyField("third"),
		}
		o.Fields[position].RoundTrip = false
		if o.qualifies() {
			t.Errorf("an observation qualified with property %d not round-tripping", position)
		}
	}
}

// A field must name the attribute it reached and the door it went through. An
// unnamed attribute would make the mapping claim unverifiable, which is the
// whole point of this family.
func TestUserPropertyFieldRequiresItsMapping(t *testing.T) {
	for name, apply := range map[string]func(*userPropertyField){
		"a property name":                     func(f *userPropertyField) { f.Property = "" },
		"the attribute it reached":            func(f *userPropertyField) { f.Attribute = "" },
		"a known path":                        func(f *userPropertyField) { f.Path = "magic" },
		"an unrecorded path":                  func(f *userPropertyField) { f.Path = "" },
		"the unrelated properties surviving":  func(f *userPropertyField) { f.UnrelatedKept = false },
		"the omitted update changing nothing": func(f *userPropertyField) { f.OmittedUnchanged = false },
	} {
		t.Run(name, func(t *testing.T) {
			field := passingUserPropertyField("HomeDrive")
			apply(&field)
			if field.acceptable() {
				t.Fatalf("a field was accepted without %q", name)
			}
		})
	}
}

// The two doors do not offer the same guarantee, and an observation that
// recorded one door's semantics against the other has mislabelled what it
// measured. Both mislabellings must fail, in both directions.
func TestSPNObservationRejectsMismatchedSemantics(t *testing.T) {
	typed := passingSPNObservation()
	typed.Path, typed.Semantics = spnPathTyped, spnSemanticsValues
	if typed.qualifies() {
		t.Error("the typed property qualified while claiming add/remove semantics")
	}
	explicit := passingSPNObservation()
	explicit.Path, explicit.Semantics = spnPathExplicit, spnSemanticsReplace
	if explicit.qualifies() {
		t.Error("the explicit change path qualified while claiming replace semantics")
	}
	// And the correctly labelled typed path must still be able to pass, or the
	// service account could never evidence this family at all.
	ok := passingSPNObservation()
	ok.Path, ok.Semantics = spnPathTyped, spnSemanticsReplace
	if !ok.qualifies() {
		t.Error("a correctly labelled typed-property observation did not qualify")
	}
	if spnSemantics("neither") != "" {
		t.Error("an unknown path was given semantics")
	}
}

// A clear that leaves an attribute absent is unprovable by readback, so the SDK
// reports it unverifiable and the harness proves the effect with a read of its
// own. The report must never stand in for that read: an observation that only
// knows the SDK declined to prove the clear knows nothing about whether the
// values went.
func TestAnUnverifiableClearDoesNotProveTheClear(t *testing.T) {
	cert := passingCertificateObservation()
	cert.ClearedUnverifiable, cert.ClearedState = true, ""
	if cert.qualifies() {
		t.Error("a certificate observation qualified on an unverifiable report with no readback")
	}
	spn := passingSPNObservation()
	spn.ClearUnverifiable, spn.ClearEmptied = true, false
	if spn.qualifies() {
		t.Error("an SPN observation qualified on an unverifiable report without the values going")
	}
	// And the independent readback alone is enough, whether or not the write
	// was reported unverifiable, because the readback is the thing that settles
	// it either way.
	for _, reported := range []bool{true, false} {
		ok := passingSPNObservation()
		ok.ClearUnverifiable = reported
		if !ok.qualifies() {
			t.Errorf("a proved clear did not qualify with unverifiable=%v", reported)
		}
	}
}
