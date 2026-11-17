//go:build windows && (amd64 || arm64)

package acceptance

import (
	"context"
	"encoding/json"
	"errors"
	"os"
	"strings"
	"testing"

	admodel "github.com/deploymenttheory/go-sdk-activedirectory/activedirectory/internal/model"
)

// The parameter-set sweep's decision logic runs only inside an opt-in lab
// harness, so without these tests nothing exercises it. An aggregation that
// silently became permissive would make every future run report success
// regardless of what the directory did, and the lab artifact would then read as
// evidence for parameter sets that were never invoked.

func InternalPassingVariantObservation() InternalVariantObservation {
	return InternalVariantObservation{
		Cmdlet:            "Get-ADObject",
		Variant:           "Filter (Default)",
		SuccessTest:       "Get-ADObject/filter-default/success",
		FailureTest:       "Get-ADObject/filter-default/failure",
		Observable:        true,
		SatisfiedRead:     true,
		SatisfiedObjects:  1,
		SatisfiedSelected: true,
		RefusalObserved:   true,
		RefusalObjects:    0,
		RefusalSpecific:   true,
		Allocations:       0,
	}
}

// Every input must be load-bearing. Withholding any single one must withhold
// the qualification, including the native allocation balance and the record
// that the run could observe this parameter set at all.
func TestVariantObservationRequiresEveryInput(t *testing.T) {
	if !InternalPassingVariantObservation().InternalQualifies() {
		t.Fatal("the fully satisfied observation does not qualify")
	}
	for _, mutation := range []struct {
		InternalName  string
		InternalApply func(*InternalVariantObservation)
	}{
		{"observable", func(o *InternalVariantObservation) { o.Observable = false }},
		{"satisfied invocation", func(o *InternalVariantObservation) { o.SatisfiedRead = false }},
		{"satisfied objects", func(o *InternalVariantObservation) { o.SatisfiedObjects = 0 }},
		{"satisfied selected the requested object", func(o *InternalVariantObservation) { o.SatisfiedSelected = false }},
		{"refusal observed", func(o *InternalVariantObservation) { o.RefusalObserved = false }},
		{"refusal returned no object", func(o *InternalVariantObservation) { o.RefusalObjects = 1 }},
		{"refusal specific to the parameter set", func(o *InternalVariantObservation) { o.RefusalSpecific = false }},
		{"native allocations balanced", func(o *InternalVariantObservation) { o.Allocations = 1 }},
	} {
		t.Run(mutation.InternalName, func(t *testing.T) {
			o := InternalPassingVariantObservation()
			mutation.InternalApply(&o)
			if o.InternalQualifies() {
				t.Fatalf("the observation still qualified without %q", mutation.InternalName)
			}
		})
	}
}

// An unobservable row is the case the harness exists to get right: it must be
// recorded and excluded, and it must never qualify, however complete the rest
// of the observation looks.
func TestVariantObservationNeverPassesUnobserved(t *testing.T) {
	o := InternalVariantObservation{
		Cmdlet: "Get-ADObject", Variant: "Identity",
		ObservableDetail: "no readable object was found",
	}
	if o.InternalQualifies() {
		t.Fatal("an unobserved parameter set qualified")
	}
	o.Observable = true
	if o.InternalQualifies() {
		t.Fatal("declaring a row observable qualified it without any invocation")
	}
}

func TestVariantDetailClassifiesOutcomes(t *testing.T) {
	for _, test := range []struct {
		InternalName string
		InternalOut  InternalVariantOutcome
		InternalWant string
	}{
		{"completed", InternalVariantOutcome{InternalComplete: true, InternalObjects: 1}, ""},
		{"error wins over completeness", InternalVariantOutcome{InternalComplete: true, InternalErr: errors.New("boom")}, "boom"},
		{"did not finish", InternalVariantOutcome{}, "incomplete: the invocation did not finish"},
	} {
		t.Run(test.InternalName, func(t *testing.T) {
			if got := InternalVariantDetail(test.InternalOut); got != test.InternalWant {
				t.Fatalf("detail = %q, want %q", got, test.InternalWant)
			}
		})
	}
}

// The satisfied half must mean the parameter set selected the object it was
// asked for, not merely that a call returned without error.
func TestVariantSatisfiedHalfRequiresTheRequestedObject(t *testing.T) {
	inputs := InternalVariantInputs{
		InternalDefaultNC: "DC=ad,DC=sdk,DC=test",
		InternalContainer: "CN=Users,DC=ad,DC=sdk,DC=test",
		InternalPresentDN: "CN=Selected,CN=Users,DC=ad,DC=sdk,DC=test",
		// The directory returns distinguished names in its own case, so the
		// comparison must be case-insensitive rather than byte-equal.
		InternalPresentGUID: []byte{1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16},
		InternalAbsentGUID:  "9f51cb95-7f3a-4d1e-8c26-0b7a5e4d3c21",
	}
	good := InternalVariantOutcome{
		InternalObjects: 1, InternalComplete: true,
		InternalSelected: "cn=selected,cn=users,dc=ad,dc=sdk,dc=test",
	}
	if !InternalVariantSelectsPresentObject(inputs, good) {
		t.Fatal("selecting the requested object did not satisfy the half")
	}
	for _, mutation := range []struct {
		InternalName  string
		InternalApply func(*InternalVariantOutcome)
	}{
		{"an error", func(o *InternalVariantOutcome) { o.InternalErr = errors.New("boom") }},
		{"an unfinished invocation", func(o *InternalVariantOutcome) { o.InternalComplete = false }},
		{"no object", func(o *InternalVariantOutcome) { o.InternalObjects, o.InternalSelected = 0, "" }},
		{"more than one object", func(o *InternalVariantOutcome) { o.InternalObjects = 2 }},
		{"a different object", func(o *InternalVariantOutcome) {
			o.InternalSelected = "CN=Other,CN=Users,DC=ad,DC=sdk,DC=test"
		}},
		{"no named object", func(o *InternalVariantOutcome) { o.InternalSelected = "" }},
	} {
		t.Run(mutation.InternalName, func(t *testing.T) {
			out := good
			mutation.InternalApply(&out)
			if InternalVariantSelectsPresentObject(inputs, out) {
				t.Fatalf("the half was satisfied by %s", mutation.InternalName)
			}
		})
	}
	// With no requested object there is nothing to have selected, so a result
	// naming some object must not satisfy the half either.
	if InternalVariantSelectsPresentObject(InternalVariantInputs{}, good) {
		t.Fatal("the half was satisfied without a requested object")
	}
	// Every row judges its satisfied half the same way, and must agree.
	for _, target := range InternalObjectVariantTargets() {
		if !target.InternalSatisfiedHolds(inputs, good) {
			t.Errorf(
				"%s/%s rejected the requested object",
				target.InternalCmdlet,
				target.InternalVariant,
			)
		}
		missed := good
		missed.InternalSelected = "CN=Other,CN=Users,DC=ad,DC=sdk,DC=test"
		if target.InternalSatisfiedHolds(inputs, missed) {
			t.Errorf(
				"%s/%s accepted a different object",
				target.InternalCmdlet,
				target.InternalVariant,
			)
		}
	}
}

// A refusal only qualifies a parameter set if it is that parameter set's own
// refusal. The cross-product is the point: a row satisfied by another row's
// refusal would qualify a parameter set the run never actually exercised.
func TestVariantRefusalIsSpecificToItsParameterSet(t *testing.T) {
	refusals := map[string]error{
		// Refused while the filter was composed: no search reached the wire.
		"Filter (Default)": admodel.ErrInvalidFilter,
		// Refused by the directory, because raw text is sent as written.
		"LdapFilter": &admodel.SearchError{Cause: errors.New("LDAP filter error")},
		// A completed search that selected nothing.
		"Identity": admodel.ErrDirectoryObjectNotFound,
	}
	targets := InternalObjectVariantTargets()
	for _, target := range targets {
		if _, found := refusals[target.InternalVariant]; !found {
			t.Fatalf(
				"%s/%s has no refusal sample in this test",
				target.InternalCmdlet,
				target.InternalVariant,
			)
		}
	}
	for _, target := range targets {
		t.Run(target.InternalVariant, func(t *testing.T) {
			own := InternalVariantOutcome{InternalErr: refusals[target.InternalVariant]}
			if !target.InternalRefusalHolds(InternalVariantInputs{}, own) {
				t.Fatalf("its own refusal did not hold: %v", own.InternalErr)
			}
			// No refusal at all, and a refusal that returned an object anyway.
			if target.InternalRefusalHolds(
				InternalVariantInputs{},
				InternalVariantOutcome{InternalComplete: true, InternalObjects: 1},
			) {
				t.Fatal("a completed invocation counted as a refusal")
			}
			returned := own
			returned.InternalObjects = 1
			if target.InternalRefusalHolds(InternalVariantInputs{}, returned) {
				t.Fatal("a refusal that still returned an object held")
			}
			finished := own
			finished.InternalComplete = true
			if target.InternalRefusalHolds(InternalVariantInputs{}, finished) {
				t.Fatal("a finished invocation held as a refusal")
			}
			// An unrelated failure, and every other parameter set's refusal.
			if target.InternalRefusalHolds(
				InternalVariantInputs{},
				InternalVariantOutcome{InternalErr: errors.New("boom")},
			) {
				t.Fatal("an unrelated error held as this parameter set's refusal")
			}
			for variant, sample := range refusals {
				if variant == target.InternalVariant {
					continue
				}
				if target.InternalRefusalHolds(
					InternalVariantInputs{},
					InternalVariantOutcome{InternalErr: sample},
				) {
					t.Fatalf("%q's refusal held for this parameter set: %v", variant, sample)
				}
			}
		})
	}
	// A composition failure reported through a search error belongs to the
	// typed set, so the raw-text row must not accept it as a directory refusal.
	for _, target := range targets {
		if target.InternalVariant != "LdapFilter" {
			continue
		}
		wrapped := InternalVariantOutcome{
			InternalErr: &admodel.SearchError{Cause: admodel.ErrInvalidFilter},
		}
		if target.InternalRefusalHolds(InternalVariantInputs{}, wrapped) {
			t.Fatal("the raw-text row accepted a typed-filter composition failure")
		}
	}
}

// The two filter refusals must be refused in different places, because that is
// what makes each one its own parameter set's refusal. The typed set cannot
// compose its filter, so the invocation never reaches the directory; the raw
// set's text passes this SDK's validation unchanged, so only the directory can
// reject it. If the raw filter were refused here instead, the LdapFilter row
// would be observing the typed set's behavior under another name.
func TestVariantFilterRefusalsAreRefusedInDifferentPlaces(t *testing.T) {
	base := admodel.SearchOptions{
		Base:     "CN=Users,DC=ad,DC=sdk,DC=test",
		Scope:    admodel.ScopeSubtree,
		PageSize: 16,
	}
	typed := base
	typed.TypedFilter = admodel.FilterPresent(InternalVariantUncomposableAttribute)
	if err := typed.Validate(); !errors.Is(err, admodel.ErrInvalidFilter) {
		t.Fatalf("the typed refusal was not refused before the wire: %v", err)
	}
	raw := base
	raw.Filter = InternalVariantUnterminatedFilter
	if err := raw.Validate(); err != nil {
		t.Fatalf("the raw refusal was refused before reaching the directory: %v", err)
	}
}

// A refusal must come from the parameter set, not from the session. A closed
// client refuses everything, and would otherwise qualify every row while
// invoking nothing.
func TestVariantRowsRejectAClosedSession(t *testing.T) {
	ctx := context.Background()
	inputs := InternalVariantInputs{
		InternalDefaultNC:   "DC=ad,DC=sdk,DC=test",
		InternalContainer:   "CN=Users,DC=ad,DC=sdk,DC=test",
		InternalPresentDN:   "CN=Selected,CN=Users,DC=ad,DC=sdk,DC=test",
		InternalPresentGUID: []byte{1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16},
		InternalAbsentGUID:  "9f51cb95-7f3a-4d1e-8c26-0b7a5e4d3c21",
	}
	for _, target := range InternalObjectVariantTargets() {
		t.Run(target.InternalVariant, func(t *testing.T) {
			refused := target.InternalRefused(ctx, nil, inputs)
			if refused.InternalErr == nil {
				t.Fatal("a closed session produced no error")
			}
			if !errors.Is(refused.InternalErr, admodel.ErrClosed) {
				t.Fatalf(
					"a closed session reported %v rather than a closed client",
					refused.InternalErr,
				)
			}
			if target.InternalRefusalHolds(inputs, refused) {
				t.Fatal("a closed session counted as this parameter set's refusal")
			}
			satisfied := target.InternalSatisfied(ctx, nil, inputs)
			if target.InternalSatisfiedHolds(inputs, satisfied) {
				t.Fatal("a closed session satisfied this parameter set")
			}
		})
	}
}

// Observability is a precondition, not a result: with nothing from the lab,
// every row must decline to be observed, and with everything, every row must
// accept.
func TestVariantRowsDeclineWithoutLabInputs(t *testing.T) {
	complete := InternalVariantInputs{
		InternalDefaultNC:   "DC=ad,DC=sdk,DC=test",
		InternalContainer:   "CN=Users,DC=ad,DC=sdk,DC=test",
		InternalPresentDN:   "CN=Selected,CN=Users,DC=ad,DC=sdk,DC=test",
		InternalPresentGUID: []byte{1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16},
		InternalAbsentGUID:  "9f51cb95-7f3a-4d1e-8c26-0b7a5e4d3c21",
	}
	for _, target := range InternalObjectVariantTargets() {
		t.Run(target.InternalVariant, func(t *testing.T) {
			if reason := target.InternalRequires(InternalVariantInputs{}); reason == "" {
				t.Fatal("the row claimed to be observable with nothing from the lab")
			}
			if reason := target.InternalRequires(complete); reason != "" {
				t.Fatalf("the row refused a complete run: %s", reason)
			}
			for _, mutation := range []struct {
				InternalName  string
				InternalApply func(*InternalVariantInputs)
			}{
				{"container", func(in *InternalVariantInputs) { in.InternalContainer = "" }},
				{"selected object", func(in *InternalVariantInputs) { in.InternalPresentDN = "" }},
				{"selected object guid", func(in *InternalVariantInputs) { in.InternalPresentGUID = nil }},
			} {
				in := complete
				mutation.InternalApply(&in)
				if reason := target.InternalRequires(in); reason == "" {
					t.Errorf(
						"the row claimed to be observable without the %s",
						mutation.InternalName,
					)
				}
			}
		})
	}
	// Only the identity row needs an absent identity, so it is the only row
	// that may decline for the want of one.
	in := complete
	in.InternalAbsentGUID = ""
	for _, target := range InternalObjectVariantTargets() {
		declined := target.InternalRequires(in) != ""
		if (target.InternalVariant == "Identity") != declined {
			t.Errorf("%s/%s observability without an absent identity = %v",
				target.InternalCmdlet, target.InternalVariant, declined)
		}
	}
}

// The table is a claim about the coverage contract: each row says it observes
// one operation's parameter set, and cites that parameter set's two test
// identifiers. A row naming a parameter set the contract does not list, citing
// identifiers the contract does not use, or repeating another row, would make
// the artifact evidence for something nobody asked for.
func TestVariantTableMatchesCoverageContract(t *testing.T) {
	data, err := os.ReadFile(repositoryFile("coverage/inventory.json"))
	if err != nil {
		t.Fatal(err)
	}
	// Windows PowerShell UTF8 output may include the BOM.
	if len(data) >= 3 && string(data[:3]) == "\xef\xbb\xbf" {
		data = data[3:]
	}
	var inventory struct {
		Operations []struct {
			Cmdlet   string `json:"cmdlet"`
			Variants []struct {
				Name  string   `json:"name"`
				Tests []string `json:"tests"`
			} `json:"variants"`
		} `json:"operations"`
	}
	if err := json.Unmarshal(data, &inventory); err != nil {
		t.Fatal(err)
	}
	contract := map[string][]string{}
	for _, operation := range inventory.Operations {
		for _, variant := range operation.Variants {
			contract[operation.Cmdlet+"/"+variant.Name] = variant.Tests
		}
	}
	if len(contract) == 0 {
		t.Fatal("no operation in the contract declares a parameter set")
	}
	targets := InternalObjectVariantTargets()
	if len(targets) == 0 {
		t.Fatal("the parameter-set table is empty")
	}
	seen := map[string]bool{}
	for _, target := range targets {
		key := target.InternalCmdlet + "/" + target.InternalVariant
		if seen[key] {
			t.Errorf("%s appears twice in the parameter-set table", key)
		}
		seen[key] = true
		tests, found := contract[key]
		if !found {
			t.Errorf("%s is not a parameter set in the coverage contract", key)
			continue
		}
		// Both halves the contract requires, cited exactly as it names them.
		if len(tests) != 2 {
			t.Errorf("%s does not declare exactly two tests: %v", key, tests)
			continue
		}
		for _, cited := range []string{target.InternalSuccessTest, target.InternalFailureTest} {
			if cited != tests[0] && cited != tests[1] {
				t.Errorf("%s cites %q, which the contract does not list: %v", key, cited, tests)
			}
		}
		if !strings.HasSuffix(target.InternalSuccessTest, "/success") {
			t.Errorf("%s does not cite a success test: %q", key, target.InternalSuccessTest)
		}
		if !strings.HasSuffix(target.InternalFailureTest, "/failure") {
			t.Errorf("%s does not cite a failure test: %q", key, target.InternalFailureTest)
		}
		if target.InternalSuccessTest == target.InternalFailureTest {
			t.Errorf("%s cites one identifier for both halves", key)
		}
	}
	// Get-ADObject's three parameter sets are what this harness claims to
	// observe; a row silently dropped would make the sweep quietly narrower.
	for _, variant := range []string{"Filter (Default)", "Identity", "LdapFilter"} {
		if !seen["Get-ADObject/"+variant] {
			t.Errorf("Get-ADObject/%s is not in the parameter-set table", variant)
		}
	}
	// Every row must carry both invocations and both judgements; a nil would
	// panic in the lab rather than fail.
	for _, target := range targets {
		if target.InternalRequires == nil || target.InternalSatisfied == nil ||
			target.InternalSatisfiedHolds == nil ||
			target.InternalRefused == nil ||
			target.InternalRefusalHolds == nil {
			t.Errorf("%s/%s is an incomplete row", target.InternalCmdlet, target.InternalVariant)
		}
	}
}
