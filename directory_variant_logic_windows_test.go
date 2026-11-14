//go:build windows && (amd64 || arm64)

package activedirectory

import (
	"context"
	"encoding/json"
	"errors"
	"os"
	"strings"
	"testing"
)

// The parameter-set sweep's decision logic runs only inside an opt-in lab
// harness, so without these tests nothing exercises it. An aggregation that
// silently became permissive would make every future run report success
// regardless of what the directory did, and the lab artifact would then read as
// evidence for parameter sets that were never invoked.

func passingVariantObservation() variantObservation {
	return variantObservation{
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
	if !passingVariantObservation().qualifies() {
		t.Fatal("the fully satisfied observation does not qualify")
	}
	for _, mutation := range []struct {
		name  string
		apply func(*variantObservation)
	}{
		{"observable", func(o *variantObservation) { o.Observable = false }},
		{"satisfied invocation", func(o *variantObservation) { o.SatisfiedRead = false }},
		{"satisfied objects", func(o *variantObservation) { o.SatisfiedObjects = 0 }},
		{"satisfied selected the requested object", func(o *variantObservation) { o.SatisfiedSelected = false }},
		{"refusal observed", func(o *variantObservation) { o.RefusalObserved = false }},
		{"refusal returned no object", func(o *variantObservation) { o.RefusalObjects = 1 }},
		{"refusal specific to the parameter set", func(o *variantObservation) { o.RefusalSpecific = false }},
		{"native allocations balanced", func(o *variantObservation) { o.Allocations = 1 }},
	} {
		t.Run(mutation.name, func(t *testing.T) {
			o := passingVariantObservation()
			mutation.apply(&o)
			if o.qualifies() {
				t.Fatalf("the observation still qualified without %q", mutation.name)
			}
		})
	}
}

// An unobservable row is the case the harness exists to get right: it must be
// recorded and excluded, and it must never qualify, however complete the rest
// of the observation looks.
func TestVariantObservationNeverPassesUnobserved(t *testing.T) {
	o := variantObservation{Cmdlet: "Get-ADObject", Variant: "Identity",
		ObservableDetail: "no readable object was found"}
	if o.qualifies() {
		t.Fatal("an unobserved parameter set qualified")
	}
	o.Observable = true
	if o.qualifies() {
		t.Fatal("declaring a row observable qualified it without any invocation")
	}
}

func TestVariantDetailClassifiesOutcomes(t *testing.T) {
	for _, test := range []struct {
		name string
		out  variantOutcome
		want string
	}{
		{"completed", variantOutcome{complete: true, objects: 1}, ""},
		{"error wins over completeness", variantOutcome{complete: true, err: errors.New("boom")}, "boom"},
		{"did not finish", variantOutcome{}, "incomplete: the invocation did not finish"},
	} {
		t.Run(test.name, func(t *testing.T) {
			if got := variantDetail(test.out); got != test.want {
				t.Fatalf("detail = %q, want %q", got, test.want)
			}
		})
	}
}

// The satisfied half must mean the parameter set selected the object it was
// asked for, not merely that a call returned without error.
func TestVariantSatisfiedHalfRequiresTheRequestedObject(t *testing.T) {
	inputs := variantInputs{
		defaultNC: "DC=ad,DC=sdk,DC=test",
		container: "CN=Users,DC=ad,DC=sdk,DC=test",
		presentDN: "CN=Selected,CN=Users,DC=ad,DC=sdk,DC=test",
		// The directory returns distinguished names in its own case, so the
		// comparison must be case-insensitive rather than byte-equal.
		presentGUID: []byte{1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16},
		absentGUID:  "9f51cb95-7f3a-4d1e-8c26-0b7a5e4d3c21",
	}
	good := variantOutcome{objects: 1, complete: true,
		selected: "cn=selected,cn=users,dc=ad,dc=sdk,dc=test"}
	if !variantSelectsPresentObject(inputs, good) {
		t.Fatal("selecting the requested object did not satisfy the half")
	}
	for _, mutation := range []struct {
		name  string
		apply func(*variantOutcome)
	}{
		{"an error", func(o *variantOutcome) { o.err = errors.New("boom") }},
		{"an unfinished invocation", func(o *variantOutcome) { o.complete = false }},
		{"no object", func(o *variantOutcome) { o.objects, o.selected = 0, "" }},
		{"more than one object", func(o *variantOutcome) { o.objects = 2 }},
		{"a different object", func(o *variantOutcome) {
			o.selected = "CN=Other,CN=Users,DC=ad,DC=sdk,DC=test"
		}},
		{"no named object", func(o *variantOutcome) { o.selected = "" }},
	} {
		t.Run(mutation.name, func(t *testing.T) {
			out := good
			mutation.apply(&out)
			if variantSelectsPresentObject(inputs, out) {
				t.Fatalf("the half was satisfied by %s", mutation.name)
			}
		})
	}
	// With no requested object there is nothing to have selected, so a result
	// naming some object must not satisfy the half either.
	if variantSelectsPresentObject(variantInputs{}, good) {
		t.Fatal("the half was satisfied without a requested object")
	}
	// Every row judges its satisfied half the same way, and must agree.
	for _, target := range objectVariantTargets() {
		if !target.satisfiedHolds(inputs, good) {
			t.Errorf("%s/%s rejected the requested object", target.cmdlet, target.variant)
		}
		missed := good
		missed.selected = "CN=Other,CN=Users,DC=ad,DC=sdk,DC=test"
		if target.satisfiedHolds(inputs, missed) {
			t.Errorf("%s/%s accepted a different object", target.cmdlet, target.variant)
		}
	}
}

// A refusal only qualifies a parameter set if it is that parameter set's own
// refusal. The cross-product is the point: a row satisfied by another row's
// refusal would qualify a parameter set the run never actually exercised.
func TestVariantRefusalIsSpecificToItsParameterSet(t *testing.T) {
	refusals := map[string]error{
		// Refused while the filter was composed: no search reached the wire.
		"Filter (Default)": ErrInvalidFilter,
		// Refused by the directory, because raw text is sent as written.
		"LdapFilter": &SearchError{Cause: errors.New("LDAP filter error")},
		// A completed search that selected nothing.
		"Identity": ErrDirectoryObjectNotFound,
	}
	targets := objectVariantTargets()
	for _, target := range targets {
		if _, found := refusals[target.variant]; !found {
			t.Fatalf("%s/%s has no refusal sample in this test", target.cmdlet, target.variant)
		}
	}
	for _, target := range targets {
		t.Run(target.variant, func(t *testing.T) {
			own := variantOutcome{err: refusals[target.variant]}
			if !target.refusalHolds(variantInputs{}, own) {
				t.Fatalf("its own refusal did not hold: %v", own.err)
			}
			// No refusal at all, and a refusal that returned an object anyway.
			if target.refusalHolds(variantInputs{}, variantOutcome{complete: true, objects: 1}) {
				t.Fatal("a completed invocation counted as a refusal")
			}
			returned := own
			returned.objects = 1
			if target.refusalHolds(variantInputs{}, returned) {
				t.Fatal("a refusal that still returned an object held")
			}
			finished := own
			finished.complete = true
			if target.refusalHolds(variantInputs{}, finished) {
				t.Fatal("a finished invocation held as a refusal")
			}
			// An unrelated failure, and every other parameter set's refusal.
			if target.refusalHolds(variantInputs{}, variantOutcome{err: errors.New("boom")}) {
				t.Fatal("an unrelated error held as this parameter set's refusal")
			}
			for variant, sample := range refusals {
				if variant == target.variant {
					continue
				}
				if target.refusalHolds(variantInputs{}, variantOutcome{err: sample}) {
					t.Fatalf("%q's refusal held for this parameter set: %v", variant, sample)
				}
			}
		})
	}
	// A composition failure reported through a search error belongs to the
	// typed set, so the raw-text row must not accept it as a directory refusal.
	for _, target := range targets {
		if target.variant != "LdapFilter" {
			continue
		}
		wrapped := variantOutcome{err: &SearchError{Cause: ErrInvalidFilter}}
		if target.refusalHolds(variantInputs{}, wrapped) {
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
	base := SearchOptions{Base: "CN=Users,DC=ad,DC=sdk,DC=test", Scope: ScopeSubtree, PageSize: 16}
	typed := base
	typed.TypedFilter = FilterPresent(variantUncomposableAttribute)
	if err := typed.Validate(); !errors.Is(err, ErrInvalidFilter) {
		t.Fatalf("the typed refusal was not refused before the wire: %v", err)
	}
	raw := base
	raw.Filter = variantUnterminatedFilter
	if err := raw.Validate(); err != nil {
		t.Fatalf("the raw refusal was refused before reaching the directory: %v", err)
	}
}

// A refusal must come from the parameter set, not from the session. A closed
// client refuses everything, and would otherwise qualify every row while
// invoking nothing.
func TestVariantRowsRejectAClosedSession(t *testing.T) {
	ctx := context.Background()
	inputs := variantInputs{
		defaultNC:   "DC=ad,DC=sdk,DC=test",
		container:   "CN=Users,DC=ad,DC=sdk,DC=test",
		presentDN:   "CN=Selected,CN=Users,DC=ad,DC=sdk,DC=test",
		presentGUID: []byte{1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16},
		absentGUID:  "9f51cb95-7f3a-4d1e-8c26-0b7a5e4d3c21",
	}
	for _, target := range objectVariantTargets() {
		t.Run(target.variant, func(t *testing.T) {
			refused := target.refused(ctx, nil, inputs)
			if refused.err == nil {
				t.Fatal("a closed session produced no error")
			}
			if !errors.Is(refused.err, ErrClosed) {
				t.Fatalf("a closed session reported %v rather than a closed client", refused.err)
			}
			if target.refusalHolds(inputs, refused) {
				t.Fatal("a closed session counted as this parameter set's refusal")
			}
			satisfied := target.satisfied(ctx, nil, inputs)
			if target.satisfiedHolds(inputs, satisfied) {
				t.Fatal("a closed session satisfied this parameter set")
			}
		})
	}
}

// Observability is a precondition, not a result: with nothing from the lab,
// every row must decline to be observed, and with everything, every row must
// accept.
func TestVariantRowsDeclineWithoutLabInputs(t *testing.T) {
	complete := variantInputs{
		defaultNC:   "DC=ad,DC=sdk,DC=test",
		container:   "CN=Users,DC=ad,DC=sdk,DC=test",
		presentDN:   "CN=Selected,CN=Users,DC=ad,DC=sdk,DC=test",
		presentGUID: []byte{1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16},
		absentGUID:  "9f51cb95-7f3a-4d1e-8c26-0b7a5e4d3c21",
	}
	for _, target := range objectVariantTargets() {
		t.Run(target.variant, func(t *testing.T) {
			if reason := target.requires(variantInputs{}); reason == "" {
				t.Fatal("the row claimed to be observable with nothing from the lab")
			}
			if reason := target.requires(complete); reason != "" {
				t.Fatalf("the row refused a complete run: %s", reason)
			}
			for _, mutation := range []struct {
				name  string
				apply func(*variantInputs)
			}{
				{"container", func(in *variantInputs) { in.container = "" }},
				{"selected object", func(in *variantInputs) { in.presentDN = "" }},
				{"selected object guid", func(in *variantInputs) { in.presentGUID = nil }},
			} {
				in := complete
				mutation.apply(&in)
				if reason := target.requires(in); reason == "" {
					t.Errorf("the row claimed to be observable without the %s", mutation.name)
				}
			}
		})
	}
	// Only the identity row needs an absent identity, so it is the only row
	// that may decline for the want of one.
	in := complete
	in.absentGUID = ""
	for _, target := range objectVariantTargets() {
		declined := target.requires(in) != ""
		if (target.variant == "Identity") != declined {
			t.Errorf("%s/%s observability without an absent identity = %v",
				target.cmdlet, target.variant, declined)
		}
	}
}

// The table is a claim about the coverage contract: each row says it observes
// one operation's parameter set, and cites that parameter set's two test
// identifiers. A row naming a parameter set the contract does not list, citing
// identifiers the contract does not use, or repeating another row, would make
// the artifact evidence for something nobody asked for.
func TestVariantTableMatchesCoverageContract(t *testing.T) {
	data, err := os.ReadFile("coverage/inventory.json")
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
	targets := objectVariantTargets()
	if len(targets) == 0 {
		t.Fatal("the parameter-set table is empty")
	}
	seen := map[string]bool{}
	for _, target := range targets {
		key := target.cmdlet + "/" + target.variant
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
		for _, cited := range []string{target.successTest, target.failureTest} {
			if cited != tests[0] && cited != tests[1] {
				t.Errorf("%s cites %q, which the contract does not list: %v", key, cited, tests)
			}
		}
		if !strings.HasSuffix(target.successTest, "/success") {
			t.Errorf("%s does not cite a success test: %q", key, target.successTest)
		}
		if !strings.HasSuffix(target.failureTest, "/failure") {
			t.Errorf("%s does not cite a failure test: %q", key, target.failureTest)
		}
		if target.successTest == target.failureTest {
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
		if target.requires == nil || target.satisfied == nil || target.satisfiedHolds == nil ||
			target.refused == nil || target.refusalHolds == nil {
			t.Errorf("%s/%s is an incomplete row", target.cmdlet, target.variant)
		}
	}
}
