//go:build windows && (amd64 || arm64)

package acceptance

import (
	"encoding/json"
	"errors"
	"os"
	"testing"

	admodel "github.com/deploymenttheory/go-sdk-activedirectory/activedirectory/internal/model"
)

// The sweep's decision logic runs only inside an opt-in lab harness, so without
// these tests nothing exercises it. An aggregation that silently became
// permissive would make every future sweep report success regardless of what
// the directory did, and the lab artifact would look like evidence.

func InternalPassingSweepObservation() InternalSweepObservation {
	explicit := true
	return InternalSweepObservation{
		Cmdlet:                 "Get-ADObject",
		DomainScoped:           true,
		PrimaryDefaultRead:     true,
		SecondaryDefaultRead:   true,
		ExplicitBaseRead:       &explicit,
		MismatchedBaseRefused:  true,
		MismatchedBaseNoObject: true,
		AllocationsRemaining:   0,
	}
}

// Every input must be load-bearing. Flipping any single one must withhold the
// qualification, including the native allocation balance.
func TestSweepObservationRequiresEveryHalf(t *testing.T) {
	if !InternalPassingSweepObservation().InternalQualifies() {
		t.Fatal("the fully satisfied observation does not qualify")
	}
	refused := false
	for _, mutation := range []struct {
		InternalName  string
		InternalApply func(*InternalSweepObservation)
	}{
		{"primary default read", func(o *InternalSweepObservation) { o.PrimaryDefaultRead = false }},
		{"secondary default read", func(o *InternalSweepObservation) { o.SecondaryDefaultRead = false }},
		{"explicit base read", func(o *InternalSweepObservation) { o.ExplicitBaseRead = &refused }},
		{"mismatched base refused", func(o *InternalSweepObservation) { o.MismatchedBaseRefused = false }},
		{"mismatched base returned nothing", func(o *InternalSweepObservation) { o.MismatchedBaseNoObject = false }},
		{"native allocations balanced", func(o *InternalSweepObservation) { o.AllocationsRemaining = 1 }},
	} {
		t.Run(mutation.InternalName, func(t *testing.T) {
			o := InternalPassingSweepObservation()
			mutation.InternalApply(&o)
			if o.InternalQualifies() {
				t.Fatalf("the observation still qualified without %q", mutation.InternalName)
			}
		})
	}
}

// A container-scoped read is not asked for an explicit domain base, so a nil
// ExplicitBaseRead must neither qualify it by default nor disqualify it.
func TestSweepObservationTreatsInapplicableExplicitBaseAsNeutral(t *testing.T) {
	o := InternalPassingSweepObservation()
	o.DomainScoped, o.ExplicitBaseRead = false, nil
	if !o.InternalQualifies() {
		t.Fatal("a container-scoped observation was disqualified for having no explicit base read")
	}
	o.MismatchedBaseRefused = false
	if o.InternalQualifies() {
		t.Fatal("a nil explicit base read excused a missing refusal")
	}
}

func TestSweepDetailClassifiesOutcomes(t *testing.T) {
	for _, test := range []struct {
		InternalName   string
		InternalErr    error
		InternalResult admodel.SearchResult
		InternalWant   string
	}{
		{"completed", nil, admodel.SearchResult{Complete: true}, ""},
		{"error wins over completeness", errors.New("boom"), admodel.SearchResult{Complete: true}, "boom"},
		{"caller limit", nil, admodel.SearchResult{LimitReached: true}, "incomplete: caller limit reached"},
		{"server stopped short", nil, admodel.SearchResult{}, "incomplete: server did not end the search"},
	} {
		t.Run(test.InternalName, func(t *testing.T) {
			if got := InternalSweepDetail(
				test.InternalErr,
				test.InternalResult,
			); got != test.InternalWant {
				t.Fatalf("detail = %q, want %q", got, test.InternalWant)
			}
		})
	}
}

// A dropped counter would hide a leak of exactly that resource, so each one is
// asserted to reach the total on its own.
func TestSweepAllocationsCountsEveryResource(t *testing.T) {
	for _, test := range []struct {
		InternalName  string
		InternalApply func(*InternalSearchNativeCounts)
	}{
		{"messages", func(c *InternalSearchNativeCounts) { c.InternalMessages = 1 }},
		{"request controls", func(c *InternalSearchNativeCounts) { c.InternalControls = 1 }},
		{"response controls", func(c *InternalSearchNativeCounts) { c.InternalControlSets = 1 }},
		{"cookies", func(c *InternalSearchNativeCounts) { c.InternalCookies = 1 }},
		{"values", func(c *InternalSearchNativeCounts) { c.InternalValues = 1 }},
		{"names", func(c *InternalSearchNativeCounts) { c.InternalNames = 1 }},
		{"attribute cursors", func(c *InternalSearchNativeCounts) { c.InternalCursors = 1 }},
	} {
		t.Run(test.InternalName, func(t *testing.T) {
			var counts InternalSearchNativeCounts
			test.InternalApply(&counts)
			if got := InternalSweepAllocations(counts); got != 1 {
				t.Fatalf("%s did not reach the total: got %d", test.InternalName, got)
			}
		})
	}
	if InternalSweepAllocations(InternalSearchNativeCounts{}) != 0 {
		t.Fatal("a balanced session did not total zero")
	}
}

// The table is a claim about the coverage contract: each row says it observes
// one operation's endpoint-and-partition scenario. A row naming an operation
// that has no such scenario, or a duplicate row, would make the artifact cite
// evidence for something the contract does not ask for.
func TestEndpointSweepTableMatchesCoverageContract(t *testing.T) {
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
			Cmdlet    string `json:"cmdlet"`
			Scenarios []struct {
				Name string `json:"name"`
			} `json:"scenarios"`
		} `json:"operations"`
	}
	if err := json.Unmarshal(data, &inventory); err != nil {
		t.Fatal(err)
	}
	scoped := map[string]bool{}
	for _, operation := range inventory.Operations {
		for _, scenario := range operation.Scenarios {
			if scenario.Name == "endpoint-and-partition" {
				scoped[operation.Cmdlet] = true
			}
		}
	}
	if len(scoped) == 0 {
		t.Fatal("no operation in the contract declares an endpoint-and-partition scenario")
	}
	seen := map[string]bool{}
	for _, target := range InternalEndpointSweepTargets() {
		if seen[target.InternalCmdlet] {
			t.Errorf("%s appears twice in the sweep table", target.InternalCmdlet)
		}
		seen[target.InternalCmdlet] = true
		if !scoped[target.InternalCmdlet] {
			t.Errorf(
				"%s has no endpoint-and-partition scenario in the coverage contract",
				target.InternalCmdlet,
			)
		}
	}
	if len(seen) == 0 {
		t.Fatal("the sweep table is empty")
	}
}
