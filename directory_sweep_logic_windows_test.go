//go:build windows && (amd64 || arm64)

package activedirectory

import (
	"encoding/json"
	"errors"
	"os"
	"testing"
)

// The sweep's decision logic runs only inside an opt-in lab harness, so without
// these tests nothing exercises it. An aggregation that silently became
// permissive would make every future sweep report success regardless of what
// the directory did, and the lab artifact would look like evidence.

func passingSweepObservation() sweepObservation {
	explicit := true
	return sweepObservation{
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
	if !passingSweepObservation().qualifies() {
		t.Fatal("the fully satisfied observation does not qualify")
	}
	refused := false
	for _, mutation := range []struct {
		name  string
		apply func(*sweepObservation)
	}{
		{"primary default read", func(o *sweepObservation) { o.PrimaryDefaultRead = false }},
		{"secondary default read", func(o *sweepObservation) { o.SecondaryDefaultRead = false }},
		{"explicit base read", func(o *sweepObservation) { o.ExplicitBaseRead = &refused }},
		{"mismatched base refused", func(o *sweepObservation) { o.MismatchedBaseRefused = false }},
		{"mismatched base returned nothing", func(o *sweepObservation) { o.MismatchedBaseNoObject = false }},
		{"native allocations balanced", func(o *sweepObservation) { o.AllocationsRemaining = 1 }},
	} {
		t.Run(mutation.name, func(t *testing.T) {
			o := passingSweepObservation()
			mutation.apply(&o)
			if o.qualifies() {
				t.Fatalf("the observation still qualified without %q", mutation.name)
			}
		})
	}
}

// A container-scoped read is not asked for an explicit domain base, so a nil
// ExplicitBaseRead must neither qualify it by default nor disqualify it.
func TestSweepObservationTreatsInapplicableExplicitBaseAsNeutral(t *testing.T) {
	o := passingSweepObservation()
	o.DomainScoped, o.ExplicitBaseRead = false, nil
	if !o.qualifies() {
		t.Fatal("a container-scoped observation was disqualified for having no explicit base read")
	}
	o.MismatchedBaseRefused = false
	if o.qualifies() {
		t.Fatal("a nil explicit base read excused a missing refusal")
	}
}

func TestSweepDetailClassifiesOutcomes(t *testing.T) {
	for _, test := range []struct {
		name   string
		err    error
		result SearchResult
		want   string
	}{
		{"completed", nil, SearchResult{Complete: true}, ""},
		{"error wins over completeness", errors.New("boom"), SearchResult{Complete: true}, "boom"},
		{"caller limit", nil, SearchResult{LimitReached: true}, "incomplete: caller limit reached"},
		{"server stopped short", nil, SearchResult{}, "incomplete: server did not end the search"},
	} {
		t.Run(test.name, func(t *testing.T) {
			if got := sweepDetail(test.err, test.result); got != test.want {
				t.Fatalf("detail = %q, want %q", got, test.want)
			}
		})
	}
}

// A dropped counter would hide a leak of exactly that resource, so each one is
// asserted to reach the total on its own.
func TestSweepAllocationsCountsEveryResource(t *testing.T) {
	for _, test := range []struct {
		name  string
		apply func(*searchNativeCounts)
	}{
		{"messages", func(c *searchNativeCounts) { c.messages = 1 }},
		{"request controls", func(c *searchNativeCounts) { c.controls = 1 }},
		{"response controls", func(c *searchNativeCounts) { c.controlSets = 1 }},
		{"cookies", func(c *searchNativeCounts) { c.cookies = 1 }},
		{"values", func(c *searchNativeCounts) { c.values = 1 }},
		{"names", func(c *searchNativeCounts) { c.names = 1 }},
		{"attribute cursors", func(c *searchNativeCounts) { c.cursors = 1 }},
	} {
		t.Run(test.name, func(t *testing.T) {
			var counts searchNativeCounts
			test.apply(&counts)
			if got := sweepAllocations(counts); got != 1 {
				t.Fatalf("%s did not reach the total: got %d", test.name, got)
			}
		})
	}
	if sweepAllocations(searchNativeCounts{}) != 0 {
		t.Fatal("a balanced session did not total zero")
	}
}

// The table is a claim about the coverage contract: each row says it observes
// one operation's endpoint-and-partition scenario. A row naming an operation
// that has no such scenario, or a duplicate row, would make the artifact cite
// evidence for something the contract does not ask for.
func TestEndpointSweepTableMatchesCoverageContract(t *testing.T) {
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
	for _, target := range endpointSweepTargets() {
		if seen[target.cmdlet] {
			t.Errorf("%s appears twice in the sweep table", target.cmdlet)
		}
		seen[target.cmdlet] = true
		if !scoped[target.cmdlet] {
			t.Errorf("%s has no endpoint-and-partition scenario in the coverage contract", target.cmdlet)
		}
	}
	if len(seen) == 0 {
		t.Fatal("the sweep table is empty")
	}
}
