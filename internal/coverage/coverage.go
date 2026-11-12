// Package coverage validates the SDK's compatibility contract independently of a live directory.
package coverage

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"regexp"
	"slices"
	"strings"
)

type ParameterSet struct {
	Name       string   `json:"name"`
	Parameters []string `json:"parameters"`
}
type Command struct {
	Name          string         `json:"name"`
	Source        string         `json:"source"`
	SHA256        string         `json:"sha256"`
	ParameterSets []ParameterSet `json:"parameter_sets"`
	Parameters    []string       `json:"parameters"`
}
type Reference struct {
	SchemaVersion int       `json:"schema_version"`
	Repository    string    `json:"repository"`
	Commit        string    `json:"commit"`
	View          string    `json:"view"`
	Commands      []Command `json:"commands"`
}
type Applicability struct {
	ADDS  string `json:"ad_ds"`
	ADLDS string `json:"ad_lds"`
	Notes string `json:"notes"`
}
type Variant struct {
	Name           string   `json:"name"`
	Parameters     []string `json:"parameters"`
	State          string   `json:"state"`
	Implementation string   `json:"implementation,omitempty"`
	Tests          []string `json:"tests"`
	Evidence       []string `json:"evidence"`
}

// Scenario describes behavior that a PowerShell parameter-set name cannot express,
// such as a cross-domain move or one particular FSMO role's seizure semantics.
type Scenario struct {
	Name           string   `json:"name"`
	Description    string   `json:"description"`
	Parameters     []string `json:"parameters"`
	Prerequisites  []string `json:"prerequisites"`
	Expected       string   `json:"expected"`
	State          string   `json:"state"`
	Implementation string   `json:"implementation,omitempty"`
	Tests          []string `json:"tests"`
	Evidence       []string `json:"evidence"`
}

type Operation struct {
	Cmdlet         string            `json:"cmdlet"`
	Issues         []string          `json:"issues"`
	APIOwner       string            `json:"api_owner"`
	Mechanism      string            `json:"mechanism"`
	Applicability  Applicability     `json:"applicability"`
	Prerequisites  []string          `json:"prerequisites"`
	Variants       []Variant         `json:"variants"`
	Scenarios      []Scenario        `json:"scenarios"`
	ParameterTests map[string]string `json:"parameter_tests"`
	Evidence       []string          `json:"evidence"`
}
type Inventory struct {
	SchemaVersion int         `json:"schema_version"`
	Differences   []string    `json:"differences"`
	Operations    []Operation `json:"operations"`
}

type ScenarioRequirement struct {
	Cmdlet    string   `json:"cmdlet"`
	Scenarios []string `json:"scenarios"`
}

type ScenarioRequirements struct {
	SchemaVersion int                   `json:"schema_version"`
	Operations    []ScenarioRequirement `json:"operations"`
}

// Evidence is a checked-in result artifact, not a list of planned test names.
// Use explicit "not applicable: ..." environment values for local-only tests.
type Evidence struct {
	Passed        bool     `json:"passed"`
	Tests         []string `json:"tests"`
	ServerVersion string   `json:"server_version"`
	ModuleVersion string   `json:"module_version"`
	HostVersion   string   `json:"host_version"`
	Run           string   `json:"run"`
}

var errInvalidContract = errors.New("invalid coverage contract")

func invalidf(format string, args ...any) error {
	return fmt.Errorf("%w: %s", errInvalidContract, fmt.Sprintf(format, args...))
}

func decode(data []byte, value any) error {
	d := json.NewDecoder(bytes.NewReader(data))
	d.DisallowUnknownFields()
	if err := d.Decode(value); err != nil {
		return fmt.Errorf("decode JSON: %w", err)
	}
	if err := d.Decode(new(any)); err == nil {
		return invalidf("expected one JSON value")
	} else if !errors.Is(err, io.EOF) {
		return fmt.Errorf("decode trailing JSON: %w", err)
	}
	return nil
}

func Load(root string) (Reference, Inventory, error) {
	var r Reference
	var i Inventory
	for _, item := range []struct {
		name  string
		value any
	}{{"reference.json", &r}, {"inventory.json", &i}} {
		data, err := os.ReadFile(filepath.Join(root, "coverage", item.name))
		if err != nil {
			return r, i, fmt.Errorf("read %s: %w", item.name, err)
		}
		if err := decode(data, item.value); err != nil {
			return r, i, fmt.Errorf("%s: %w", item.name, err)
		}
	}
	return r, i, nil
}

func unique(values []string) bool {
	seen := map[string]bool{}
	for _, value := range values {
		if strings.TrimSpace(value) == "" || seen[value] {
			return false
		}
		seen[value] = true
	}
	return true
}

func same(a, b []string) bool {
	if !unique(a) || !unique(b) {
		return false
	}
	a, b = slices.Clone(a), slices.Clone(b)
	slices.Sort(a)
	slices.Sort(b)
	return slices.Equal(a, b)
}

// Validate checks against the separately pinned source snapshot and opens evidence
// through os.Root so paths cannot escape the repository via traversal or symlinks.
func Validate(root string, r Reference, i Inventory) error {
	if r.SchemaVersion != 1 || i.SchemaVersion != 2 {
		return invalidf("unsupported schema version")
	}
	if r.Repository != "https://github.com/MicrosoftDocs/windows-powershell-docs" ||
		r.View != "windowsserver2025-ps" ||
		!regexp.MustCompile(`^[a-f0-9]{40}$`).MatchString(r.Commit) {
		return invalidf("invalid source provenance")
	}
	if len(r.Commands) == 0 || len(i.Differences) == 0 || !unique(i.Differences) {
		return invalidf("missing commands or compatibility differences")
	}
	fs, err := os.OpenRoot(root)
	if err != nil {
		return fmt.Errorf("open repository root: %w", err)
	}
	defer fs.Close()
	requirements, err := loadScenarioRequirements(fs)
	if err != nil {
		return err
	}
	commands, err := indexReferenceCommands(r)
	if err != nil {
		return err
	}
	if len(requirements) != len(commands) {
		return invalidf("scenario requirements differ from the approved command inventory")
	}
	seen := map[string]bool{}
	for _, op := range i.Operations {
		c, ok := commands[op.Cmdlet]
		if !ok || seen[op.Cmdlet] {
			return invalidf("unknown/duplicate operation %q", op.Cmdlet)
		}
		seen[op.Cmdlet] = true
		names := make([]string, 0, len(op.Scenarios))
		for _, scenario := range op.Scenarios {
			names = append(names, scenario.Name)
		}
		if !same(names, requirements[op.Cmdlet]) {
			return invalidf(
				"%s: behavioral scenarios differ from the approved requirements",
				op.Cmdlet,
			)
		}
		if err := validateOperation(fs, c, op); err != nil {
			return fmt.Errorf("%s: %w", op.Cmdlet, err)
		}
	}
	if len(seen) != len(commands) {
		return invalidf("missing operations: have %d, need %d", len(seen), len(commands))
	}
	return nil
}

func indexReferenceCommands(r Reference) (map[string]Command, error) {
	commands := map[string]Command{}
	for _, c := range r.Commands {
		if _, exists := commands[c.Name]; exists || c.Name == "" {
			return nil, invalidf("duplicate/empty reference command %q", c.Name)
		}
		if !regexp.MustCompile(`^[a-f0-9]{64}$`).MatchString(c.SHA256) ||
			!strings.Contains(c.Source, "/blob/"+r.Commit+"/") {
			return nil, invalidf("%s: invalid document provenance", c.Name)
		}
		if len(c.ParameterSets) == 0 || !unique(c.Parameters) {
			return nil, invalidf("%s: invalid reference parameters", c.Name)
		}
		sets := map[string]bool{}
		for _, s := range c.ParameterSets {
			if s.Name == "" || sets[s.Name] || !unique(s.Parameters) {
				return nil, invalidf("%s: duplicate/invalid source parameter set", c.Name)
			}
			sets[s.Name] = true
			for _, p := range s.Parameters {
				if !slices.Contains(c.Parameters, p) {
					return nil, invalidf("%s: unknown source parameter %s", c.Name, p)
				}
			}
		}
		commands[c.Name] = c
	}
	return commands, nil
}

func loadScenarioRequirements(fs *os.Root) (map[string][]string, error) {
	data, err := fs.ReadFile("coverage/scenario-requirements.json")
	if err != nil {
		return nil, fmt.Errorf("read scenario requirements: %w", err)
	}
	var requirements ScenarioRequirements
	if err := decode(data, &requirements); err != nil {
		return nil, fmt.Errorf("decode scenario requirements: %w", err)
	}
	if requirements.SchemaVersion != 1 || len(requirements.Operations) == 0 {
		return nil, invalidf("invalid scenario requirements version or empty command list")
	}
	result := map[string][]string{}
	for _, operation := range requirements.Operations {
		if operation.Cmdlet == "" || result[operation.Cmdlet] != nil ||
			len(operation.Scenarios) == 0 || !unique(operation.Scenarios) {
			return nil, invalidf(
				"duplicate/incomplete scenario requirements for %q",
				operation.Cmdlet,
			)
		}
		result[operation.Cmdlet] = operation.Scenarios
	}
	return result, nil
}

func validateOperation(fs *os.Root, c Command, op Operation) error {
	if err := validateOperationMetadata(c, op); err != nil {
		return err
	}
	if err := validateScenarios(fs, c, op); err != nil {
		return err
	}
	return validateVariants(fs, c, op)
}

func validateOperationMetadata(c Command, op Operation) error {
	if op.APIOwner == "" || op.Mechanism == "" || len(op.Issues) == 0 || !unique(op.Issues) ||
		len(op.Prerequisites) == 0 ||
		!unique(op.Prerequisites) {
		return invalidf("missing ownership, mechanism, or prerequisites")
	}
	for _, issue := range op.Issues {
		if !regexp.MustCompile(`^https://github.com/deploymenttheory/go-sdk-activedirectory/issues/[1-9][0-9]*$`).
			MatchString(issue) {
			return invalidf("invalid owning issue %q", issue)
		}
	}
	for _, applicability := range []string{op.Applicability.ADDS, op.Applicability.ADLDS} {
		if !slices.Contains([]string{"unverified", "documented", "unsupported"}, applicability) {
			return invalidf("invalid applicability %q", applicability)
		}
	}
	if op.Applicability.Notes == "" {
		return invalidf("applicability explanation required")
	}
	params := make([]string, 0, len(op.ParameterTests))
	ids := make([]string, 0, len(op.ParameterTests))
	for p, id := range op.ParameterTests {
		if id == "" {
			return invalidf("parameter %s has no planned test", p)
		}
		params = append(params, p)
		ids = append(ids, id)
	}
	if !unique(ids) {
		return invalidf("parameter test identifiers must be distinct")
	}
	if !same(params, c.Parameters) {
		return invalidf("parameter coverage differs from source")
	}
	return nil
}

func validateVariants(fs *os.Root, c Command, op Operation) error {
	sets := map[string]ParameterSet{}
	for _, s := range c.ParameterSets {
		sets[s.Name] = s
	}
	seen := map[string]bool{}
	for _, v := range op.Variants {
		s, ok := sets[v.Name]
		if !ok || seen[v.Name] || !same(s.Parameters, v.Parameters) {
			return invalidf("unknown, duplicate, or incomplete variant %q", v.Name)
		}
		seen[v.Name] = true
		if len(v.Tests) == 0 || !unique(v.Tests) {
			return invalidf("%s: test identifiers required", v.Name)
		}
		if err := validateImplementation(fs, v.State, v.Implementation); err != nil {
			return fmt.Errorf("%s: %w", v.Name, err)
		}
		if v.State == "validated" {
			required := slices.Clone(v.Tests)
			for _, p := range v.Parameters {
				required = append(required, op.ParameterTests[p])
			}
			// Parameters absent from source syntax still need evidence before claiming parity.
			for _, p := range c.Parameters {
				inSyntax := false
				for _, set := range c.ParameterSets {
					inSyntax = inSyntax || slices.Contains(set.Parameters, p)
				}
				if !inSyntax {
					required = append(required, op.ParameterTests[p])
				}
			}
			if err := validateEvidence(
				fs,
				append(slices.Clone(op.Evidence), v.Evidence...),
				required,
			); err != nil {
				return fmt.Errorf("%s: %w", v.Name, err)
			}
		}
	}
	if len(seen) != len(sets) {
		return invalidf("missing parameter variants")
	}
	return nil
}

func validateImplementation(fs *os.Root, state, implementation string) error {
	if !slices.Contains([]string{"unverified", "implemented", "validated"}, state) {
		return invalidf("invalid state %q", state)
	}
	if state == "unverified" {
		return nil
	}
	if !filepath.IsLocal(implementation) {
		return invalidf("local implementation required")
	}
	info, err := fs.Stat(implementation)
	if err != nil || !info.Mode().IsRegular() {
		return invalidf("implementation file missing")
	}
	return nil
}

func validateScenarios(fs *os.Root, c Command, op Operation) error {
	if len(op.Scenarios) == 0 {
		return invalidf("behavioral scenarios required")
	}
	names := map[string]bool{}
	tests := map[string]bool{}
	for _, id := range op.ParameterTests {
		tests[id] = true
	}
	for _, v := range op.Variants {
		for _, id := range v.Tests {
			tests[id] = true
		}
	}
	for _, s := range op.Scenarios {
		if !regexp.MustCompile(`^[a-z][a-z0-9-]*$`).MatchString(s.Name) || names[s.Name] {
			return invalidf("duplicate or invalid scenario %q", s.Name)
		}
		names[s.Name] = true
		if strings.TrimSpace(s.Description) == "" || strings.TrimSpace(s.Expected) == "" ||
			len(s.Prerequisites) == 0 || !unique(s.Prerequisites) || !unique(s.Parameters) ||
			len(s.Tests) == 0 || !unique(s.Tests) {
			return invalidf(
				"%s: scenario needs description, outcome, prerequisites, and tests",
				s.Name,
			)
		}
		for _, p := range s.Parameters {
			if !slices.Contains(c.Parameters, p) {
				return invalidf("%s: unknown scenario parameter %q", s.Name, p)
			}
		}
		for _, id := range s.Tests {
			if tests[id] {
				return invalidf("%s: scenario must have distinct test identifiers", s.Name)
			}
			tests[id] = true
		}
		if err := validateImplementation(fs, s.State, s.Implementation); err != nil {
			return fmt.Errorf("scenario %s: %w", s.Name, err)
		}
		if s.State == "validated" {
			if err := validateEvidence(
				fs,
				append(slices.Clone(op.Evidence), s.Evidence...),
				s.Tests,
			); err != nil {
				return fmt.Errorf("scenario %s: %w", s.Name, err)
			}
		}
	}
	return nil
}

func validateEvidence(fs *os.Root, paths, required []string) error {
	if len(paths) == 0 || !unique(paths) {
		return invalidf("validated variant requires unique evidence paths")
	}
	passed := map[string]bool{}
	for _, path := range paths {
		if !filepath.IsLocal(path) {
			return invalidf("evidence must be repository-local")
		}
		data, err := fs.ReadFile(path)
		if err != nil {
			return fmt.Errorf("read evidence: %w", err)
		}
		var e Evidence
		if err := decode(data, &e); err != nil {
			return fmt.Errorf("decode evidence: %w", err)
		}
		if !e.Passed || e.ServerVersion == "" || e.ModuleVersion == "" || e.HostVersion == "" ||
			e.Run == "" ||
			len(e.Tests) == 0 ||
			!unique(e.Tests) {
			return invalidf("evidence needs passing results, versions, and run provenance")
		}
		for _, test := range e.Tests {
			passed[test] = true
		}
	}
	for _, test := range required {
		if !passed[test] {
			return invalidf("missing passing evidence for %s", test)
		}
	}
	return nil
}

func State(op Operation) string {
	state := "validated"
	for _, v := range op.Variants {
		state = leastAdvanced(state, v.State)
	}
	for _, s := range op.Scenarios {
		state = leastAdvanced(state, s.State)
	}
	return state
}

func leastAdvanced(a, b string) string {
	if a == "unverified" || b == "unverified" {
		return "unverified"
	}
	if a == "implemented" || b == "implemented" {
		return "implemented"
	}
	return "validated"
}

func Report(r Reference, i Inventory) []byte {
	var out strings.Builder
	fmt.Fprintln(
		&out,
		"# Active Directory operation coverage\n\nGenerated by `go run ./cmd/adcoverage -write`. Do not edit this report directly.",
	)
	fmt.Fprintf(
		&out,
		"\nSource: [Microsoft documentation commit `%s`](%s/tree/%s/docset/winserver2025-ps/ActiveDirectory).\n",
		r.Commit,
		r.Repository,
		r.Commit,
	)
	counts := map[string]int{}
	for _, op := range i.Operations {
		counts[State(op)]++
	}
	fmt.Fprintf(
		&out,
		"\n%d operations: **%d validated**, **%d implemented**, **%d unverified**. Planned test identifiers are not passing evidence. Applicability is separate from implementation status.\n",
		len(i.Operations),
		counts["validated"],
		counts["implemented"],
		counts["unverified"],
	)
	fmt.Fprint(&out, "\n## Agreed differences\n\n")
	for _, d := range i.Differences {
		fmt.Fprintf(&out, "- %s\n", d)
	}
	fmt.Fprintln(
		&out,
		"\n## Operations\n\n| Cmdlet | API owner (planned) | State | Parameter sets | Parameters | Scenarios | AD LDS | Tickets |\n| --- | --- | --- | ---: | ---: | ---: | --- | --- |",
	)
	ops := slices.Clone(i.Operations)
	slices.SortFunc(ops, func(a, b Operation) int { return strings.Compare(a.Cmdlet, b.Cmdlet) })
	for _, op := range ops {
		links := make([]string, 0, len(op.Issues))
		for _, issue := range op.Issues {
			links = append(
				links,
				fmt.Sprintf("[#%s](%s)", issue[strings.LastIndex(issue, "/")+1:], issue),
			)
		}
		fmt.Fprintf(
			&out,
			"| [%s](https://learn.microsoft.com/en-us/powershell/module/activedirectory/%s?view=windowsserver2025-ps) | %s | %s | %d | %d | %d | %s | %s |\n",
			op.Cmdlet,
			strings.ToLower(op.Cmdlet),
			op.APIOwner,
			State(op),
			len(op.Variants),
			len(op.ParameterTests),
			len(op.Scenarios),
			op.Applicability.ADLDS,
			strings.Join(links, ", "),
		)
	}
	fmt.Fprintln(
		&out,
		"\nParameter sets, behavioral scenarios with expected outcomes, individual parameter test IDs, prerequisites, proposed native mechanisms, and evidence paths are in [the inventory](../coverage/inventory.json). A command's status includes every parameter set and scenario. See [the coverage guide](coverage-guide.md) for maintenance and validation rules.",
	)
	return []byte(out.String())
}
