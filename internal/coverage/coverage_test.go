package coverage

import (
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func fixture() (Reference, Inventory) {
	commit := strings.Repeat("a", 40)
	r := Reference{
		SchemaVersion: 1,
		Repository:    "https://github.com/MicrosoftDocs/windows-powershell-docs",
		Commit:        commit,
		View:          "windowsserver2025-ps",
		Commands: []Command{
			{
				Name:          "Get-ADExample",
				Source:        "https://github.com/MicrosoftDocs/windows-powershell-docs/blob/" + commit + "/example.md",
				SHA256:        strings.Repeat("b", 64),
				ParameterSets: []ParameterSet{{Name: "Identity", Parameters: []string{"Identity"}}},
				Parameters:    []string{"Identity"},
			},
		},
	}
	i := Inventory{
		SchemaVersion: 2,
		Differences:   []string{"No shell runtime"},
		Operations: []Operation{
			{
				Cmdlet: "Get-ADExample",
				Issues: []string{
					"https://github.com/deploymenttheory/go-sdk-activedirectory/issues/7",
				},
				APIOwner:  "Objects",
				Mechanism: "planned LDAP",
				Applicability: Applicability{
					ADDS:  "unverified",
					ADLDS: "unverified",
					Notes: "Verify prerequisites",
				},
				Prerequisites: []string{"Windows"},
				Variants: []Variant{
					{
						Name:       "Identity",
						Parameters: []string{"Identity"},
						State:      "unverified",
						Tests:      []string{"identity/success"},
					},
				},
				ParameterTests: map[string]string{"Identity": "parameter/Identity"},
				Scenarios: []Scenario{
					{
						Name:        "ambiguous-name",
						Description: "Resolve a nonunique account name.",
						Parameters: []string{
							"Identity",
						},
						Prerequisites: []string{"Two matching accounts"},
						Expected:      "Return an ambiguity error, never an arbitrary match.",
						State:         "unverified",
						Tests:         []string{"ambiguous-name/failure"},
					},
				},
			},
		},
	}
	return r, i
}

func fixtureRoot(t *testing.T) string {
	t.Helper()
	root := t.TempDir()
	if err := os.Mkdir(filepath.Join(root, "coverage"), 0o700); err != nil {
		t.Fatal(err)
	}
	writeJSON(
		t,
		filepath.Join(root, "coverage", "scenario-requirements.json"),
		ScenarioRequirements{
			SchemaVersion: 1,
			Operations: []ScenarioRequirement{
				{Cmdlet: "Get-ADExample", Scenarios: []string{"ambiguous-name"}},
			},
		},
	)
	return root
}

func TestRejectCoverageRegressions(t *testing.T) {
	cases := []struct {
		name   string
		mutate func(*Reference, *Inventory)
	}{
		{"missing operation", func(r *Reference, i *Inventory) { i.Operations = nil }},
		{
			"duplicate operation",
			func(r *Reference, i *Inventory) { i.Operations = append(i.Operations, i.Operations[0]) },
		},
		{
			"unknown operation",
			func(r *Reference, i *Inventory) { i.Operations[0].Cmdlet = "Get-Unknown" },
		},
		{"unowned operation", func(r *Reference, i *Inventory) { i.Operations[0].Issues = nil }},
		{"missing variant", func(r *Reference, i *Inventory) { i.Operations[0].Variants = nil }},
		{"duplicate variant", func(r *Reference, i *Inventory) {
			i.Operations[0].Variants = append(i.Operations[0].Variants, i.Operations[0].Variants[0])
		}},
		{
			"missing parameter",
			func(r *Reference, i *Inventory) { delete(i.Operations[0].ParameterTests, "Identity") },
		},
		{
			"missing parameter in variant",
			func(r *Reference, i *Inventory) { i.Operations[0].Variants[0].Parameters = nil },
		},
		{
			"invented state",
			func(r *Reference, i *Inventory) { i.Operations[0].Variants[0].State = "done" },
		},
		{
			"missing implementation",
			func(r *Reference, i *Inventory) { i.Operations[0].Variants[0].State = "implemented" },
		},
		{"unversioned reference", func(r *Reference, i *Inventory) { r.Commit = "main" }},
		{"no compatibility differences", func(r *Reference, i *Inventory) { i.Differences = nil }},
		{
			"missing test identifier",
			func(r *Reference, i *Inventory) { i.Operations[0].Variants[0].Tests = nil },
		},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			r, i := fixture()
			tc.mutate(&r, &i)
			if err := Validate(fixtureRoot(t), r, i); err == nil {
				t.Fatal("invalid coverage accepted")
			}
		})
	}
}

func writeJSON(t *testing.T, path string, value any) {
	t.Helper()
	data, err := json.Marshal(value)
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(path, data, 0o600); err != nil {
		t.Fatal(err)
	}
}

func TestValidatedRequiresActualVersionedPassingEvidence(t *testing.T) {
	root := fixtureRoot(t)
	r, i := fixture()
	if err := os.WriteFile(
		filepath.Join(root, "impl.go"),
		[]byte("package example\n"),
		0o600,
	); err != nil {
		t.Fatal(err)
	}
	v := &i.Operations[0].Variants[0]
	v.State = "validated"
	v.Implementation = "impl.go"
	if err := Validate(root, r, i); err == nil {
		t.Fatal("accepted no evidence")
	}
	v.Evidence = []string{"result.json"}
	e := Evidence{
		Passed:        true,
		Tests:         []string{"identity/success"},
		ServerVersion: "Server 2025 build",
		ModuleVersion: "1.0.1.0",
		HostVersion:   "Windows amd64 build",
		Run:           "https://example.test/run/1",
	}
	writeJSON(t, filepath.Join(root, "result.json"), e)
	if err := Validate(root, r, i); err == nil {
		t.Fatal("accepted missing parameter test result")
	}
	e.Tests = append(e.Tests, "parameter/Identity")
	writeJSON(t, filepath.Join(root, "result.json"), e)
	if err := Validate(root, r, i); err != nil {
		t.Fatal(err)
	}
	e.Passed = false
	writeJSON(t, filepath.Join(root, "result.json"), e)
	if err := Validate(root, r, i); err == nil {
		t.Fatal("accepted failed evidence")
	}
	e.Passed = true
	e.ModuleVersion = ""
	writeJSON(t, filepath.Join(root, "result.json"), e)
	if err := Validate(root, r, i); err == nil {
		t.Fatal("accepted unversioned evidence")
	}
	v.Evidence = []string{"../escape.json"}
	if err := Validate(root, r, i); err == nil {
		t.Fatal("accepted escaping evidence")
	}
}

func TestRepositoryContract(t *testing.T) {
	root := filepath.Join("..", "..")
	r, i, err := Load(root)
	if err != nil {
		t.Fatal(err)
	}
	if len(r.Commands) != 151 {
		t.Fatalf(
			"approved inventory has 151 cmdlets, got %d; inventory changes require explicit review",
			len(r.Commands),
		)
	}
	if err := Validate(root, r, i); err != nil {
		t.Fatal(err)
	}
	got, err := os.ReadFile(filepath.Join(root, "docs", "coverage.md"))
	if err != nil {
		t.Fatal(err)
	}
	if strings.ReplaceAll(string(got), "\r\n", "\n") != string(Report(r, i)) {
		t.Fatal("generated coverage report is stale")
	}
}

func TestStrictJSON(t *testing.T) {
	for _, input := range []string{`{"schema_version":1,"typo":true}`, `{} {}`, `{} garbage`} {
		var i Inventory
		if err := decode([]byte(input), &i); err == nil {
			t.Fatalf("accepted %s", input)
		}
	}
}
