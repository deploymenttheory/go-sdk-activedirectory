package coverage

import (
	"os"
	"path/filepath"
	"slices"
	"testing"
)

func TestRejectIncompleteBehavioralScenarios(t *testing.T) {
	cases := []struct {
		name   string
		mutate func(*Operation)
	}{
		{"missing scenarios", func(op *Operation) { op.Scenarios = nil }},
		{
			"duplicate scenarios",
			func(op *Operation) { op.Scenarios = append(op.Scenarios, op.Scenarios[0]) },
		},
		{"no description", func(op *Operation) { op.Scenarios[0].Description = " " }},
		{"no expected outcome", func(op *Operation) { op.Scenarios[0].Expected = "" }},
		{"no prerequisites", func(op *Operation) { op.Scenarios[0].Prerequisites = nil }},
		{
			"unknown parameter",
			func(op *Operation) { op.Scenarios[0].Parameters = []string{"Typo"} },
		},
		{"no tests", func(op *Operation) { op.Scenarios[0].Tests = nil }},
		{
			"reused parameter test",
			func(op *Operation) { op.Scenarios[0].Tests = []string{"parameter/Identity"} },
		},
		{
			"reused variant test",
			func(op *Operation) { op.Scenarios[0].Tests = []string{"identity/success"} },
		},
		{"invented state", func(op *Operation) { op.Scenarios[0].State = "complete" }},
		{"missing implementation", func(op *Operation) { op.Scenarios[0].State = "implemented" }},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			r, i := fixture()
			tc.mutate(&i.Operations[0])
			if err := Validate(t.TempDir(), r, i); err == nil {
				t.Fatal("incomplete behavioral contract accepted")
			}
		})
	}
}

func TestBehavioralCoverageCannotBorrowParameterSetEvidence(t *testing.T) {
	root := t.TempDir()
	r, i := fixture()
	if err := os.WriteFile(
		filepath.Join(root, "impl.go"),
		[]byte("package example\n"),
		0o600,
	); err != nil {
		t.Fatal(err)
	}
	op := &i.Operations[0]
	op.Variants[0].State = "validated"
	op.Variants[0].Implementation = "impl.go"
	op.Evidence = []string{"result.json"}
	e := Evidence{
		Passed:        true,
		Tests:         []string{"identity/success", "parameter/Identity"},
		ServerVersion: "2025 build",
		ModuleVersion: "1.0.1.0",
		HostVersion:   "Windows amd64 build",
		Run:           "run-1",
	}
	writeJSON(t, filepath.Join(root, "result.json"), e)
	if err := Validate(root, r, i); err != nil {
		t.Fatal(err)
	}
	if State(*op) != "unverified" {
		t.Fatal("parameter-set validation hid an unverified behavior")
	}
	op.Scenarios[0].State = "implemented"
	op.Scenarios[0].Implementation = "impl.go"
	if State(*op) != "implemented" {
		t.Fatal("scenario progress was ignored")
	}
	op.Scenarios[0].State = "validated"
	if err := Validate(root, r, i); err == nil {
		t.Fatal("parameter-set results incorrectly validated a behavioral scenario")
	}
	e.Tests = append(e.Tests, "ambiguous-name/failure")
	writeJSON(t, filepath.Join(root, "result.json"), e)
	if err := Validate(root, r, i); err != nil {
		t.Fatal(err)
	}
	if State(*op) != "validated" {
		t.Fatal("complete versioned evidence did not advance the operation")
	}
	e.Passed = false
	writeJSON(t, filepath.Join(root, "result.json"), e)
	if err := Validate(root, r, i); err == nil {
		t.Fatal("failed scenario evidence accepted")
	}
	op.Scenarios[0].Evidence = []string{"../escape.json"}
	if err := Validate(root, r, i); err == nil {
		t.Fatal("escaping scenario evidence accepted")
	}
}

// These are acceptance requirements, independent of PowerShell's syntax-set names.
// Keep the distinct transitions visible when evolving the inventory.
func TestCriticalWorkflowRequirements(t *testing.T) {
	_, inventory, err := Load(filepath.Join("..", ".."))
	if err != nil {
		t.Fatal(err)
	}
	required := map[string][]string{
		"Move-ADObject": {
			"same-partition-ad-ds",
			"same-partition-ad-lds",
			"cross-domain-user-password",
			"cross-domain-computer-password",
			"cross-domain-preconditions-and-interruption",
		},
		"Set-ADAccountPassword": {"old-password-change", "administrative-reset"},
		"Sync-ADObject": {
			"single-object-shared-partition",
			"rodc-password-only",
		},
		"New-ADServiceAccount": {
			"smsa-creation-prerequisites",
			"gmsa-creation-prerequisites",
			"dmsa-creation-prerequisites",
			"outbound-only-gmsa",
		},
		"Start-ADServiceAccountMigration": {
			"unlinked-to-started",
			"migration-conflict-repeat-and-recovery",
		},
		"Complete-ADServiceAccountMigration": {
			"started-to-completed",
			"migration-conflict-repeat-and-recovery",
		},
		"Undo-ADServiceAccountMigration": {
			"completed-to-started",
			"started-to-unlinked",
			"migration-conflict-repeat-and-recovery",
		},
		"Reset-ADServiceAccountMigration": {
			"reset-from-started",
			"reset-from-completed",
			"reset-from-unlinked",
			"migration-conflict-repeat-and-recovery",
		},
		"New-ADDCCloneConfigFile": {
			"online-cloning-readiness",
			"offline-cloning-configuration",
			"clone-networking-variants",
		},
	}
	for _, role := range []string{"pdc-emulator", "rid-master", "infrastructure-master", "schema-master", "domain-naming-master"} {
		for _, action := range []string{"transfer", "seizure"} {
			required["Move-ADDirectoryServerOperationMasterRole"] = append(
				required["Move-ADDirectoryServerOperationMasterRole"],
				role+"-"+action,
			)
		}
	}
	for command, names := range required {
		t.Run(command, func(t *testing.T) {
			index := slices.IndexFunc(
				inventory.Operations,
				func(op Operation) bool { return op.Cmdlet == command },
			)
			if index < 0 {
				t.Fatal("required operation missing")
			}
			for _, name := range names {
				if !slices.ContainsFunc(
					inventory.Operations[index].Scenarios,
					func(s Scenario) bool { return s.Name == name },
				) {
					t.Errorf("missing required behavior %s", name)
				}
			}
		})
	}
}
