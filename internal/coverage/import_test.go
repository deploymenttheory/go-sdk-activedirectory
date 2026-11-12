package coverage

import (
	"os"
	"path/filepath"
	"slices"
	"strings"
	"testing"
)

func TestImportKeepsParameterVariantsAndDocumentedOnlyParameters(t *testing.T) {
	dir := t.TempDir()
	source := "# Get-ADExample\r\n\r\n## SYNTAX\r\n\r\n### Identity (Default)\r\n```\r\nGet-ADExample [-Identity] <ADObject> [-Server <String>]\r\n```\r\n### Filter\r\n```powershell\r\nGet-ADExample -Filter <String> [-Server <String>]\r\n```\r\n## PARAMETERS\r\n### -DocumentedOnly\r\nSome prose.\r\n"
	if err := os.WriteFile(
		filepath.Join(dir, "Get-ADExample.md"),
		[]byte(source),
		0o600,
	); err != nil {
		t.Fatal(err)
	}
	r, err := ImportReference(dir, strings.Repeat("a", 40), []string{"Get-ADExample"})
	if err != nil {
		t.Fatal(err)
	}
	c := r.Commands[0]
	if len(c.ParameterSets) != 2 || c.ParameterSets[0].Name != "Identity (Default)" {
		t.Fatalf("sets: %+v", c.ParameterSets)
	}
	if !slices.Equal(c.Parameters, []string{"DocumentedOnly", "Filter", "Identity", "Server"}) {
		t.Fatalf("parameters: %v", c.Parameters)
	}
	if _, err := ImportReference(dir, "main", []string{"Get-ADExample"}); err == nil {
		t.Fatal("accepted moving ref")
	}
	if _, err := ImportReference(
		dir,
		strings.Repeat("a", 40),
		[]string{"../Get-ADExample"},
	); err == nil {
		t.Fatal("accepted traversal")
	}
}

func TestImportUnnamedParameterSet(t *testing.T) {
	dir := t.TempDir()
	if err := os.WriteFile(
		filepath.Join(dir, "Get-ADExample.md"),
		[]byte(
			"## SYNTAX\n```\nGet-ADExample [<CommonParameters>]\n```\n## DESCRIPTION\nExample\n",
		),
		0o600,
	); err != nil {
		t.Fatal(err)
	}
	r, err := ImportReference(dir, strings.Repeat("a", 40), []string{"Get-ADExample"})
	if err != nil {
		t.Fatal(err)
	}
	if r.Commands[0].ParameterSets[0].Name != "Default" ||
		r.Commands[0].ParameterSets[0].Parameters == nil {
		t.Fatal("unnamed parameter set was not normalized")
	}
}
