package acceptance

import (
	"encoding/json"
	"math"
	"os"
	"slices"
	"testing"

	admodel "github.com/deploymenttheory/go-sdk-activedirectory/activedirectory/internal/model"
)

func TestAccountExpirationInstalledModuleReference(t *testing.T) {
	data, err := os.ReadFile(repositoryFile("testdata/account-expiration-reference.json"))
	if err != nil {
		t.Fatal(err)
	}
	// Windows PowerShell UTF8 output may include the BOM.
	if len(data) >= 3 && string(data[:3]) == "\xef\xbb\xbf" {
		data = data[3:]
	}
	var reference struct {
		Schema    int    `json:"schema_version"`
		Source    string `json:"source"`
		Contacted bool   `json:"directory_contacted"`
		Module    string `json:"module_version"`
		Assembly  string `json:"assembly_file_version"`
		State     struct {
			Ge      int `json:"greater_or_equal_operator"`
			Methods []struct {
				Method string
				SHA    string `json:"il_sha256"`
			}
			Mappings []struct {
				Table, Property string
				Attributes      []string
			}
		} `json:"state_inspection"`
		Cases []struct {
			Kind, Instant string
			Value         string `json:"ldap_value"`
		}
	}
	if err := json.Unmarshal(data, &reference); err != nil {
		t.Fatal(err)
	}
	if reference.Schema != 1 || reference.Source != "offline_module_converter" ||
		reference.Contacted ||
		reference.Module == "" ||
		reference.Assembly == "" ||
		len(reference.Cases) != 4 {
		t.Fatal("missing offline provenance")
	}
	if reference.State.Ge != 2 || len(reference.State.Methods) != 3 ||
		len(reference.State.Mappings) != 6 {
		t.Fatal("missing state inspection provenance")
	}
	for _, method := range reference.State.Methods {
		if method.Method == "" || len(method.SHA) != 64 {
			t.Fatal(method)
		}
	}
	for _, mapping := range reference.State.Mappings {
		kind := admodel.DirectoryADDS
		if mapping.Table == "ADAMMappingTable" {
			kind = admodel.DirectoryADLDS
		} else if mapping.Table != "ADMappingTable" {
			t.Fatal(mapping.Table)
		}
		condition := map[string]admodel.AccountStateCondition{"LockedOut": admodel.AccountLockedOut, "PasswordExpired": admodel.AccountPasswordExpired, "LastLogonDate": admodel.AccountInactive}[mapping.Property]
		if condition == 0 || len(mapping.Attributes) == 0 {
			t.Fatal(mapping)
		}
		attribute := mapping.Attributes[0]
		if kind == admodel.DirectoryADDS && condition != admodel.AccountInactive {
			attribute = "msDS-User-Account-Control-Computed"
		}
		if !slices.Contains(mapping.Attributes, attribute) ||
			!slices.Contains(
				admodel.InternalAccountStateProperties(
					admodel.AccountStateQuery{Condition: condition},
					kind,
				),
				attribute,
			) {
			t.Fatal(mapping, attribute)
		}
	}
	for _, row := range reference.Cases {
		value := admodel.FileTime(math.MaxInt64)
		if row.Kind == "set" {
			var err error
			value, err = admodel.InternalFiniteAccountTime(InternalAccountStateTime(t, row.Instant))
			if err != nil {
				t.Fatal(err)
			}
		} else if row.Kind != "clear" {
			t.Fatal(row.Kind)
		}
		if value.LDAPString() != row.Value {
			t.Fatal(row, value.LDAPString())
		}
	}
}
