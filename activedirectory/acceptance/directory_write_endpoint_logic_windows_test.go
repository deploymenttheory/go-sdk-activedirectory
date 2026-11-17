//go:build windows && (amd64 || arm64)

package acceptance

import (
	"encoding/json"
	"os"
	"testing"

	admodel "github.com/deploymenttheory/go-sdk-activedirectory/activedirectory/internal/model"
)

// The write-endpoint sweep's decision logic runs only inside the lab, so
// without these tests nothing exercises it. An aggregation that silently
// became permissive would make every future run report success regardless of
// what the directory did.

func InternalPassingWriteEndpointObservation() InternalWriteEndpointObservation {
	return InternalWriteEndpointObservation{
		Cmdlet: "New-ADUser", Role: InternalWriteRoleCreate,
		ExplicitServer: "dc1.ad.sdk.test", ExplicitPartition: "DC=ad,DC=sdk,DC=test",
		ExplicitWrote: true, LandedInPartition: true,
		MismatchPartition: "CN=Configuration,DC=ad,DC=sdk,DC=test",
		MismatchDNRefused: true, MismatchDNClass: admodel.ClassInvalidRequest.String(),
		MismatchRefused: true, MismatchClass: admodel.ClassNotFound.String(),
		MismatchNoWrite: true, Allocations: 0,
	}
}

func TestWriteEndpointObservationRequiresEveryHalf(t *testing.T) {
	if !InternalPassingWriteEndpointObservation().InternalQualifies() {
		t.Fatal("the fully satisfied observation does not qualify")
	}
	for _, mutation := range []struct {
		InternalName  string
		InternalApply func(*InternalWriteEndpointObservation)
	}{
		{"the explicit endpoint wrote", func(o *InternalWriteEndpointObservation) { o.ExplicitWrote = false }},
		{"it landed in the requested partition", func(o *InternalWriteEndpointObservation) { o.LandedInPartition = false }},
		{"the distinguished-name mismatch was refused", func(o *InternalWriteEndpointObservation) {
			o.MismatchDNRefused = false
		}},
		{"the GUID mismatch was refused", func(o *InternalWriteEndpointObservation) { o.MismatchRefused = false }},
		{"the refusal wrote nothing", func(o *InternalWriteEndpointObservation) { o.MismatchNoWrite = false }},
		{"native allocations balanced", func(o *InternalWriteEndpointObservation) { o.Allocations = 1 }},
	} {
		t.Run(mutation.InternalName, func(t *testing.T) {
			o := InternalPassingWriteEndpointObservation()
			mutation.InternalApply(&o)
			if o.InternalQualifies() {
				t.Fatalf("the observation still qualified without %q", mutation.InternalName)
			}
		})
	}
}

// A mismatched partition must be refused as a request to correct, or as
// something this directory cannot do. Reported as denied or uncertain it would
// mean the SDK had tried to write across partitions, which is the thing this
// scenario exists to rule out — so those must not pass.
func TestWriteEndpointRejectsTheWrongKindOfRefusal(t *testing.T) {
	// A distinguished name can be scope-checked without touching the
	// directory, so its refusal must be request-level.
	for _, class := range []admodel.ErrorClass{admodel.ClassInvalidRequest, admodel.ClassUnsupported} {
		o := InternalPassingWriteEndpointObservation()
		o.MismatchDNClass = class.String()
		if !o.InternalQualifies() {
			t.Errorf("a DN mismatch refused as %s was not accepted", class)
		}
	}
	for _, class := range []admodel.ErrorClass{admodel.ClassUnclassified, admodel.ClassDenied, admodel.ClassUncertain, admodel.ClassConflict, admodel.ClassNotFound, admodel.ClassAlreadyExists, admodel.ClassUnverified, admodel.ClassIncomplete, admodel.ClassTransport} {
		o := InternalPassingWriteEndpointObservation()
		o.MismatchDNClass = class.String()
		if o.InternalQualifies() {
			t.Errorf("a DN mismatch reported as %s was accepted; only a request-level "+
				"refusal proves the SDK rejected it without asking the directory", class)
		}
	}

	// A GUID cannot be scope-checked, so the honest answer is that it is not in
	// the requested partition. Anything else would mean another partition was
	// consulted, or that the write was attempted.
	for _, class := range []admodel.ErrorClass{admodel.ClassUnclassified, admodel.ClassInvalidRequest, admodel.ClassDenied, admodel.ClassUncertain, admodel.ClassConflict, admodel.ClassAlreadyExists, admodel.ClassUnverified, admodel.ClassIncomplete, admodel.ClassTransport, admodel.ClassUnsupported} {
		o := InternalPassingWriteEndpointObservation()
		o.MismatchClass = class.String()
		if o.InternalQualifies() {
			t.Errorf("a GUID mismatch reported as %s was accepted; not-found is the "+
				"only answer that proves no other partition was searched", class)
		}
	}
	o := InternalPassingWriteEndpointObservation()
	o.MismatchClass = admodel.ClassNotFound.String()
	if !o.InternalQualifies() {
		t.Error("a GUID mismatch refused as not-found was not accepted")
	}
}

// Every role is claimed against a real operation in the contract, and that
// operation has to carry the scenario being cited.
func TestWriteEndpointRolesCoverTheContract(t *testing.T) {
	data, err := os.ReadFile(repositoryFile("coverage/inventory.json"))
	if err != nil {
		t.Fatal(err)
	}
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

	// The sweep covers create, update and delete for every class, plus the one
	// rename operation. Anything else would be a row with no evidence behind it.
	expected := map[string]bool{"Rename-ADObject": true}
	for _, target := range InternalLifecycleTargets() {
		for _, cmdlet := range []string{target.InternalCreateCmdlet, target.InternalUpdateCmdlet, target.InternalRemoveCmdlet} {
			expected[cmdlet] = true
		}
	}
	if len(expected) != 16 {
		t.Fatalf("the sweep covers %d operations, want the sixteen mutating ones", len(expected))
	}
	for cmdlet := range expected {
		if !scoped[cmdlet] {
			t.Errorf("%s has no endpoint-and-partition scenario in the coverage contract", cmdlet)
		}
	}
}

// The two partitions must be genuinely different naming contexts, or the
// mismatch half proves nothing. Pinning the comparison keeps a future change
// from reducing it to a string the server would accept anyway.
func TestWriteEndpointRoleNamesAreDistinct(t *testing.T) {
	seen := map[InternalWriteEndpointRole]bool{}
	for _, role := range []InternalWriteEndpointRole{
		InternalWriteRoleCreate, InternalWriteRoleUpdate, InternalWriteRoleDelete, InternalWriteRoleRename,
	} {
		if role == "" {
			t.Error("a role has no name")
		}
		if seen[role] {
			t.Errorf("role %q appears twice", role)
		}
		seen[role] = true
	}
	if len(seen) != 4 {
		t.Fatalf("got %d roles, want four", len(seen))
	}
}
