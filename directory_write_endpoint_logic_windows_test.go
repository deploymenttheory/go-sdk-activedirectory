//go:build windows && (amd64 || arm64)

package activedirectory

import (
	"encoding/json"
	"os"
	"testing"
)

// The write-endpoint sweep's decision logic runs only inside the lab, so
// without these tests nothing exercises it. An aggregation that silently
// became permissive would make every future run report success regardless of
// what the directory did.

func passingWriteEndpointObservation() writeEndpointObservation {
	return writeEndpointObservation{
		Cmdlet: "New-ADUser", Role: writeRoleCreate,
		ExplicitServer: "dc1.ad.sdk.test", ExplicitPartition: "DC=ad,DC=sdk,DC=test",
		ExplicitWrote: true, LandedInPartition: true,
		MismatchPartition: "CN=Configuration,DC=ad,DC=sdk,DC=test",
		MismatchDNRefused: true, MismatchDNClass: ClassInvalidRequest.String(),
		MismatchRefused: true, MismatchClass: ClassNotFound.String(),
		MismatchNoWrite: true, Allocations: 0,
	}
}

func TestWriteEndpointObservationRequiresEveryHalf(t *testing.T) {
	if !passingWriteEndpointObservation().qualifies() {
		t.Fatal("the fully satisfied observation does not qualify")
	}
	for _, mutation := range []struct {
		name  string
		apply func(*writeEndpointObservation)
	}{
		{"the explicit endpoint wrote", func(o *writeEndpointObservation) { o.ExplicitWrote = false }},
		{"it landed in the requested partition", func(o *writeEndpointObservation) { o.LandedInPartition = false }},
		{"the distinguished-name mismatch was refused", func(o *writeEndpointObservation) {
			o.MismatchDNRefused = false
		}},
		{"the GUID mismatch was refused", func(o *writeEndpointObservation) { o.MismatchRefused = false }},
		{"the refusal wrote nothing", func(o *writeEndpointObservation) { o.MismatchNoWrite = false }},
		{"native allocations balanced", func(o *writeEndpointObservation) { o.Allocations = 1 }},
	} {
		t.Run(mutation.name, func(t *testing.T) {
			o := passingWriteEndpointObservation()
			mutation.apply(&o)
			if o.qualifies() {
				t.Fatalf("the observation still qualified without %q", mutation.name)
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
	for _, class := range []ErrorClass{ClassInvalidRequest, ClassUnsupported} {
		o := passingWriteEndpointObservation()
		o.MismatchDNClass = class.String()
		if !o.qualifies() {
			t.Errorf("a DN mismatch refused as %s was not accepted", class)
		}
	}
	for _, class := range []ErrorClass{
		ClassUnclassified, ClassDenied, ClassUncertain, ClassConflict,
		ClassNotFound, ClassAlreadyExists, ClassUnverified, ClassIncomplete, ClassTransport,
	} {
		o := passingWriteEndpointObservation()
		o.MismatchDNClass = class.String()
		if o.qualifies() {
			t.Errorf("a DN mismatch reported as %s was accepted; only a request-level "+
				"refusal proves the SDK rejected it without asking the directory", class)
		}
	}

	// A GUID cannot be scope-checked, so the honest answer is that it is not in
	// the requested partition. Anything else would mean another partition was
	// consulted, or that the write was attempted.
	for _, class := range []ErrorClass{
		ClassUnclassified, ClassInvalidRequest, ClassDenied, ClassUncertain,
		ClassConflict, ClassAlreadyExists, ClassUnverified, ClassIncomplete,
		ClassTransport, ClassUnsupported,
	} {
		o := passingWriteEndpointObservation()
		o.MismatchClass = class.String()
		if o.qualifies() {
			t.Errorf("a GUID mismatch reported as %s was accepted; not-found is the "+
				"only answer that proves no other partition was searched", class)
		}
	}
	o := passingWriteEndpointObservation()
	o.MismatchClass = ClassNotFound.String()
	if !o.qualifies() {
		t.Error("a GUID mismatch refused as not-found was not accepted")
	}
}

// Every role is claimed against a real operation in the contract, and that
// operation has to carry the scenario being cited.
func TestWriteEndpointRolesCoverTheContract(t *testing.T) {
	data, err := os.ReadFile("coverage/inventory.json")
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
	for _, target := range lifecycleTargets() {
		for _, cmdlet := range []string{target.createCmdlet, target.updateCmdlet, target.removeCmdlet} {
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
	seen := map[writeEndpointRole]bool{}
	for _, role := range []writeEndpointRole{
		writeRoleCreate, writeRoleUpdate, writeRoleDelete, writeRoleRename,
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
