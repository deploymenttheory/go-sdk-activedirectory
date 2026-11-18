package acceptance

import (
	"testing"

	ad "github.com/deploymenttheory/go-sdk-activedirectory/activedirectory"
)

func TestPortableMutationLabOwnershipScopes(t *testing.T) {
	if portableMutationLabSAM("sdk09-offline", "subject") != "sd9d73ba5feafdb" {
		t.Fatal("Go collector SAM differs from the independently checked PowerShell fixture contract")
	}
	for _, privileged := range []bool{false, true} {
		input := portableMutationLabTestInput(privileged)
		targets, actual, err := portableMutationLabTargets(input)
		if err != nil || actual != privileged || len(targets) != len(input.Targets) {
			t.Fatal("explicit fixture target scope rejected", targets, actual, err)
		}
	}
	for _, mode := range []string{"run", "count", "duplicate-guid", "empty-guid", "unknown-role", "foreign-dn", "mixed-privilege", "missing-parent"} {
		t.Run(mode, func(t *testing.T) {
			input := portableMutationLabTestInput(false)
			switch mode {
			case "run":
				input.RunID = "../../foreign"
			case "count":
				input.Targets = input.Targets[:1]
			case "duplicate-guid":
				input.Targets[1].GUID = input.Targets[0].GUID
			case "empty-guid":
				input.Targets[1].GUID = (ad.GUID{}).String()
			case "unknown-role":
				input.Targets[1].Role = "foreign"
			case "foreign-dn":
				input.Targets[1].DN = "CN=subject,OU=foreign," + portableMutationDomain
			case "mixed-privilege":
				input.Targets[1].Role = "delete-verified"
				input.Targets[1].DN, _ = portableMutationLabDN(input.RunID, "delete-verified")
			case "missing-parent":
				input.Targets[0].Role = "subject"
			}
			if _, _, err := portableMutationLabTargets(input); err == nil {
				t.Fatal("unsafe mutation fixture scope was accepted")
			}
		})
	}
}

func portableMutationLabTestInput(privileged bool) portablePolicyLabInput {
	input := portablePolicyLabInput{RunID: "sdk09-offline"}
	roles := []string{"parent", "subject", "manager", "hidden", "group-allowed", "group-denied", "site", "settings", "delete-unverified"}
	if privileged {
		roles = []string{"parent", "delete-verified"}
	}
	for i, role := range roles {
		guid := ad.GUID{}
		guid[15] = byte(i + 1)
		dn, _ := portableMutationLabDN(input.RunID, role)
		input.Targets = append(input.Targets, portablePolicyLabTarget{Role: role, DN: dn, GUID: guid.String()})
	}
	return input
}
