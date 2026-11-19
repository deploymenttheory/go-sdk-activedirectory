package acceptance

import (
	"context"
	"errors"
	"fmt"
	"testing"

	ad "github.com/deploymenttheory/go-sdk-activedirectory/activedirectory"
)

func TestPortableMutationLabInvisibleProofRequiresKnownVisibilityCauses(t *testing.T) {
	denied := errors.Join(ad.ErrObjectReadback, &ad.SearchError{Cause: &ad.LDAPError{Code: 50}}, ad.ErrObjectWritePermission)
	for _, test := range []struct {
		name string
		err  error
		pass bool
	}{
		{"empty", ad.ErrObjectUnverifiable, true},
		{"not-found", errors.Join(ad.ErrObjectReadback, &ad.SearchError{Cause: &ad.LDAPError{Code: 32}}), true},
		{"denied", denied, true},
		{"refused-control", errors.Join(ad.ErrObjectReadback, &ad.LDAPError{Code: 12}), false},
		{"references", errors.Join(ad.ErrObjectReadback, ad.ErrSearchReferences), false},
		{"denied-with-references", errors.Join(denied, ad.ErrSearchReferences), false},
		{"denied-with-connection", errors.Join(denied, ad.ErrConnection), false},
		{"denied-with-invalid-result", errors.Join(denied, ad.ErrInvalidResult), false},
		{"denied-with-scope", errors.Join(denied, ad.ErrIdentityScope), false},
		{"denied-with-unknown", errors.Join(denied, fmt.Errorf("wrapped: %w", errors.New("private diagnostic is never serialized"))), false},
		{"empty-with-canceled", errors.Join(ad.ErrObjectUnverifiable, context.Canceled), false},
		{"empty-with-timeout", errors.Join(ad.ErrObjectUnverifiable, context.DeadlineExceeded), false},
	} {
		t.Run(test.name, func(t *testing.T) {
			entry := &portableMutationLabCase{}
			portableMutationLabCapture(entry, ad.ObjectMutationResult{}, test.err)
			if portableMutationLabInvisibleProof(entry, test.err) != test.pass {
				t.Fatal("invisible proof accepted an unknown/mixed cause or rejected the documented visibility outcome", entry.ErrorFacts)
			}
		})
	}
}

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
