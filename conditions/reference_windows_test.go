//go:build windows && (amd64 || arm64)

package conditions

import (
	"encoding/json"
	"fmt"
	"os"
	"testing"
)

// The isolated PowerShell reference harness requests this corpus from the same
// executable that runs the native tests. Ordinary unit tests do not write files.
func TestEmitReferenceCorpus(t *testing.T) {
	output := os.Getenv("ADSDK_CONDITION_CORPUS")
	if output == "" {
		t.Skip("the isolated reference harness supplies ADSDK_CONDITION_CORPUS")
	}
	type referenceCase struct {
		Name           string `json:"name"`
		Input          string `json:"input"`
		Valid          bool   `json:"valid"`
		Normalized     string `json:"normalized"`
		PolicyProperty string `json:"policy_property,omitempty"`
	}
	var corpus []referenceCase
	for _, fixture := range []struct {
		name           string
		expression     Expression
		policyProperty string
	}{
		{"device-membership-from", MemberOf(true, "S-1-1-0"), "UserAllowedToAuthenticateFrom"},
		{"user-membership-to", MemberOf(false, "S-1-1-0"), "UserAllowedToAuthenticateTo"},
		{"compound-device-from", All(MemberOf(true, "S-1-1-0"), Not(MemberOf(true, "S-1-5-32-544"))), "ServiceAllowedToAuthenticateFrom"},
		{"unicode-literal", Compare(Claim{User, "Department"}, Equal, Text("Cymru £ 😀")), ""},
		{"literal-punctuation", Compare(Claim{User, "Name"}, Equal, Text(`C:\Finance 50%; x);`)), ""},
		{"unknown-directory-claim", Compare(Claim{User, "NotAnActualDirectoryClaim"}, Equal, Text("syntactically-valid")), ""},
	} {
		condition, err := fixture.expression.Render()
		if err != nil {
			t.Fatal(err)
		}
		result, err := Compile(
			ACE{TrusteeSID: "S-1-1-0", AccessMask: 0x100, Condition: fixture.expression},
		)
		if err != nil {
			t.Fatalf("%s: %v", fixture.name, err)
		}
		corpus = append(corpus, referenceCase{
			Name:  fixture.name,
			Input: fmt.Sprintf("D:(XA;;0x100;;;S-1-1-0;%s)", condition), Valid: true,
			Normalized: result, PolicyProperty: fixture.policyProperty,
		})
	}
	for _, fixture := range []struct {
		name, sddl string
		valid      bool
	}{
		{"full-descriptor", "O:SYG:BAD:PAI(A;;GA;;;SY)S:(AU;SA;GA;;;WD)", true},
		{"deny-condition", `D:(XD;;CR;;;WD;(@User.Department == "Finance"))`, true},
		{"malformed-condition", `D:(XA;;CR;;;WD;(@User.Name === "x"))`, false},
		{"malformed-descriptor", "not SDDL", false},
	} {
		normalized, err := NormalizeSDDL(fixture.sddl)
		if (err == nil) != fixture.valid {
			t.Fatalf("%s validity: %v", fixture.name, err)
		}
		corpus = append(
			corpus,
			referenceCase{
				Name:       fixture.name,
				Input:      fixture.sddl,
				Valid:      fixture.valid,
				Normalized: normalized,
			},
		)
	}
	encoded, err := json.MarshalIndent(corpus, "", "  ")
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(output, append(encoded, '\n'), 0o600); err != nil {
		t.Fatal(err)
	}
}
