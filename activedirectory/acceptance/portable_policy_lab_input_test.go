package acceptance

import (
	"bytes"
	"encoding/json"
	"fmt"
	"strings"
	"testing"

	ad "github.com/deploymenttheory/go-sdk-activedirectory/activedirectory"
	admodel "github.com/deploymenttheory/go-sdk-activedirectory/activedirectory/internal/model"
)

func portablePolicyLabTestInput() portablePolicyLabInput {
	input := portablePolicyLabInput{
		RunID: "sdk08-offline-case", CredentialSource: "password", Password: []byte("fixture-policy-lab-only"),
		Endpoint: "adsdk25dc1.ad.sdk.test:389", SPN: "ldap/adsdk25dc1.ad.sdk.test", Realm: "AD.SDK.TEST", Username: "owned-actor",
	}
	for i, role := range []string{"auth", "auth-denied", "rule", "rule-denied"} {
		parent := "CN=AuthN Policies,CN=AuthN Policy Configuration,CN=Services," + portablePolicyConfiguration
		if strings.HasPrefix(role, "rule") {
			parent = admodel.InternalCentralAccessParent(portablePolicyConfiguration, false)
		}
		input.Targets = append(input.Targets, portablePolicyLabTarget{
			Role: role, DN: "CN=sdk08-" + input.RunID + "-" + role + "," + parent,
			GUID: fmt.Sprintf("00112233-4455-6677-8899-%012d", i+1),
		})
	}
	return input
}

func TestPortablePolicyLabRejectsUnownedOrAmbiguousTargets(t *testing.T) {
	valid := portablePolicyLabTestInput()
	defer clear(valid.Password)
	if targets, err := portablePolicyLabTargets(valid); err != nil || len(targets) != 4 {
		t.Fatal("valid explicit four-object scope rejected", err)
	}
	for _, change := range []func(*portablePolicyLabInput){
		func(input *portablePolicyLabInput) { input.RunID = "../escape" },
		func(input *portablePolicyLabInput) { input.Targets = input.Targets[:3] },
		func(input *portablePolicyLabInput) { input.Targets[0].Role = "foreign" },
		func(input *portablePolicyLabInput) { input.Targets[0].DN = "CN=foreign," + portablePolicyConfiguration },
		func(input *portablePolicyLabInput) { input.Targets[0].GUID = "00000000-0000-0000-0000-000000000000" },
		func(input *portablePolicyLabInput) { input.Targets[0].GUID = input.Targets[1].GUID },
		func(input *portablePolicyLabInput) { input.Targets[0] = input.Targets[1] },
	} {
		input := valid
		input.Targets = append([]portablePolicyLabTarget(nil), valid.Targets...)
		change(&input)
		if _, err := portablePolicyLabTargets(input); err == nil {
			t.Fatal("unsafe or ambiguous policy targets were accepted")
		}
	}
}

func TestPortablePolicyLabInputIsBoundedExplicitAndRedacted(t *testing.T) {
	input := portablePolicyLabTestInput()
	defer clear(input.Password)
	config, err := portablePolicyLabConfig(input)
	if err != nil || config.Backend != ad.BackendPortable || config.Authentication != ad.AuthenticationKerberos ||
		config.SASLProtection != ad.SASLProtectionSeal || config.Kerberos.Source != ad.KerberosPassword {
		t.Fatal("policy collector did not require explicit public Kerberos Seal", err)
	}
	for _, format := range []string{"%v", "%+v", "%#v", "%s", "%q", "%d", "%x"} {
		if text := fmt.Sprintf(format, map[string]any{"nested": input}); strings.Contains(text, "fixture-policy-lab-only") {
			t.Fatal("policy credential escaped a formatting hook")
		}
	}
	encoded, err := json.Marshal(struct{ Input portablePolicyLabInput }{input})
	if err != nil || bytes.Contains(encoded, []byte("password")) || !bytes.Contains(encoded, []byte(`"redacted":true`)) {
		t.Fatal("policy input JSON did not redact credentials", err)
	}
	for _, text := range []string{"[]", "{}{}", `{"unknown":"fixture-policy-lab-only"}`, strings.Repeat("x", 128*1024+1)} {
		decoded, err := portableReadPolicyLabInput(strings.NewReader(text))
		clear(decoded.Password)
		if err == nil || strings.Contains(err.Error(), "fixture-policy-lab-only") {
			t.Fatal("malformed stdin was accepted or disclosed its payload")
		}
	}
	input.CachePath = "explicit-cache.ccache"
	if _, err := portablePolicyLabConfig(input); err == nil {
		t.Fatal("conflicting password/cache inputs were accepted")
	}
	input.Password, input.CredentialSource = nil, "cache"
	config, err = portablePolicyLabConfig(input)
	if err != nil || config.Kerberos.Source != ad.KerberosCredentialCacheFile {
		t.Fatal("explicit caller-owned FILE cache was rejected", err)
	}
}
