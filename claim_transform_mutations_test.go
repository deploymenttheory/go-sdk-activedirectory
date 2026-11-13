package activedirectory

import (
	"errors"
	"slices"
	"strings"
	"testing"
)

func TestClaimTransformManagedAttributesRejected(t *testing.T) {
	// A raw write to the rules attribute would bypass rule validation and the
	// CDATA envelope entirely.
	if !slices.Contains(claimTransformManaged, claimTransformRules) {
		t.Fatal("the rules attribute must be managed")
	}
	for _, managed := range claimTransformManaged {
		if err := claimTransformRawChanges([]AttributeChange{{Attribute: strings.ToUpper(managed), Kind: AttributeSet}}); !errors.Is(err, ErrClaimTransformPolicy) {
			t.Fatalf("raw change to %q must be rejected, got %v", managed, err)
		}
		if err := claimTransformRawAttributes(map[string][]RawValue{managed: nil}); !errors.Is(err, ErrClaimTransformPolicy) {
			t.Fatalf("raw attribute %q must be rejected, got %v", managed, err)
		}
	}
	if err := claimTransformRawChanges([]AttributeChange{{Attribute: "adminDescription", Kind: AttributeSet}}); err != nil {
		t.Fatalf("an unmanaged change must be accepted: %v", err)
	}
}

func TestClaimTransformUpdateChangesRejectContradictions(t *testing.T) {
	text := "x"
	for name, request := range map[string]UpdateClaimTransformPolicyRequest{
		"description set and cleared": {Description: &text, ClearDescription: true},
		"rules set and cleared":       {Rules: ClaimTransformRuleSet{AllowAll: true}, ClearRules: true},
	} {
		if _, err := claimTransformUpdateChanges(request); !errors.Is(err, ErrClaimTransformPolicy) {
			t.Fatalf("%s: expected ErrClaimTransformPolicy, got %v", name, err)
		}
	}
	// Two rule forms at once is still a contradiction through the update path.
	if _, err := claimTransformUpdateChanges(UpdateClaimTransformPolicyRequest{Rules: ClaimTransformRuleSet{AllowAll: true, DenyAll: true}}); !errors.Is(err, ErrClaimTransformPolicy) {
		t.Fatalf("conflicting rule forms must be rejected: %v", err)
	}
}

func TestClaimTransformUpdateChangesRendersEnvelope(t *testing.T) {
	changes, err := claimTransformUpdateChanges(UpdateClaimTransformPolicyRequest{Rules: ClaimTransformRuleSet{DenyAll: true}})
	if err != nil {
		t.Fatal(err)
	}
	change, found := claimChangeFor(changes, claimTransformRules)
	if !found || change.Kind != AttributeSet || len(change.Values) != 1 {
		t.Fatalf("rules change missing or malformed: %+v", change)
	}
	stored := string(change.Values[0].Bytes())
	if !strings.HasPrefix(stored, " <ClaimsTransformationPolicy>") || !strings.Contains(stored, `C1:[Type !~ "*"]=>Issue(claim=C1);`) {
		t.Fatalf("update did not write the observed envelope: %q", stored)
	}
}

func TestClaimTransformUpdateChangesClears(t *testing.T) {
	changes, err := claimTransformUpdateChanges(UpdateClaimTransformPolicyRequest{ClearRules: true, ClearDescription: true})
	if err != nil {
		t.Fatal(err)
	}
	for _, attribute := range []string{claimTransformRules, "description"} {
		change, found := claimChangeFor(changes, attribute)
		if !found || change.Kind != AttributeClear {
			t.Fatalf("%s: expected a clear, got %+v", attribute, change)
		}
	}
}

func TestClaimTransformUpdateEmptyRequestChangesNothing(t *testing.T) {
	// A zero rule set must not be read as "deny all"; it changes nothing.
	changes, err := claimTransformUpdateChanges(UpdateClaimTransformPolicyRequest{})
	if err != nil || len(changes) != 0 {
		t.Fatalf("an empty request must render no changes: %+v err=%v", changes, err)
	}
}

func TestClaimTransformDirectionAttribute(t *testing.T) {
	// The direction maps one-to-one onto the stored attribute. No TrustRole is
	// inferred, because that correspondence has not been qualified.
	egress, err := ClaimTransformEgress.attribute()
	if err != nil || egress != "msDS-EgressClaimsTransformationPolicy" {
		t.Fatalf("egress: %q %v", egress, err)
	}
	ingress, err := ClaimTransformIngress.attribute()
	if err != nil || ingress != "msDS-IngressClaimsTransformationPolicy" {
		t.Fatalf("ingress: %q %v", ingress, err)
	}
	if egress == ingress {
		t.Fatal("the two directions must not share an attribute")
	}
	for _, invalid := range []ClaimTransformDirection{0, 3, 255} {
		if _, err := invalid.attribute(); !errors.Is(err, ErrClaimTransformLink) {
			t.Fatalf("direction %d must be rejected, got %v", invalid, err)
		}
	}
}

func TestClaimTransformLinkRequiresDirectionAndPolicy(t *testing.T) {
	client := &Client{}
	// An unset direction is refused before anything is resolved.
	if _, err := client.SetClaimTransformLink(t.Context(), ClaimTransformLinkRequest{}); !errors.Is(err, ErrClaimTransformLink) {
		t.Fatalf("missing direction must be rejected, got %v", err)
	}
	trust, err := IdentityByDN("CN=partner,CN=System,DC=example")
	if err != nil {
		t.Fatal(err)
	}
	// Setting a link with no policy identity cannot proceed; clearing can.
	_, err = client.SetClaimTransformLink(t.Context(), ClaimTransformLinkRequest{Trust: trust, Direction: ClaimTransformEgress})
	if !errors.Is(err, ErrClaimTransformLink) || !errors.Is(err, ErrInvalidIdentity) {
		t.Fatalf("a set without a policy must be rejected, got %v", err)
	}
}
