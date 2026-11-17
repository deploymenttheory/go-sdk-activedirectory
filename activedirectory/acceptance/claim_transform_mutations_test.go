package acceptance

import (
	"errors"
	"slices"
	"strings"
	"testing"

	adengine "github.com/deploymenttheory/go-sdk-activedirectory/activedirectory/internal/engine"
	admodel "github.com/deploymenttheory/go-sdk-activedirectory/activedirectory/internal/model"
	adservice_claims "github.com/deploymenttheory/go-sdk-activedirectory/activedirectory/services/claims"
)

func TestClaimTransformManagedAttributesRejected(t *testing.T) {
	// A raw write to the rules attribute would bypass rule validation and the
	// CDATA envelope entirely.
	if !slices.Contains(
		admodel.InternalClaimTransformManaged,
		admodel.InternalClaimTransformRules,
	) {
		t.Fatal("the rules attribute must be managed")
	}
	for _, managed := range admodel.InternalClaimTransformManaged {
		if err := admodel.InternalClaimTransformRawChanges(
			[]admodel.AttributeChange{
				{Attribute: strings.ToUpper(managed), Kind: admodel.AttributeSet},
			},
		); !errors.Is(
			err,
			admodel.ErrClaimTransformPolicy,
		) {
			t.Fatalf("raw change to %q must be rejected, got %v", managed, err)
		}
		if err := admodel.InternalClaimTransformRawAttributes(
			map[string][]admodel.RawValue{managed: nil},
		); !errors.Is(
			err,
			admodel.ErrClaimTransformPolicy,
		) {
			t.Fatalf("raw attribute %q must be rejected, got %v", managed, err)
		}
	}
	if err := admodel.InternalClaimTransformRawChanges(
		[]admodel.AttributeChange{{Attribute: "adminDescription", Kind: admodel.AttributeSet}},
	); err != nil {
		t.Fatalf("an unmanaged change must be accepted: %v", err)
	}
}

func TestClaimTransformUpdateChangesRejectContradictions(t *testing.T) {
	text := "x"
	for name, request := range map[string]admodel.UpdateClaimTransformPolicyRequest{
		"description set and cleared": {Description: &text, ClearDescription: true},
		"rules set and cleared":       {Rules: admodel.ClaimTransformRuleSet{AllowAll: true}, ClearRules: true},
	} {
		if _, err := admodel.InternalClaimTransformUpdateChanges(
			request,
		); !errors.Is(
			err,
			admodel.ErrClaimTransformPolicy,
		) {
			t.Fatalf("%s: expected ErrClaimTransformPolicy, got %v", name, err)
		}
	}
	// Two rule forms at once is still a contradiction through the update path.
	if _, err := admodel.InternalClaimTransformUpdateChanges(
		admodel.UpdateClaimTransformPolicyRequest{
			Rules: admodel.ClaimTransformRuleSet{AllowAll: true, DenyAll: true},
		},
	); !errors.Is(
		err,
		admodel.ErrClaimTransformPolicy,
	) {
		t.Fatalf("conflicting rule forms must be rejected: %v", err)
	}
}

func TestClaimTransformUpdateChangesRendersEnvelope(t *testing.T) {
	changes, err := admodel.InternalClaimTransformUpdateChanges(
		admodel.UpdateClaimTransformPolicyRequest{
			Rules: admodel.ClaimTransformRuleSet{DenyAll: true},
		},
	)
	if err != nil {
		t.Fatal(err)
	}
	change, found := InternalClaimChangeFor(changes, admodel.InternalClaimTransformRules)
	if !found || change.Kind != admodel.AttributeSet || len(change.Values) != 1 {
		t.Fatalf("rules change missing or malformed: %+v", change)
	}
	stored := string(change.Values[0].Bytes())
	if !strings.HasPrefix(stored, " <ClaimsTransformationPolicy>") ||
		!strings.Contains(stored, `C1:[Type !~ "*"]=>Issue(claim=C1);`) {
		t.Fatalf("update did not write the observed envelope: %q", stored)
	}
}

func TestClaimTransformUpdateChangesClears(t *testing.T) {
	changes, err := admodel.InternalClaimTransformUpdateChanges(
		admodel.UpdateClaimTransformPolicyRequest{ClearRules: true, ClearDescription: true},
	)
	if err != nil {
		t.Fatal(err)
	}
	for _, attribute := range []string{admodel.InternalClaimTransformRules, "description"} {
		change, found := InternalClaimChangeFor(changes, attribute)
		if !found || change.Kind != admodel.AttributeClear {
			t.Fatalf("%s: expected a clear, got %+v", attribute, change)
		}
	}
}

func TestClaimTransformUpdateEmptyRequestChangesNothing(t *testing.T) {
	// A zero rule set must not be read as "deny all"; it changes nothing.
	changes, err := admodel.InternalClaimTransformUpdateChanges(
		admodel.UpdateClaimTransformPolicyRequest{},
	)
	if err != nil || len(changes) != 0 {
		t.Fatalf("an empty request must render no changes: %+v err=%v", changes, err)
	}
}

func TestClaimTransformDirectionAttribute(t *testing.T) {
	// The direction maps one-to-one onto the stored attribute. No TrustRole is
	// inferred, because that correspondence has not been qualified.
	egress, err := admodel.InternalClaimTransformDirectionAttribute(admodel.ClaimTransformEgress)
	if err != nil || egress != "msDS-EgressClaimsTransformationPolicy" {
		t.Fatalf("egress: %q %v", egress, err)
	}
	ingress, err := admodel.InternalClaimTransformDirectionAttribute(admodel.ClaimTransformIngress)
	if err != nil || ingress != "msDS-IngressClaimsTransformationPolicy" {
		t.Fatalf("ingress: %q %v", ingress, err)
	}
	if egress == ingress {
		t.Fatal("the two directions must not share an attribute")
	}
	for _, invalid := range []admodel.ClaimTransformDirection{0, 3, 255} {
		if _, err := admodel.InternalClaimTransformDirectionAttribute(
			invalid,
		); !errors.Is(
			err,
			admodel.ErrClaimTransformLink,
		) {
			t.Fatalf("direction %d must be rejected, got %v", invalid, err)
		}
	}
}

func TestClaimTransformLinkRequiresDirectionAndPolicy(t *testing.T) {
	client := &adengine.Client{}
	// An unset direction is refused before anything is resolved.
	if _, err := adservice_claims.New(client).
		SetClaimTransformLink(t.Context(), admodel.ClaimTransformLinkRequest{}); !errors.Is(
		err,
		admodel.ErrClaimTransformLink,
	) {
		t.Fatalf("missing direction must be rejected, got %v", err)
	}
	trust, err := admodel.IdentityByDN("CN=partner,CN=System,DC=example")
	if err != nil {
		t.Fatal(err)
	}
	// Setting a link with no policy identity cannot proceed; clearing can.
	_, err = adservice_claims.New(client).
		SetClaimTransformLink(t.Context(), admodel.ClaimTransformLinkRequest{Trust: trust, Direction: admodel.ClaimTransformEgress})
	if !errors.Is(err, admodel.ErrClaimTransformLink) ||
		!errors.Is(err, admodel.ErrInvalidIdentity) {
		t.Fatalf("a set without a policy must be rejected, got %v", err)
	}
}
