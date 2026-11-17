package acceptance

import (
	"errors"
	"slices"
	"strings"
	"testing"

	admodel "github.com/deploymenttheory/go-sdk-activedirectory/activedirectory/internal/model"
)

func InternalClaimChangeFor(
	changes []admodel.AttributeChange,
	attribute string,
) (admodel.AttributeChange, bool) {
	for _, change := range changes {
		if strings.EqualFold(change.Attribute, attribute) {
			return change, true
		}
	}
	return admodel.AttributeChange{}, false
}

func TestClaimRawChangesRejectManagedAttributes(t *testing.T) {
	// Every managed attribute is written from a typed field. A raw change
	// naming one would bypass source and value-type validation.
	for _, managed := range admodel.InternalClaimManagedAttributes {
		if err := admodel.InternalClaimRawChanges(
			[]admodel.AttributeChange{
				{Attribute: strings.ToUpper(managed), Kind: admodel.AttributeSet},
			},
		); !errors.Is(
			err,
			admodel.ErrClaimType,
		) {
			t.Fatalf("raw change to %q must be rejected, got %v", managed, err)
		}
		if err := admodel.InternalClaimRawAttributes(
			map[string][]admodel.RawValue{managed: nil},
		); !errors.Is(
			err,
			admodel.ErrClaimType,
		) {
			t.Fatalf("raw attribute %q must be rejected, got %v", managed, err)
		}
	}
	// Unmanaged attributes stay available for callers.
	if err := admodel.InternalClaimRawChanges(
		[]admodel.AttributeChange{{Attribute: "adminDescription", Kind: admodel.AttributeSet}},
	); err != nil {
		t.Fatalf("unmanaged change must be accepted: %v", err)
	}
	if err := admodel.InternalClaimRawAttributes(
		map[string][]admodel.RawValue{"adminDescription": nil},
	); err != nil {
		t.Fatalf("unmanaged attribute must be accepted: %v", err)
	}
}

func TestClaimManagedAttributesCoverSourceAndValueType(t *testing.T) {
	// A gap here would let a raw change rewrite a claim's source silently.
	for _, required := range []string{admodel.InternalClaimSourceAttribute, admodel.InternalClaimSourceOID, admodel.InternalClaimSourceKind, admodel.InternalClaimValueType, admodel.InternalClaimPossible, admodel.InternalClaimApplies, "name"} {
		if !slices.Contains(admodel.InternalClaimManagedAttributes, required) {
			t.Fatalf("%s must be a managed attribute", required)
		}
	}
}

func TestClaimUpdateChangesRejectContradictions(t *testing.T) {
	text := func(value string) *string { return &value }
	for name, request := range map[string]admodel.UpdateClaimTypeRequest{
		"description set and cleared":  {Description: text("x"), ClearDescription: true},
		"values set and cleared":       {SuggestedValues: []admodel.ClaimSuggestedValue{{Text: text("a")}}, ClearSuggestedValues: true},
		"classes set and cleared":      {AppliesToClasses: []admodel.SchemaReference{{LDAPDisplayName: "user"}}, ClearAppliesToClasses: true},
		"classes replaced and cleared": {ReplaceAppliesToClasses: true, ClearAppliesToClasses: true},
	} {
		if _, err := admodel.InternalClaimUpdateChanges(
			request,
		); !errors.Is(
			err,
			admodel.ErrClaimType,
		) {
			t.Fatalf("%s: expected ErrClaimType, got %v", name, err)
		}
	}
}

func TestClaimUpdateChangesRendersTypedFields(t *testing.T) {
	enabled, single, restrict := true, false, true
	display, description := "Department", "the department claim"
	changes, err := admodel.InternalClaimUpdateChanges(admodel.UpdateClaimTypeRequest{
		DisplayName:    &display,
		Description:    &description,
		Enabled:        &enabled,
		IsSingleValued: &single,
		RestrictValues: &restrict,
		Changes: []admodel.AttributeChange{
			{Attribute: "adminDescription", Kind: admodel.AttributeSet},
		},
	})
	if err != nil {
		t.Fatal(err)
	}
	for attribute, want := range map[string]string{
		"displayName": "Department",
		"description": "the department claim",
		"enabled":     "TRUE", admodel.InternalClaimSingle: "FALSE", admodel.InternalClaimRestricted: "TRUE",
	} {
		change, found := InternalClaimChangeFor(changes, attribute)
		if !found || change.Kind != admodel.AttributeSet || len(change.Values) != 1 {
			t.Fatalf("%s: missing or malformed change %+v", attribute, change)
		}
		if got := string(change.Values[0].Bytes()); got != want {
			t.Fatalf("%s: got %q want %q", attribute, got, want)
		}
	}
	// Caller-supplied raw changes are preserved alongside the typed ones.
	if _, found := InternalClaimChangeFor(changes, "adminDescription"); !found {
		t.Fatal("caller change was dropped")
	}
}

func TestClaimUpdateChangesRendersClears(t *testing.T) {
	changes, err := admodel.InternalClaimUpdateChanges(
		admodel.UpdateClaimTypeRequest{
			ClearDescription:      true,
			ClearSuggestedValues:  true,
			ClearAppliesToClasses: true,
		},
	)
	if err != nil {
		t.Fatal(err)
	}
	for _, attribute := range []string{"description", admodel.InternalClaimPossible, admodel.InternalClaimApplies} {
		change, found := InternalClaimChangeFor(changes, attribute)
		if !found || change.Kind != admodel.AttributeClear {
			t.Fatalf("%s: expected a clear, got %+v", attribute, change)
		}
	}
}

func TestClaimUpdateChangesRejectsInvalidText(t *testing.T) {
	empty := ""
	if _, err := admodel.InternalClaimUpdateChanges(
		admodel.UpdateClaimTypeRequest{DisplayName: &empty},
	); !errors.Is(
		err,
		admodel.ErrInvalidObjectMutation,
	) {
		t.Fatalf("an empty display name must be rejected, got %v", err)
	}
	control := "bad\x00name"
	if _, err := admodel.InternalClaimUpdateChanges(
		admodel.UpdateClaimTypeRequest{DisplayName: &control},
	); !errors.Is(
		err,
		admodel.ErrInvalidObjectMutation,
	) {
		t.Fatalf("a control character must be rejected, got %v", err)
	}
	if _, err := admodel.InternalClaimUpdateChanges(
		admodel.UpdateClaimTypeRequest{Description: &control},
	); !errors.Is(
		err,
		admodel.ErrInvalidObjectMutation,
	) {
		t.Fatalf("an invalid description must be rejected, got %v", err)
	}
}

func TestClaimUpdateChangesEmptyRequestChangesNothing(t *testing.T) {
	changes, err := admodel.InternalClaimUpdateChanges(admodel.UpdateClaimTypeRequest{})
	if err != nil || len(changes) != 0 {
		t.Fatalf("an empty request must render no changes: %+v err=%v", changes, err)
	}
}

func TestClaimStaleSourceAttributes(t *testing.T) {
	// Re-pointing a source must retire the attributes the other forms own so
	// a stale DN or OID never outlives the change.
	if got := admodel.InternalClaimStaleSourceAttributes(
		admodel.ClaimSourceAttribute,
	); !slices.Equal(
		got,
		[]string{admodel.InternalClaimSourceOID},
	) {
		t.Fatalf("attribute source: %v", got)
	}
	if got := admodel.InternalClaimStaleSourceAttributes(
		admodel.ClaimSourceCertificate,
	); !slices.Equal(
		got,
		[]string{admodel.InternalClaimSourceAttribute},
	) {
		t.Fatalf("certificate source: %v", got)
	}
	got := admodel.InternalClaimStaleSourceAttributes(admodel.ClaimSourceTransform)
	if !slices.Contains(got, admodel.InternalClaimSourceAttribute) ||
		!slices.Contains(got, admodel.InternalClaimSourceOID) {
		t.Fatalf("transform source must retire both: %v", got)
	}
	// The retired set must never include the attribute the new form writes.
	for kind, written := range map[admodel.ClaimSourceType]string{admodel.ClaimSourceAttribute: admodel.InternalClaimSourceAttribute, admodel.ClaimSourceCertificate: admodel.InternalClaimSourceOID} {
		if slices.Contains(admodel.InternalClaimStaleSourceAttributes(kind), written) {
			t.Fatalf("%s retires the attribute it writes", kind)
		}
	}
}

func TestClaimSourceAttributesRenderStoredForm(t *testing.T) {
	resolution := admodel.InternalClaimSchemaResolution{
		SourceAttributeDN: "CN=department,CN=Schema,DC=example",
		ValueType:         admodel.ClaimString,
	}
	attributes := admodel.InternalClaimSourceAttributes(
		admodel.ClaimTypeSource{Type: admodel.ClaimSourceAttribute},
		resolution,
	)
	if got := string(
		attributes[admodel.InternalClaimSourceAttribute][0].Bytes(),
	); got != resolution.SourceAttributeDN {
		t.Fatalf("attribute DN: %q", got)
	}
	if got := string(attributes[admodel.InternalClaimValueType][0].Bytes()); got != "3" {
		t.Fatalf("value type: %q", got)
	}
	if got := string(
		attributes[admodel.InternalClaimSourceKind][0].Bytes(),
	); got != string(
		admodel.ClaimSourceAttribute,
	) {
		t.Fatalf("source kind: %q", got)
	}
	if _, present := attributes[admodel.InternalClaimSourceOID]; present {
		t.Fatal("an attribute source must not write a source OID")
	}

	oid := admodel.InternalClaimSourceAttributes(
		admodel.ClaimTypeSource{Type: admodel.ClaimSourceCertificate, OID: "1.2.3"},
		admodel.InternalClaimSchemaResolution{ValueType: admodel.ClaimString},
	)
	if got := string(oid[admodel.InternalClaimSourceOID][0].Bytes()); got != "1.2.3" {
		t.Fatalf("source OID: %q", got)
	}
	if _, present := oid[admodel.InternalClaimSourceAttribute]; present {
		t.Fatal("a certificate source must not write an attribute DN")
	}

	transform := admodel.InternalClaimSourceAttributes(
		admodel.ClaimTypeSource{Type: admodel.ClaimSourceTransform},
		admodel.InternalClaimSchemaResolution{ValueType: admodel.ClaimBoolean},
	)
	for _, absent := range []string{admodel.InternalClaimSourceAttribute, admodel.InternalClaimSourceOID} {
		if _, present := transform[absent]; present {
			t.Fatalf("a transform source must not write %s", absent)
		}
	}
}

func TestClaimSuggestedValueAttributeOmitsEmpty(t *testing.T) {
	values, err := admodel.InternalClaimSuggestedValueAttribute(nil, admodel.ClaimString)
	if err != nil || values != nil {
		t.Fatalf("no suggested values must write no attribute: %+v err=%v", values, err)
	}
	text := "engineering"
	encoded, err := admodel.InternalClaimSuggestedValueAttribute(
		[]admodel.ClaimSuggestedValue{{Text: &text}},
		admodel.ClaimString,
	)
	if err != nil || len(encoded) != 1 {
		t.Fatalf("suggested values: %+v err=%v", encoded, err)
	}
	if !strings.Contains(string(encoded[0].Bytes()), "engineering") {
		t.Fatalf("encoded values lost the suggestion: %q", encoded[0].Bytes())
	}
	// A suggestion that does not match the settled value type is an error,
	// not a silently coerced value.
	if _, err := admodel.InternalClaimSuggestedValueAttribute(
		[]admodel.ClaimSuggestedValue{{Text: &text}},
		admodel.ClaimInt64,
	); err == nil {
		t.Fatal("a mistyped suggestion must be rejected")
	}
}

func TestClaimBoolValue(t *testing.T) {
	if got := string(admodel.InternalClaimBoolValue(true).Bytes()); got != "TRUE" {
		t.Fatalf("true rendered as %q", got)
	}
	if got := string(admodel.InternalClaimBoolValue(false).Bytes()); got != "FALSE" {
		t.Fatalf("false rendered as %q", got)
	}
}

func TestClaimClassValues(t *testing.T) {
	dns := []string{"CN=user,CN=Schema,DC=example", "CN=computer,CN=Schema,DC=example"}
	values := admodel.InternalClaimClassValues(dns)
	if len(values) != len(dns) {
		t.Fatalf("expected %d values, got %d", len(dns), len(values))
	}
	for i, dn := range dns {
		if got := string(values[i].Bytes()); got != dn {
			t.Fatalf("value %d: got %q want %q", i, got, dn)
		}
	}
	if values := admodel.InternalClaimClassValues(nil); len(values) != 0 {
		t.Fatalf("no classes must render no values: %+v", values)
	}
}
