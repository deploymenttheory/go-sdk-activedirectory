package activedirectory

import (
	"errors"
	"slices"
	"strings"
	"testing"
)

func claimChangeFor(changes []AttributeChange, attribute string) (AttributeChange, bool) {
	for _, change := range changes {
		if strings.EqualFold(change.Attribute, attribute) {
			return change, true
		}
	}
	return AttributeChange{}, false
}

func TestClaimRawChangesRejectManagedAttributes(t *testing.T) {
	// Every managed attribute is written from a typed field. A raw change
	// naming one would bypass source and value-type validation.
	for _, managed := range claimManagedAttributes {
		if err := claimRawChanges([]AttributeChange{{Attribute: strings.ToUpper(managed), Kind: AttributeSet}}); !errors.Is(err, ErrClaimType) {
			t.Fatalf("raw change to %q must be rejected, got %v", managed, err)
		}
		if err := claimRawAttributes(map[string][]RawValue{managed: nil}); !errors.Is(err, ErrClaimType) {
			t.Fatalf("raw attribute %q must be rejected, got %v", managed, err)
		}
	}
	// Unmanaged attributes stay available for callers.
	if err := claimRawChanges([]AttributeChange{{Attribute: "adminDescription", Kind: AttributeSet}}); err != nil {
		t.Fatalf("unmanaged change must be accepted: %v", err)
	}
	if err := claimRawAttributes(map[string][]RawValue{"adminDescription": nil}); err != nil {
		t.Fatalf("unmanaged attribute must be accepted: %v", err)
	}
}

func TestClaimManagedAttributesCoverSourceAndValueType(t *testing.T) {
	// A gap here would let a raw change rewrite a claim's source silently.
	for _, required := range []string{claimSourceAttribute, claimSourceOID, claimSourceKind, claimValueType, claimPossible, claimApplies, "name"} {
		if !slices.Contains(claimManagedAttributes, required) {
			t.Fatalf("%s must be a managed attribute", required)
		}
	}
}

func TestClaimUpdateChangesRejectContradictions(t *testing.T) {
	text := func(value string) *string { return &value }
	for name, request := range map[string]UpdateClaimTypeRequest{
		"description set and cleared":  {Description: text("x"), ClearDescription: true},
		"values set and cleared":       {SuggestedValues: []ClaimSuggestedValue{{Text: text("a")}}, ClearSuggestedValues: true},
		"classes set and cleared":      {AppliesToClasses: []SchemaReference{{LDAPDisplayName: "user"}}, ClearAppliesToClasses: true},
		"classes replaced and cleared": {ReplaceAppliesToClasses: true, ClearAppliesToClasses: true},
	} {
		if _, err := claimUpdateChanges(request); !errors.Is(err, ErrClaimType) {
			t.Fatalf("%s: expected ErrClaimType, got %v", name, err)
		}
	}
}

func TestClaimUpdateChangesRendersTypedFields(t *testing.T) {
	enabled, single, restrict := true, false, true
	display, description := "Department", "the department claim"
	changes, err := claimUpdateChanges(UpdateClaimTypeRequest{
		DisplayName:    &display,
		Description:    &description,
		Enabled:        &enabled,
		IsSingleValued: &single,
		RestrictValues: &restrict,
		Changes:        []AttributeChange{{Attribute: "adminDescription", Kind: AttributeSet}},
	})
	if err != nil {
		t.Fatal(err)
	}
	for attribute, want := range map[string]string{
		"displayName":   "Department",
		"description":   "the department claim",
		"enabled":       "TRUE",
		claimSingle:     "FALSE",
		claimRestricted: "TRUE",
	} {
		change, found := claimChangeFor(changes, attribute)
		if !found || change.Kind != AttributeSet || len(change.Values) != 1 {
			t.Fatalf("%s: missing or malformed change %+v", attribute, change)
		}
		if got := string(change.Values[0].Bytes()); got != want {
			t.Fatalf("%s: got %q want %q", attribute, got, want)
		}
	}
	// Caller-supplied raw changes are preserved alongside the typed ones.
	if _, found := claimChangeFor(changes, "adminDescription"); !found {
		t.Fatal("caller change was dropped")
	}
}

func TestClaimUpdateChangesRendersClears(t *testing.T) {
	changes, err := claimUpdateChanges(UpdateClaimTypeRequest{ClearDescription: true, ClearSuggestedValues: true, ClearAppliesToClasses: true})
	if err != nil {
		t.Fatal(err)
	}
	for _, attribute := range []string{"description", claimPossible, claimApplies} {
		change, found := claimChangeFor(changes, attribute)
		if !found || change.Kind != AttributeClear {
			t.Fatalf("%s: expected a clear, got %+v", attribute, change)
		}
	}
}

func TestClaimUpdateChangesRejectsInvalidText(t *testing.T) {
	empty := ""
	if _, err := claimUpdateChanges(UpdateClaimTypeRequest{DisplayName: &empty}); !errors.Is(err, ErrInvalidObjectMutation) {
		t.Fatalf("an empty display name must be rejected, got %v", err)
	}
	control := "bad\x00name"
	if _, err := claimUpdateChanges(UpdateClaimTypeRequest{DisplayName: &control}); !errors.Is(err, ErrInvalidObjectMutation) {
		t.Fatalf("a control character must be rejected, got %v", err)
	}
	if _, err := claimUpdateChanges(UpdateClaimTypeRequest{Description: &control}); !errors.Is(err, ErrInvalidObjectMutation) {
		t.Fatalf("an invalid description must be rejected, got %v", err)
	}
}

func TestClaimUpdateChangesEmptyRequestChangesNothing(t *testing.T) {
	changes, err := claimUpdateChanges(UpdateClaimTypeRequest{})
	if err != nil || len(changes) != 0 {
		t.Fatalf("an empty request must render no changes: %+v err=%v", changes, err)
	}
}

func TestClaimStaleSourceAttributes(t *testing.T) {
	// Re-pointing a source must retire the attributes the other forms own so
	// a stale DN or OID never outlives the change.
	if got := claimStaleSourceAttributes(ClaimSourceAttribute); !slices.Equal(got, []string{claimSourceOID}) {
		t.Fatalf("attribute source: %v", got)
	}
	if got := claimStaleSourceAttributes(ClaimSourceCertificate); !slices.Equal(got, []string{claimSourceAttribute}) {
		t.Fatalf("certificate source: %v", got)
	}
	got := claimStaleSourceAttributes(ClaimSourceTransform)
	if !slices.Contains(got, claimSourceAttribute) || !slices.Contains(got, claimSourceOID) {
		t.Fatalf("transform source must retire both: %v", got)
	}
	// The retired set must never include the attribute the new form writes.
	for kind, written := range map[ClaimSourceType]string{
		ClaimSourceAttribute:   claimSourceAttribute,
		ClaimSourceCertificate: claimSourceOID,
	} {
		if slices.Contains(claimStaleSourceAttributes(kind), written) {
			t.Fatalf("%s retires the attribute it writes", kind)
		}
	}
}

func TestClaimSourceAttributesRenderStoredForm(t *testing.T) {
	resolution := claimSchemaResolution{SourceAttributeDN: "CN=department,CN=Schema,DC=example", ValueType: ClaimString}
	attributes := claimSourceAttributes(ClaimTypeSource{Type: ClaimSourceAttribute}, resolution)
	if got := string(attributes[claimSourceAttribute][0].Bytes()); got != resolution.SourceAttributeDN {
		t.Fatalf("attribute DN: %q", got)
	}
	if got := string(attributes[claimValueType][0].Bytes()); got != "3" {
		t.Fatalf("value type: %q", got)
	}
	if got := string(attributes[claimSourceKind][0].Bytes()); got != string(ClaimSourceAttribute) {
		t.Fatalf("source kind: %q", got)
	}
	if _, present := attributes[claimSourceOID]; present {
		t.Fatal("an attribute source must not write a source OID")
	}

	oid := claimSourceAttributes(ClaimTypeSource{Type: ClaimSourceCertificate, OID: "1.2.3"}, claimSchemaResolution{ValueType: ClaimString})
	if got := string(oid[claimSourceOID][0].Bytes()); got != "1.2.3" {
		t.Fatalf("source OID: %q", got)
	}
	if _, present := oid[claimSourceAttribute]; present {
		t.Fatal("a certificate source must not write an attribute DN")
	}

	transform := claimSourceAttributes(ClaimTypeSource{Type: ClaimSourceTransform}, claimSchemaResolution{ValueType: ClaimBoolean})
	for _, absent := range []string{claimSourceAttribute, claimSourceOID} {
		if _, present := transform[absent]; present {
			t.Fatalf("a transform source must not write %s", absent)
		}
	}
}

func TestClaimSuggestedValueAttributeOmitsEmpty(t *testing.T) {
	values, err := claimSuggestedValueAttribute(nil, ClaimString)
	if err != nil || values != nil {
		t.Fatalf("no suggested values must write no attribute: %+v err=%v", values, err)
	}
	text := "engineering"
	encoded, err := claimSuggestedValueAttribute([]ClaimSuggestedValue{{Text: &text}}, ClaimString)
	if err != nil || len(encoded) != 1 {
		t.Fatalf("suggested values: %+v err=%v", encoded, err)
	}
	if !strings.Contains(string(encoded[0].Bytes()), "engineering") {
		t.Fatalf("encoded values lost the suggestion: %q", encoded[0].Bytes())
	}
	// A suggestion that does not match the settled value type is an error,
	// not a silently coerced value.
	if _, err := claimSuggestedValueAttribute([]ClaimSuggestedValue{{Text: &text}}, ClaimInt64); err == nil {
		t.Fatal("a mistyped suggestion must be rejected")
	}
}

func TestClaimBoolValue(t *testing.T) {
	if got := string(claimBoolValue(true).Bytes()); got != "TRUE" {
		t.Fatalf("true rendered as %q", got)
	}
	if got := string(claimBoolValue(false).Bytes()); got != "FALSE" {
		t.Fatalf("false rendered as %q", got)
	}
}

func TestClaimClassValues(t *testing.T) {
	dns := []string{"CN=user,CN=Schema,DC=example", "CN=computer,CN=Schema,DC=example"}
	values := claimClassValues(dns)
	if len(values) != len(dns) {
		t.Fatalf("expected %d values, got %d", len(dns), len(values))
	}
	for i, dn := range dns {
		if got := string(values[i].Bytes()); got != dn {
			t.Fatalf("value %d: got %q want %q", i, got, dn)
		}
	}
	if values := claimClassValues(nil); len(values) != 0 {
		t.Fatalf("no classes must render no values: %+v", values)
	}
}
