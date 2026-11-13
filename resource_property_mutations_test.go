package activedirectory

import (
	"errors"
	"slices"
	"strings"
	"testing"
)

func resourceText(value string) *string { return &value }

func TestResourceManagedAttributesRejected(t *testing.T) {
	// The value-type reference, shared-values link, possible values and member
	// list are written only from typed fields. A raw change naming one would
	// bypass value-type settlement and container verification.
	for _, required := range []string{resourceValueTypeReference, resourceSharesValuesWith, resourceListMembers, claimPossible, claimValueType, "name"} {
		if !slices.Contains(resourceManaged, required) {
			t.Fatalf("%s must be managed", required)
		}
	}
	for _, managed := range resourceManaged {
		if err := resourceRawChanges([]AttributeChange{{Attribute: strings.ToUpper(managed), Kind: AttributeSet}}); !errors.Is(err, ErrResourceProperty) {
			t.Fatalf("raw change to %q must be rejected, got %v", managed, err)
		}
		if err := resourceRawAttributes(map[string][]RawValue{managed: nil}); !errors.Is(err, ErrResourceProperty) {
			t.Fatalf("raw attribute %q must be rejected, got %v", managed, err)
		}
	}
	if err := resourceRawChanges([]AttributeChange{{Attribute: "adminDescription", Kind: AttributeSet}}); err != nil {
		t.Fatalf("an unmanaged change must be accepted: %v", err)
	}
}

func TestResourceAppliesToValid(t *testing.T) {
	if err := resourceAppliesToValid([]string{"File", "Folder"}); err != nil {
		t.Fatalf("distinct types must be accepted: %v", err)
	}
	if err := resourceAppliesToValid(nil); err != nil {
		t.Fatalf("an empty list must be accepted: %v", err)
	}
	// Duplicates differing only by case would write the same value twice.
	for name, types := range map[string][]string{
		"empty entry":    {""},
		"control char":   {"File\x00"},
		"duplicate":      {"File", "File"},
		"case duplicate": {"File", "file"},
	} {
		if err := resourceAppliesToValid(types); !errors.Is(err, ErrResourceProperty) {
			t.Fatalf("%s: expected ErrResourceProperty, got %v", name, err)
		}
	}
}

func TestResourcePropertyUpdateChangesRejectContradictions(t *testing.T) {
	identity, err := IdentityByDN("CN=c,CN=Claim Types,CN=Claims Configuration,CN=Services,CN=Configuration,DC=example")
	if err != nil {
		t.Fatal(err)
	}
	for name, request := range map[string]UpdateResourcePropertyRequest{
		"description set and cleared": {Description: resourceText("x"), ClearDescription: true},
		"shares set and cleared":      {SharesValuesWith: &identity, ClearSharesValuesWith: true},
		"values set and cleared":      {SuggestedValues: []ClaimSuggestedValue{{Text: resourceText("a")}}, ClearSuggestedValues: true},
		"applies set and cleared":     {AppliesToResourceTypes: []string{"File"}, ClearAppliesToResourceTypes: true},
		"applies replace and cleared": {ReplaceAppliesToResourceTypes: true, ClearAppliesToResourceTypes: true},
	} {
		if _, err := resourcePropertyUpdateChanges(request); !errors.Is(err, ErrResourceProperty) {
			t.Fatalf("%s: expected ErrResourceProperty, got %v", name, err)
		}
	}
}

func TestResourcePropertyUpdateChangesRendersTypedFields(t *testing.T) {
	enabled, secured, restrict := true, false, true
	display := "Department"
	changes, err := resourcePropertyUpdateChanges(UpdateResourcePropertyRequest{
		DisplayName:    &display,
		Enabled:        &enabled,
		IsSecured:      &secured,
		RestrictValues: &restrict,
		Changes:        []AttributeChange{{Attribute: "adminDescription", Kind: AttributeSet}},
	})
	if err != nil {
		t.Fatal(err)
	}
	for attribute, want := range map[string]string{
		"displayName":     "Department",
		"enabled":         "TRUE",
		resourceIsSecured: "FALSE",
		claimRestricted:   "TRUE",
	} {
		change, found := claimChangeFor(changes, attribute)
		if !found || change.Kind != AttributeSet || len(change.Values) != 1 {
			t.Fatalf("%s: missing or malformed %+v", attribute, change)
		}
		if got := string(change.Values[0].Bytes()); got != want {
			t.Fatalf("%s: got %q want %q", attribute, got, want)
		}
	}
	if _, found := claimChangeFor(changes, "adminDescription"); !found {
		t.Fatal("caller change was dropped")
	}
}

func TestResourcePropertyUpdateAppliesToAddsByDefault(t *testing.T) {
	// Adding is the default so a caller must opt in to rewriting the list.
	changes, err := resourcePropertyUpdateChanges(UpdateResourcePropertyRequest{AppliesToResourceTypes: []string{"File"}})
	if err != nil {
		t.Fatal(err)
	}
	change, found := claimChangeFor(changes, resourceAppliesTo)
	if !found || change.Kind != AttributeAddValues {
		t.Fatalf("expected an add, got %+v", change)
	}
	changes, err = resourcePropertyUpdateChanges(UpdateResourcePropertyRequest{AppliesToResourceTypes: []string{"File"}, ReplaceAppliesToResourceTypes: true})
	if err != nil {
		t.Fatal(err)
	}
	change, found = claimChangeFor(changes, resourceAppliesTo)
	if !found || change.Kind != AttributeSet {
		t.Fatalf("expected a replace, got %+v", change)
	}
}

func TestResourcePropertyUpdateChangesClears(t *testing.T) {
	changes, err := resourcePropertyUpdateChanges(UpdateResourcePropertyRequest{
		ClearDescription:            true,
		ClearSharesValuesWith:       true,
		ClearSuggestedValues:        true,
		ClearAppliesToResourceTypes: true,
	})
	if err != nil {
		t.Fatal(err)
	}
	for _, attribute := range []string{"description", resourceSharesValuesWith, claimPossible, resourceAppliesTo} {
		change, found := claimChangeFor(changes, attribute)
		if !found || change.Kind != AttributeClear {
			t.Fatalf("%s: expected a clear, got %+v", attribute, change)
		}
	}
}

func TestResourcePropertyUpdateEmptyRequestChangesNothing(t *testing.T) {
	changes, err := resourcePropertyUpdateChanges(UpdateResourcePropertyRequest{})
	if err != nil || len(changes) != 0 {
		t.Fatalf("an empty request must render no changes: %+v err=%v", changes, err)
	}
}

func TestResourceLocationRequiresOwnContainer(t *testing.T) {
	const configuration = "CN=Configuration,DC=example"
	object := func(dn, class string) Object {
		return Object{DistinguishedName: dn, Attributes: map[string][][]byte{
			"objectclass": {[]byte("top"), []byte(class)},
		}}
	}
	// Each class is only in scope inside its own container.
	for class, container := range map[string]string{
		resourcePropertyClass:     resourcePropertyParent(configuration),
		resourcePropertyListClass: resourcePropertyListParent(configuration),
		resourceValueTypeClass:    resourceValueTypeParent(configuration),
	} {
		if err := resourceLocation(object("CN=x,"+container, class), configuration, class); err != nil {
			t.Fatalf("%s in its own container must be accepted: %v", class, err)
		}
		// The right class in the wrong container is out of scope.
		if err := resourceLocation(object("CN=x,CN=Users,DC=example", class), configuration, class); !errors.Is(err, ErrIdentityScope) {
			t.Fatalf("%s elsewhere must be out of scope, got %v", class, err)
		}
		// A different class in the right container is still wrong.
		if err := resourceLocation(object("CN=x,"+container, "user"), configuration, class); !errors.Is(err, ErrResourceProperty) {
			t.Fatalf("%s container with a user object must be rejected", class)
		}
	}
}

func TestResourceContainerForIsDistinctPerClass(t *testing.T) {
	const configuration = "CN=Configuration,DC=example"
	seen := map[string]string{}
	for _, class := range []string{resourcePropertyClass, resourcePropertyListClass, resourceValueTypeClass} {
		container := resourceContainerFor(class, configuration)
		if !strings.HasSuffix(container, configuration) {
			t.Fatalf("%s container is outside the configuration partition: %s", class, container)
		}
		if other, clash := seen[container]; clash {
			t.Fatalf("%s and %s share a container: %s", class, other, container)
		}
		seen[container] = class
	}
}

func TestResourcePropertyListMembersRequireBoundedInput(t *testing.T) {
	client := &Client{}
	// No members is not a silent no-op, and an unbounded list is refused
	// before anything is resolved.
	if _, err := client.AddResourcePropertyListMembers(t.Context(), ResourcePropertyListMembersRequest{}); err == nil {
		t.Fatal("an empty member list must be rejected")
	}
	identity, err := IdentityByDN("CN=l,CN=Resource Property Lists,CN=Claims Configuration,CN=Services,CN=Configuration,DC=example")
	if err != nil {
		t.Fatal(err)
	}
	many := make([]Identity, ResourcePropertyListMemberLimit+1)
	for i := range many {
		many[i] = identity
	}
	if _, err := client.AddResourcePropertyListMembers(t.Context(), ResourcePropertyListMembersRequest{Identity: identity, Members: many}); !errors.Is(err, ErrResourcePropertyMember) {
		t.Fatalf("an over-limit member list must be rejected, got %v", err)
	}
}

func TestDecodeResourcePropertyRejectsWrongClass(t *testing.T) {
	object := Object{DistinguishedName: "CN=p,CN=Resource Properties,CN=Claims Configuration,CN=Services,CN=Configuration,DC=example", Attributes: map[string][][]byte{
		"objectclass": {[]byte("top"), []byte("user")},
		"objectguid":  {make([]byte, 16)},
		"name":        {[]byte("p")},
		"usnchanged":  {[]byte("7")},
	}}
	if _, err := decodeResourceProperty(object); err == nil {
		t.Fatal("a user object must not decode as a resource property")
	}
	if _, err := decodeResourcePropertyList(object); err == nil {
		t.Fatal("a user object must not decode as a property list")
	}
	if _, err := decodeResourceValueType(object); err == nil {
		t.Fatal("a user object must not decode as a value type")
	}
}

func TestDecodeResourcePropertyReadsTypedFields(t *testing.T) {
	object := Object{DistinguishedName: "CN=p,CN=Resource Properties,CN=Claims Configuration,CN=Services,CN=Configuration,DC=example", Attributes: map[string][][]byte{
		"objectclass":                      {[]byte("top"), []byte(resourcePropertyClass)},
		"objectguid":                       {make([]byte, 16)},
		"name":                             {[]byte("Department_MS")},
		"usnchanged":                       {[]byte("7")},
		"displayname":                      {[]byte("Department")},
		"enabled":                          {[]byte("TRUE")},
		strings.ToLower(resourceIsSecured): {[]byte("FALSE")},
		strings.ToLower(claimValueType):    {[]byte("3")},
		strings.ToLower(resourceValueTypeReference): {[]byte("CN=MS-DS-Text,CN=Value Types,CN=Claims Configuration,CN=Services,CN=Configuration,DC=example")},
		strings.ToLower(resourceAppliesTo):          {[]byte("File"), []byte("Folder")},
	}}
	value, err := decodeResourceProperty(object)
	if err != nil {
		t.Fatal(err)
	}
	if value.ID == nil || *value.ID != "Department_MS" {
		t.Fatalf("id: %+v", value.ID)
	}
	if value.ValueType == nil || *value.ValueType != ClaimString {
		t.Fatalf("value type: %+v", value.ValueType)
	}
	if value.Enabled == nil || !*value.Enabled || value.IsSecured == nil || *value.IsSecured {
		t.Fatalf("flags: enabled=%+v secured=%+v", value.Enabled, value.IsSecured)
	}
	if len(value.AppliesToResourceTypes) != 2 {
		t.Fatalf("applies-to: %+v", value.AppliesToResourceTypes)
	}
	if value.ValueTypeDN == nil || !strings.Contains(*value.ValueTypeDN, "CN=Value Types") {
		t.Fatalf("value type DN: %+v", value.ValueTypeDN)
	}
}
