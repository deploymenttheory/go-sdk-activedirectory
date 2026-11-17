package acceptance

import (
	"errors"
	"slices"
	"strings"
	"testing"

	adengine "github.com/deploymenttheory/go-sdk-activedirectory/activedirectory/internal/engine"
	admodel "github.com/deploymenttheory/go-sdk-activedirectory/activedirectory/internal/model"
	adservice_resource_properties "github.com/deploymenttheory/go-sdk-activedirectory/activedirectory/services/resource_properties"
)

func InternalResourceText(value string) *string { return &value }

func TestResourceManagedAttributesRejected(t *testing.T) {
	// The value-type reference, shared-values link, possible values and member
	// list are written only from typed fields. A raw change naming one would
	// bypass value-type settlement and container verification.
	for _, required := range []string{admodel.InternalResourceValueTypeReference, admodel.InternalResourceSharesValuesWith, admodel.InternalResourceListMembers, admodel.InternalClaimPossible, admodel.InternalClaimValueType, "name"} {
		if !slices.Contains(admodel.InternalResourceManaged, required) {
			t.Fatalf("%s must be managed", required)
		}
	}
	for _, managed := range admodel.InternalResourceManaged {
		if err := admodel.InternalResourceRawChanges(
			[]admodel.AttributeChange{
				{Attribute: strings.ToUpper(managed), Kind: admodel.AttributeSet},
			},
		); !errors.Is(
			err,
			admodel.ErrResourceProperty,
		) {
			t.Fatalf("raw change to %q must be rejected, got %v", managed, err)
		}
		if err := admodel.InternalResourceRawAttributes(
			map[string][]admodel.RawValue{managed: nil},
		); !errors.Is(
			err,
			admodel.ErrResourceProperty,
		) {
			t.Fatalf("raw attribute %q must be rejected, got %v", managed, err)
		}
	}
	if err := admodel.InternalResourceRawChanges(
		[]admodel.AttributeChange{{Attribute: "adminDescription", Kind: admodel.AttributeSet}},
	); err != nil {
		t.Fatalf("an unmanaged change must be accepted: %v", err)
	}
}

func TestResourceAppliesToValid(t *testing.T) {
	if err := admodel.InternalResourceAppliesToValid([]string{"File", "Folder"}); err != nil {
		t.Fatalf("distinct types must be accepted: %v", err)
	}
	if err := admodel.InternalResourceAppliesToValid(nil); err != nil {
		t.Fatalf("an empty list must be accepted: %v", err)
	}
	// Duplicates differing only by case would write the same value twice.
	for name, types := range map[string][]string{
		"empty entry":    {""},
		"control char":   {"File\x00"},
		"duplicate":      {"File", "File"},
		"case duplicate": {"File", "file"},
	} {
		if err := admodel.InternalResourceAppliesToValid(
			types,
		); !errors.Is(
			err,
			admodel.ErrResourceProperty,
		) {
			t.Fatalf("%s: expected ErrResourceProperty, got %v", name, err)
		}
	}
}

func TestResourcePropertyUpdateChangesRejectContradictions(t *testing.T) {
	identity, err := admodel.IdentityByDN(
		"CN=c,CN=Claim Types,CN=Claims Configuration,CN=Services,CN=Configuration,DC=example",
	)
	if err != nil {
		t.Fatal(err)
	}
	for name, request := range map[string]admodel.UpdateResourcePropertyRequest{
		"description set and cleared": {Description: InternalResourceText("x"), ClearDescription: true},
		"shares set and cleared":      {SharesValuesWith: &identity, ClearSharesValuesWith: true},
		"values set and cleared":      {SuggestedValues: []admodel.ClaimSuggestedValue{{Text: InternalResourceText("a")}}, ClearSuggestedValues: true},
		"applies set and cleared":     {AppliesToResourceTypes: []string{"File"}, ClearAppliesToResourceTypes: true},
		"applies replace and cleared": {ReplaceAppliesToResourceTypes: true, ClearAppliesToResourceTypes: true},
	} {
		if _, err := admodel.InternalResourcePropertyUpdateChanges(
			request,
		); !errors.Is(
			err,
			admodel.ErrResourceProperty,
		) {
			t.Fatalf("%s: expected ErrResourceProperty, got %v", name, err)
		}
	}
}

func TestResourcePropertyUpdateChangesRendersTypedFields(t *testing.T) {
	enabled, secured, restrict := true, false, true
	display := "Department"
	changes, err := admodel.InternalResourcePropertyUpdateChanges(
		admodel.UpdateResourcePropertyRequest{
			DisplayName:    &display,
			Enabled:        &enabled,
			IsSecured:      &secured,
			RestrictValues: &restrict,
			Changes: []admodel.AttributeChange{
				{Attribute: "adminDescription", Kind: admodel.AttributeSet},
			},
		},
	)
	if err != nil {
		t.Fatal(err)
	}
	for attribute, want := range map[string]string{
		"displayName": "Department",
		"enabled":     "TRUE", admodel.InternalResourceIsSecured: "FALSE", admodel.InternalClaimRestricted: "TRUE",
	} {
		change, found := InternalClaimChangeFor(changes, attribute)
		if !found || change.Kind != admodel.AttributeSet || len(change.Values) != 1 {
			t.Fatalf("%s: missing or malformed %+v", attribute, change)
		}
		if got := string(change.Values[0].Bytes()); got != want {
			t.Fatalf("%s: got %q want %q", attribute, got, want)
		}
	}
	if _, found := InternalClaimChangeFor(changes, "adminDescription"); !found {
		t.Fatal("caller change was dropped")
	}
}

func TestResourcePropertyUpdateAppliesToAddsByDefault(t *testing.T) {
	// Adding is the default so a caller must opt in to rewriting the list.
	changes, err := admodel.InternalResourcePropertyUpdateChanges(
		admodel.UpdateResourcePropertyRequest{AppliesToResourceTypes: []string{"File"}},
	)
	if err != nil {
		t.Fatal(err)
	}
	change, found := InternalClaimChangeFor(changes, admodel.InternalResourceAppliesTo)
	if !found || change.Kind != admodel.AttributeAddValues {
		t.Fatalf("expected an add, got %+v", change)
	}
	changes, err = admodel.InternalResourcePropertyUpdateChanges(
		admodel.UpdateResourcePropertyRequest{
			AppliesToResourceTypes:        []string{"File"},
			ReplaceAppliesToResourceTypes: true,
		},
	)
	if err != nil {
		t.Fatal(err)
	}
	change, found = InternalClaimChangeFor(changes, admodel.InternalResourceAppliesTo)
	if !found || change.Kind != admodel.AttributeSet {
		t.Fatalf("expected a replace, got %+v", change)
	}
}

func TestResourcePropertyUpdateChangesClears(t *testing.T) {
	changes, err := admodel.InternalResourcePropertyUpdateChanges(
		admodel.UpdateResourcePropertyRequest{
			ClearDescription:            true,
			ClearSharesValuesWith:       true,
			ClearSuggestedValues:        true,
			ClearAppliesToResourceTypes: true,
		},
	)
	if err != nil {
		t.Fatal(err)
	}
	for _, attribute := range []string{"description", admodel.InternalResourceSharesValuesWith, admodel.InternalClaimPossible, admodel.InternalResourceAppliesTo} {
		change, found := InternalClaimChangeFor(changes, attribute)
		if !found || change.Kind != admodel.AttributeClear {
			t.Fatalf("%s: expected a clear, got %+v", attribute, change)
		}
	}
}

func TestResourcePropertyUpdateEmptyRequestChangesNothing(t *testing.T) {
	changes, err := admodel.InternalResourcePropertyUpdateChanges(
		admodel.UpdateResourcePropertyRequest{},
	)
	if err != nil || len(changes) != 0 {
		t.Fatalf("an empty request must render no changes: %+v err=%v", changes, err)
	}
}

func TestResourceLocationRequiresOwnContainer(t *testing.T) {
	const configuration = "CN=Configuration,DC=example"
	object := func(dn, class string) admodel.Object {
		return admodel.Object{DistinguishedName: dn, Attributes: map[string][][]byte{
			"objectclass": {[]byte("top"), []byte(class)},
		}}
	}
	// Each class is only in scope inside its own container.
	for class, container := range map[string]string{admodel.InternalResourcePropertyClass: admodel.InternalResourcePropertyParent(configuration), admodel.InternalResourcePropertyListClass: admodel.InternalResourcePropertyListParent(configuration), admodel.InternalResourceValueTypeClass: admodel.InternalResourceValueTypeParent(configuration)} {
		if err := admodel.InternalResourceLocation(
			object("CN=x,"+container, class),
			configuration,
			class,
		); err != nil {
			t.Fatalf("%s in its own container must be accepted: %v", class, err)
		}
		// The right class in the wrong container is out of scope.
		if err := admodel.InternalResourceLocation(
			object("CN=x,CN=Users,DC=example", class),
			configuration,
			class,
		); !errors.Is(
			err,
			admodel.ErrIdentityScope,
		) {
			t.Fatalf("%s elsewhere must be out of scope, got %v", class, err)
		}
		// A different class in the right container is still wrong.
		if err := admodel.InternalResourceLocation(
			object("CN=x,"+container, "user"),
			configuration,
			class,
		); !errors.Is(
			err,
			admodel.ErrResourceProperty,
		) {
			t.Fatalf("%s container with a user object must be rejected", class)
		}
	}
}

func TestResourceContainerForIsDistinctPerClass(t *testing.T) {
	const configuration = "CN=Configuration,DC=example"
	seen := map[string]string{}
	for _, class := range []string{admodel.InternalResourcePropertyClass, admodel.InternalResourcePropertyListClass, admodel.InternalResourceValueTypeClass} {
		container := admodel.InternalResourceContainerFor(class, configuration)
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
	client := &adengine.Client{}
	// No members is not a silent no-op, and an unbounded list is refused
	// before anything is resolved.
	if _, err := adservice_resource_properties.New(client).
		AddResourcePropertyListMembers(t.Context(), admodel.ResourcePropertyListMembersRequest{}); err == nil {
		t.Fatal("an empty member list must be rejected")
	}
	identity, err := admodel.IdentityByDN(
		"CN=l,CN=Resource Property Lists,CN=Claims Configuration,CN=Services,CN=Configuration,DC=example",
	)
	if err != nil {
		t.Fatal(err)
	}
	many := make([]admodel.Identity, admodel.ResourcePropertyListMemberLimit+1)
	for i := range many {
		many[i] = identity
	}
	if _, err := adservice_resource_properties.New(client).
		AddResourcePropertyListMembers(t.Context(), admodel.ResourcePropertyListMembersRequest{Identity: identity, Members: many}); !errors.Is(
		err,
		admodel.ErrResourcePropertyMember,
	) {
		t.Fatalf("an over-limit member list must be rejected, got %v", err)
	}
}

func TestDecodeResourcePropertyRejectsWrongClass(t *testing.T) {
	object := admodel.Object{
		DistinguishedName: "CN=p,CN=Resource Properties,CN=Claims Configuration,CN=Services,CN=Configuration,DC=example",
		Attributes: map[string][][]byte{
			"objectclass": {[]byte("top"), []byte("user")},
			"objectguid":  {make([]byte, 16)},
			"name":        {[]byte("p")},
			"usnchanged":  {[]byte("7")},
		},
	}
	if _, err := admodel.InternalDecodeResourceProperty(object); err == nil {
		t.Fatal("a user object must not decode as a resource property")
	}
	if _, err := admodel.InternalDecodeResourcePropertyList(object); err == nil {
		t.Fatal("a user object must not decode as a property list")
	}
	if _, err := admodel.InternalDecodeResourceValueType(object); err == nil {
		t.Fatal("a user object must not decode as a value type")
	}
}

func TestDecodeResourcePropertyReadsTypedFields(t *testing.T) {
	object := admodel.Object{
		DistinguishedName: "CN=p,CN=Resource Properties,CN=Claims Configuration,CN=Services,CN=Configuration,DC=example",
		Attributes: map[string][][]byte{
			"objectclass": {[]byte("top"), []byte(admodel.InternalResourcePropertyClass)},
			"objectguid":  {make([]byte, 16)},
			"name":        {[]byte("Department_MS")},
			"usnchanged":  {[]byte("7")},
			"displayname": {[]byte("Department")},
			"enabled":     {[]byte("TRUE")},
			strings.ToLower(admodel.InternalResourceIsSecured): {[]byte("FALSE")},
			strings.ToLower(admodel.InternalClaimValueType):    {[]byte("3")},
			strings.ToLower(admodel.InternalResourceValueTypeReference): {
				[]byte(
					"CN=MS-DS-Text,CN=Value Types,CN=Claims Configuration,CN=Services,CN=Configuration,DC=example",
				),
			},
			strings.ToLower(admodel.InternalResourceAppliesTo): {
				[]byte("File"),
				[]byte("Folder"),
			},
		},
	}
	value, err := admodel.InternalDecodeResourceProperty(object)
	if err != nil {
		t.Fatal(err)
	}
	if value.ID == nil || *value.ID != "Department_MS" {
		t.Fatalf("id: %+v", value.ID)
	}
	if value.ValueType == nil || *value.ValueType != admodel.ClaimString {
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
