package acceptance

import (
	"errors"
	"strings"
	"testing"

	admodel "github.com/deploymenttheory/go-sdk-activedirectory/activedirectory/internal/model"
)

func InternalClaimTestSource(kind admodel.ClaimSourceType) admodel.ClaimTypeSource {
	return admodel.ClaimTypeSource{Type: kind}
}

func TestValidClaimOID(t *testing.T) {
	for _, oid := range []string{"1.2", "1.3.6.1.4.1.311.25.1", "0.9.2342", "2.5.4.3"} {
		if !admodel.InternalValidClaimOID(oid) {
			t.Fatalf("rejected a well-formed OID: %q", oid)
		}
	}
	// Leading zeros, empty arcs, single arcs and non-digits are not the
	// directory's own representation and must not be accepted.
	for _, oid := range []string{"", "1", "1.", ".1", "1..2", "1.02", "1.2.a", "1.2 ", "01.2", strings.Repeat("1.", 600)} {
		if admodel.InternalValidClaimOID(oid) {
			t.Fatalf("accepted a malformed OID: %q", oid)
		}
	}
}

func TestClaimValueTypeBySyntaxRejectsUnmappedSyntax(t *testing.T) {
	// Every mapped syntax must settle on a valid claim value type.
	for syntax, value := range admodel.InternalClaimValueTypeBySyntax {
		if !admodel.InternalValidClaimValueType(value) {
			t.Fatalf("syntax %s maps to an invalid claim value type %d", syntax, value)
		}
	}
	// oMSyntax 4 covers both octet strings and SIDs, so the table must keep
	// them distinct rather than collapsing them.
	if admodel.InternalClaimValueTypeBySyntax["2.5.5.10"] == admodel.InternalClaimValueTypeBySyntax["2.5.5.17"] {
		t.Fatal("octet string and SID syntaxes must not settle on the same value type")
	}
	// UInt64 and FQBN have no deriving attribute syntax; they stay reachable
	// only from an explicit transform-policy value type.
	for _, unreachable := range []admodel.ClaimValueType{admodel.ClaimUInt64, admodel.ClaimFQBN} {
		for syntax, value := range admodel.InternalClaimValueTypeBySyntax {
			if value == unreachable {
				t.Fatalf("syntax %s must not derive value type %d", syntax, unreachable)
			}
		}
	}
}

func TestClaimSourceFromObject(t *testing.T) {
	text := func(value string) *string { return &value }
	kind := func(value admodel.ClaimSourceType) *admodel.ClaimSourceType { return &value }
	valueType := func(value admodel.ClaimValueType) *admodel.ClaimValueType { return &value }

	attribute := admodel.ClaimType{
		SourceType:        kind(admodel.ClaimSourceAttribute),
		SourceAttributeDN: text("CN=department,CN=Schema,CN=Configuration,DC=example"),
	}
	source, err := admodel.InternalClaimSourceFromObject(attribute)
	if err != nil || source.Type != admodel.ClaimSourceAttribute ||
		source.Attribute.Identity.Form() != admodel.IdentityFormDN {
		t.Fatalf("attribute source: %+v err=%v", source, err)
	}

	certificate := admodel.ClaimType{
		SourceType: kind(admodel.ClaimSourceCertificate),
		SourceOID:  text("1.3.6.1.4.1.311.25.1"),
	}
	if source, err := admodel.InternalClaimSourceFromObject(
		certificate,
	); err != nil ||
		source.OID != "1.3.6.1.4.1.311.25.1" {
		t.Fatalf("certificate source: %+v err=%v", source, err)
	}

	transform := admodel.ClaimType{
		SourceType: kind(admodel.ClaimSourceTransform),
		ValueType:  valueType(admodel.ClaimString),
	}
	if source, err := admodel.InternalClaimSourceFromObject(
		transform,
	); err != nil ||
		source.ValueType != admodel.ClaimString {
		t.Fatalf("transform source: %+v err=%v", source, err)
	}

	// A stored claim carrying another form's attributes is ambiguous and is
	// rejected rather than reinterpreted as one of them.
	for name, claim := range map[string]admodel.ClaimType{
		"no source type":        {},
		"unknown source type":   {SourceType: kind("Nonsense")},
		"attribute without dn":  {SourceType: kind(admodel.ClaimSourceAttribute)},
		"attribute with oid":    {SourceType: kind(admodel.ClaimSourceAttribute), SourceAttributeDN: text("CN=a,DC=example"), SourceOID: text("1.2")},
		"certificate with dn":   {SourceType: kind(admodel.ClaimSourceCertificate), SourceOID: text("1.2"), SourceAttributeDN: text("CN=a,DC=example")},
		"certificate without":   {SourceType: kind(admodel.ClaimSourceCertificate)},
		"transform with source": {SourceType: kind(admodel.ClaimSourceTransform), SourceOID: text("1.2"), ValueType: valueType(admodel.ClaimString)},
		"transform no value":    {SourceType: kind(admodel.ClaimSourceTransform)},
	} {
		if _, err := admodel.InternalClaimSourceFromObject(claim); err == nil {
			t.Fatalf("%s: expected rejection", name)
		}
	}
}

func TestValidateClaimSchemaRejectsNilReader(t *testing.T) {
	if _, err := admodel.InternalValidateClaimSchema(
		nil,
		InternalClaimTestSource(admodel.ClaimSourceTransform),
		nil,
		nil,
	); !errors.Is(
		err,
		admodel.ErrUnsupported,
	) {
		t.Fatalf("nil reader must be unsupported, got %v", err)
	}
}

func TestValidateClaimSchemaTransformSource(t *testing.T) {
	reader := admodel.InternalNewClaimSchemaReader(
		t.Context(),
		nil,
		admodel.Config{},
		admodel.RootDSE{},
		nil,
	)

	// A transform policy states its own value type and reads no schema.
	source := admodel.ClaimTypeSource{
		Type:      admodel.ClaimSourceTransform,
		ValueType: admodel.ClaimUInt64,
	}
	resolution, err := admodel.InternalValidateClaimSchema(reader, source, nil, nil)
	if err != nil || resolution.ValueType != admodel.ClaimUInt64 ||
		resolution.SourceAttributeDN != "" {
		t.Fatalf("transform: %+v err=%v", resolution, err)
	}

	// An invalid or absent value type cannot be derived for this source.
	for _, invalid := range []admodel.ClaimValueType{0, 7, 99, -1} {
		if _, err := admodel.InternalValidateClaimSchema(
			reader,
			admodel.ClaimTypeSource{Type: admodel.ClaimSourceTransform, ValueType: invalid},
			nil,
			nil,
		); !errors.Is(
			err,
			admodel.ErrClaimType,
		) {
			t.Fatalf("value type %d: expected ErrClaimType, got %v", invalid, err)
		}
	}

	// A transform source carrying an attribute or OID is contradictory.
	if _, err := admodel.InternalValidateClaimSchema(
		reader,
		admodel.ClaimTypeSource{
			Type:      admodel.ClaimSourceTransform,
			ValueType: admodel.ClaimString,
			OID:       "1.2",
		},
		nil,
		nil,
	); !errors.Is(
		err,
		admodel.ErrClaimType,
	) {
		t.Fatalf("transform with OID: %v", err)
	}

	// An existing claim's value type can never be changed by an update.
	existing := admodel.ClaimString
	if _, err := admodel.InternalValidateClaimSchema(
		reader,
		admodel.ClaimTypeSource{Type: admodel.ClaimSourceTransform, ValueType: admodel.ClaimUInt64},
		nil,
		&existing,
	); !errors.Is(
		err,
		admodel.ErrClaimTypeSchema,
	) {
		t.Fatalf("value type change must be rejected, got %v", err)
	}
	same := admodel.ClaimUInt64
	if _, err := admodel.InternalValidateClaimSchema(
		reader,
		admodel.ClaimTypeSource{Type: admodel.ClaimSourceTransform, ValueType: admodel.ClaimUInt64},
		nil,
		&same,
	); err != nil {
		t.Fatalf("matching value type must be accepted: %v", err)
	}
}

func TestValidateClaimSchemaCertificateSource(t *testing.T) {
	reader := admodel.InternalNewClaimSchemaReader(
		t.Context(),
		nil,
		admodel.Config{},
		admodel.RootDSE{},
		nil,
	)
	resolution, err := admodel.InternalValidateClaimSchema(
		reader,
		admodel.ClaimTypeSource{Type: admodel.ClaimSourceCertificate, OID: "1.3.6.1.4.1.311.25.1"},
		nil,
		nil,
	)
	if err != nil || resolution.ValueType != admodel.ClaimString {
		t.Fatalf("certificate: %+v err=%v", resolution, err)
	}
	for _, bad := range []string{"", "1", "1.02", "nonsense"} {
		if _, err := admodel.InternalValidateClaimSchema(
			reader,
			admodel.ClaimTypeSource{Type: admodel.ClaimSourceCertificate, OID: bad},
			nil,
			nil,
		); !errors.Is(
			err,
			admodel.ErrClaimType,
		) {
			t.Fatalf("OID %q: expected ErrClaimType, got %v", bad, err)
		}
	}
	// A stated value type that disagrees with the settled one is an error,
	// while zero continues to request derivation.
	if _, err := admodel.InternalValidateClaimSchema(
		reader,
		admodel.ClaimTypeSource{
			Type:      admodel.ClaimSourceCertificate,
			OID:       "1.2",
			ValueType: admodel.ClaimSID,
		},
		nil,
		nil,
	); !errors.Is(
		err,
		admodel.ErrClaimTypeSchema,
	) {
		t.Fatalf("disagreeing value type must be rejected, got %v", err)
	}
	if _, err := admodel.InternalValidateClaimSchema(
		reader,
		admodel.ClaimTypeSource{
			Type:      admodel.ClaimSourceCertificate,
			OID:       "1.2",
			ValueType: admodel.ClaimString,
		},
		nil,
		nil,
	); err != nil {
		t.Fatalf("agreeing value type must be accepted: %v", err)
	}
}

func TestValidateClaimSchemaUnknownSourceType(t *testing.T) {
	reader := admodel.InternalNewClaimSchemaReader(
		t.Context(),
		nil,
		admodel.Config{},
		admodel.RootDSE{},
		nil,
	)
	if _, err := admodel.InternalValidateClaimSchema(
		reader,
		InternalClaimTestSource("Nonsense"),
		nil,
		nil,
	); !errors.Is(
		err,
		admodel.ErrClaimType,
	) {
		t.Fatalf("unknown source type: %v", err)
	}
	if _, err := admodel.InternalValidateClaimSchema(
		reader,
		InternalClaimTestSource(admodel.ClaimSourceTransform),
		make([]admodel.SchemaReference, admodel.InternalClaimSchemaMaxReferences+1),
		nil,
	); !errors.Is(
		err,
		admodel.ErrClaimTypeSchema,
	) {
		t.Fatal("an unbounded applies-to list must be rejected before any read")
	}
}

func TestClaimSchemaReferenceEmpty(t *testing.T) {
	if !admodel.InternalClaimSchemaReferenceEmpty(admodel.SchemaReference{}) {
		t.Fatal("zero reference must be empty")
	}
	if admodel.InternalClaimSchemaReferenceEmpty(
		admodel.SchemaReference{LDAPDisplayName: "department"},
	) {
		t.Fatal("named reference is not empty")
	}
	identity, err := admodel.IdentityByDN("CN=department,CN=Schema,DC=example")
	if err != nil {
		t.Fatal(err)
	}
	if admodel.InternalClaimSchemaReferenceEmpty(admodel.SchemaReference{Identity: identity}) {
		t.Fatal("identity reference is not empty")
	}
}

func TestClaimSchemaResolveRequiresExactlyOneForm(t *testing.T) {
	schema := "CN=Schema,CN=Configuration,DC=example"
	reader := admodel.InternalNewClaimSchemaReader(
		t.Context(),
		nil,
		admodel.Config{},
		admodel.RootDSE{SchemaNamingContext: &schema},
		nil,
	)
	identity, err := admodel.IdentityByDN("CN=department," + schema)
	if err != nil {
		t.Fatal(err)
	}
	// Neither form, and both forms at once, are equally unresolvable: the SDK
	// never picks one over the other.
	for name, reference := range map[string]admodel.SchemaReference{
		"neither": {},
		"both":    {Identity: identity, LDAPDisplayName: "department"},
	} {
		if _, err := reader.InternalResolve(
			reference,
			"attributeSchema",
			nil,
		); !errors.Is(
			err,
			admodel.ErrInvalidIdentity,
		) {
			t.Fatalf("%s: expected ErrInvalidIdentity, got %v", name, err)
		}
	}
}

func TestClaimSchemaResolveRequiresSchemaNamingContext(t *testing.T) {
	reader := admodel.InternalNewClaimSchemaReader(
		t.Context(),
		nil,
		admodel.Config{},
		admodel.RootDSE{},
		nil,
	)
	if _, err := reader.InternalResolve(
		admodel.SchemaReference{LDAPDisplayName: "department"},
		"attributeSchema",
		nil,
	); !errors.Is(
		err,
		admodel.ErrIncompleteResult,
	) {
		t.Fatalf("absent schema naming context must be incomplete, got %v", err)
	}
	empty := ""
	reader = admodel.InternalNewClaimSchemaReader(
		t.Context(),
		nil,
		admodel.Config{},
		admodel.RootDSE{SchemaNamingContext: &empty},
		nil,
	)
	if _, err := reader.InternalResolve(
		admodel.SchemaReference{LDAPDisplayName: "department"},
		"attributeSchema",
		nil,
	); !errors.Is(
		err,
		admodel.ErrIncompleteResult,
	) {
		t.Fatalf("empty schema naming context must be incomplete, got %v", err)
	}
}

func TestClaimSchemaCheckRetainsRejectedObservation(t *testing.T) {
	var observed []admodel.ClaimSchemaObservation
	reader := admodel.InternalNewClaimSchemaReader(
		t.Context(),
		nil,
		admodel.Config{},
		admodel.RootDSE{},
		&observed,
	)
	defunct := admodel.Object{
		DistinguishedName: "CN=old,CN=Schema,DC=example",
		Attributes: map[string][][]byte{
			"objectclass": {[]byte("top"), []byte("attributeSchema")},
			"isdefunct":   {[]byte("TRUE")},
		},
	}
	err := reader.InternalCheck(defunct, "attributeSchema")
	if !errors.Is(err, admodel.ErrClaimTypeSchema) {
		t.Fatalf("a defunct schema object must be rejected, got %v", err)
	}
	// The rejected object still has to be visible as evidence.
	if len(observed) != 1 || observed[0].Object.DistinguishedName != defunct.DistinguishedName {
		t.Fatalf("rejected observation was not retained: %+v", observed)
	}
	wrongClass := admodel.Object{
		DistinguishedName: "CN=user,CN=Schema,DC=example",
		Attributes: map[string][][]byte{
			"objectclass": {[]byte("top"), []byte("classSchema")},
		},
	}
	if err := reader.InternalCheck(
		wrongClass,
		"attributeSchema",
	); !errors.Is(
		err,
		admodel.ErrClaimTypeSchema,
	) {
		t.Fatalf("a wrong-class object must be rejected, got %v", err)
	}
	if len(observed) != 2 {
		t.Fatalf("every observation must be retained: %+v", observed)
	}
}
