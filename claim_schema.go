package activedirectory

import (
	"context"
	"errors"
	"strings"
)

// Claim source and applies-to validation reads schema objects directly. The
// directory remains authoritative: every lookup is an explicit, bounded search
// in the schema naming context, and each observation is retained as evidence.

const claimSchemaMaxReferences = 1000

// claimValueTypeBySyntax maps an attributeSchema's attributeSyntax OID to the
// claim value type the reference module records in msDS-ClaimValueType.
//
// Keyed on attributeSyntax rather than oMSyntax because oMSyntax 4 is shared by
// OctetString and SID, which settle on different claim value types. Syntaxes
// absent here are rejected rather than guessed: ClaimUInt64 and ClaimFQBN have
// no attribute syntax that derives them, so they remain reachable only from a
// transform-policy source that states ValueType explicitly.
//
// See docs/research/claim-value-types.md. This table is a documented contract
// awaiting live qualification; it is not evidence of reference equivalence.
var claimValueTypeBySyntax = map[string]ClaimValueType{
	"2.5.5.8":  ClaimBoolean,     // Boolean
	"2.5.5.9":  ClaimInt64,       // Integer and Enumeration
	"2.5.5.16": ClaimInt64,       // LargeInteger
	"2.5.5.12": ClaimString,      // Unicode string
	"2.5.5.10": ClaimOctetString, // Octet string
	"2.5.5.17": ClaimSID,         // SID
}

// claimSchemaResolution reports what the schema itself said. Distinguished
// names are the directory's own values, never a caller string echoed back.
type claimSchemaResolution struct {
	SourceAttributeDN string
	AppliesToClassDNs []string
	ValueType         ClaimValueType
	IsSingleValued    *bool
}

type claimSchemaReader struct {
	ctx     context.Context
	session directorySession
	config  Config
	root    RootDSE
	out     *[]ClaimSchemaObservation
}

func newClaimSchemaReader(ctx context.Context, session directorySession, config Config, root RootDSE, out *[]ClaimSchemaObservation) *claimSchemaReader {
	return &claimSchemaReader{ctx: ctx, session: session, config: config, root: root, out: out}
}

func (r *claimSchemaReader) record(object Object) {
	if r.out != nil {
		*r.out = append(*r.out, ClaimSchemaObservation{Object: object})
	}
}

// resolve selects exactly one active schema object of the requested class.
// Exactly one of the reference's Identity and LDAPDisplayName must be set: a
// display name is never inferred from a DN, and a DN is never parsed from a
// name.
func (r *claimSchemaReader) resolve(reference SchemaReference, class string, properties []string) (Object, error) {
	var zero Object
	named := reference.LDAPDisplayName != ""
	if named == (reference.Identity.Form() != 0) {
		return zero, errors.Join(ErrClaimTypeSchema, ErrInvalidIdentity)
	}
	if r.root.SchemaNamingContext == nil || *r.root.SchemaNamingContext == "" {
		return zero, ErrIncompleteResult
	}
	properties = append(properties, "objectClass", "lDAPDisplayName", "isDefunct")
	if named {
		if !validDirectoryText(reference.LDAPDisplayName) {
			return zero, errors.Join(ErrClaimTypeSchema, ErrInvalidIdentity)
		}
		result, err := searchIdentitySession(r.ctx, r.session, SearchOptions{
			Base:        *r.root.SchemaNamingContext,
			Scope:       ScopeOneLevel,
			Filter:      "(&(objectClass=" + class + ")(lDAPDisplayName=" + ldapLiteral(reference.LDAPDisplayName) + "))",
			Properties:  properties,
			PageSize:    2,
			ResultLimit: 2,
		})
		if err != nil {
			return zero, err
		}
		switch {
		case len(result.Objects) > 1:
			return zero, ErrAmbiguousIdentity
		case !result.Complete:
			return zero, ErrIncompleteResult
		case len(result.Objects) == 0:
			return zero, ErrDirectoryObjectNotFound
		}
		return result.Objects[0], r.check(result.Objects[0], class)
	}
	observed, err := resolveIdentitySession(r.ctx, r.session, r.config, r.root, reference.Identity, ResolveIdentityOptions{
		Partition:  *r.root.SchemaNamingContext,
		Properties: properties,
	})
	if err != nil {
		return zero, err
	}
	if observed.Object == nil {
		return zero, ErrDirectoryObjectNotFound
	}
	return *observed.Object, r.check(*observed.Object, class)
}

// check retains the observation before judging it, so a rejected schema object
// is still visible as evidence.
func (r *claimSchemaReader) check(object Object, class string) error {
	r.record(object)
	if err := centralAccessClassCheck(object, class); err != nil {
		return errors.Join(ErrClaimTypeSchema, err)
	}
	decoder := rootDSEDecoder{attributes: object.Attributes}
	defunct := decodeScalar(&decoder, "isDefunct", parseLDAPBool)
	if len(decoder.errors) != 0 {
		return errors.Join(decoder.errors...)
	}
	if defunct != nil && *defunct {
		return errors.Join(ErrClaimTypeSchema, errDefunctSchemaObject)
	}
	return nil
}

var errDefunctSchemaObject = errors.New("schema object is defunct")

// claimSourceFromObject reconstructs the source a stored claim type describes.
// A claim whose stored source type is unknown, or which carries attributes
// belonging to a different source, is rejected rather than reinterpreted.
func claimSourceFromObject(claim ClaimType) (ClaimTypeSource, error) {
	var source ClaimTypeSource
	if claim.SourceType == nil {
		return source, ErrClaimType
	}
	source.Type = *claim.SourceType
	hasAttribute := claim.SourceAttributeDN != nil && *claim.SourceAttributeDN != ""
	hasOID := claim.SourceOID != nil && *claim.SourceOID != ""
	switch source.Type {
	case ClaimSourceAttribute:
		if !hasAttribute || hasOID {
			return source, ErrClaimType
		}
		identity, err := IdentityByDN(*claim.SourceAttributeDN)
		if err != nil {
			return source, err
		}
		source.Attribute = SchemaReference{Identity: identity}
	case ClaimSourceCertificate:
		if !hasOID || hasAttribute {
			return source, ErrClaimType
		}
		source.OID = *claim.SourceOID
	case ClaimSourceTransform:
		if hasAttribute || hasOID || claim.ValueType == nil {
			return source, ErrClaimType
		}
		source.ValueType = *claim.ValueType
	default:
		return source, ErrClaimType
	}
	return source, nil
}

// validateClaimSchema resolves the source and every applies-to class, and
// settles the claim value type.
//
// existing is the value type already stored on a claim. It is compared, never
// replaced: the reference module cannot change an existing claim's value type,
// so a disagreement is an error rather than an update.
func validateClaimSchema(reader *claimSchemaReader, source ClaimTypeSource, appliesTo []SchemaReference, existing *ClaimValueType) (claimSchemaResolution, error) {
	var resolution claimSchemaResolution
	if reader == nil {
		return resolution, ErrUnsupported
	}
	if len(appliesTo) > claimSchemaMaxReferences {
		return resolution, ErrClaimTypeSchema
	}
	switch source.Type {
	case ClaimSourceAttribute:
		if source.OID != "" {
			return resolution, ErrClaimType
		}
		object, err := reader.resolve(source.Attribute, "attributeSchema", []string{"attributeSyntax", "isSingleValued"})
		if err != nil {
			return resolution, err
		}
		decoder := rootDSEDecoder{attributes: object.Attributes}
		syntax := decoder.text("attributeSyntax")
		resolution.IsSingleValued = decodeScalar(&decoder, "isSingleValued", parseLDAPBool)
		if len(decoder.errors) != 0 {
			return resolution, errors.Join(decoder.errors...)
		}
		if syntax == nil {
			return resolution, errors.Join(ErrClaimTypeSchema, ErrAttributeUnavailable)
		}
		derived, ok := claimValueTypeBySyntax[strings.TrimSpace(*syntax)]
		if !ok {
			return resolution, errors.Join(ErrClaimTypeSchema, errUnmappedAttributeSyntax)
		}
		resolution.SourceAttributeDN = object.DistinguishedName
		resolution.ValueType = derived
	case ClaimSourceCertificate:
		if source.OID == "" || !claimSchemaReferenceEmpty(source.Attribute) {
			return resolution, ErrClaimType
		}
		if !validClaimOID(source.OID) {
			return resolution, ErrClaimType
		}
		// Certificate-sourced claims carry the issued OID as their value; the
		// reference module records no other value type for this source.
		resolution.ValueType = ClaimString
	case ClaimSourceTransform:
		if source.OID != "" || !claimSchemaReferenceEmpty(source.Attribute) {
			return resolution, ErrClaimType
		}
		if !validClaimValueType(source.ValueType) {
			return resolution, ErrClaimType
		}
		resolution.ValueType = source.ValueType
	default:
		return resolution, ErrClaimType
	}
	// A stated value type must agree with the one the source settles. Zero
	// requests derivation and is never treated as a disagreement.
	if source.Type != ClaimSourceTransform && source.ValueType != 0 && source.ValueType != resolution.ValueType {
		return resolution, ErrClaimTypeSchema
	}
	if existing != nil && *existing != resolution.ValueType {
		return resolution, ErrClaimTypeSchema
	}
	seen := make(map[string]struct{}, len(appliesTo))
	for _, class := range appliesTo {
		object, err := reader.resolve(class, "classSchema", nil)
		if err != nil {
			return resolution, err
		}
		key := strings.ToLower(object.DistinguishedName)
		if _, duplicate := seen[key]; duplicate {
			return resolution, errors.Join(ErrClaimTypeSchema, ErrInvalidValue)
		}
		seen[key] = struct{}{}
		resolution.AppliesToClassDNs = append(resolution.AppliesToClassDNs, object.DistinguishedName)
	}
	return resolution, nil
}

var errUnmappedAttributeSyntax = errors.New("attribute syntax has no claim value type")

// validClaimOID accepts a dotted-decimal OID with no leading zeros, matching
// the directory's own representation.
func validClaimOID(oid string) bool {
	if oid == "" || len(oid) > 1024 {
		return false
	}
	arcs := strings.Split(oid, ".")
	if len(arcs) < 2 {
		return false
	}
	for _, arc := range arcs {
		if arc == "" || (len(arc) > 1 && arc[0] == '0') {
			return false
		}
		for _, r := range arc {
			if r < '0' || r > '9' {
				return false
			}
		}
	}
	return true
}

// claimSchemaReferenceEmpty reports a reference that names nothing. Identity
// holds a byte slice and is not comparable, so its form carries the zero test.
func claimSchemaReferenceEmpty(reference SchemaReference) bool {
	return reference.LDAPDisplayName == "" && reference.Identity.Form() == 0
}
