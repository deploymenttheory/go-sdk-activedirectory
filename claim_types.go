package activedirectory

import (
	"context"
	"crypto/rand"
	"encoding/hex"
	"errors"
	"slices"
	"strings"
	"unicode"
	"unicode/utf16"
)

type ClaimSourceType string

const (
	ClaimSourceAttribute   ClaimSourceType = "AD"
	ClaimSourceCertificate ClaimSourceType = "Certificate"
	ClaimSourceTransform   ClaimSourceType = "TransformPolicy"
)
const claimClass = "msDS-ClaimType"
const claimSourceAttribute = "msDS-ClaimAttributeSource"
const claimSourceOID = "msDS-ClaimSource"
const claimSourceKind = "msDS-ClaimSourceType"
const claimValueType = "msDS-ClaimValueType"
const claimSingle = "msDS-ClaimIsSingleValued"
const claimRestricted = "msDS-ClaimIsValueSpaceRestricted"
const claimPossible = "msDS-ClaimPossibleValues"
const claimApplies = "msDS-ClaimTypeAppliesToClass"
const claimShares = "msDS-ClaimSharesPossibleValuesWith"
const claimBacklinks = "msDS-ClaimSharesPossibleValuesWithBL"

// SchemaReference selects exactly one schema object by the shared DN/GUID
// Identity or its explicit LDAP display name. It never guesses from a string.
type SchemaReference struct {
	Identity        Identity
	LDAPDisplayName string
}
type ClaimTypeSource struct {
	Type      ClaimSourceType
	Attribute SchemaReference
	OID       string
	// ValueType is required for creation from TransformPolicy. For attribute
	// and certificate sources zero requests derivation; a nonzero value must
	// agree. Updates cannot change the existing claim's value type.
	ValueType ClaimValueType
}
type ClaimType struct {
	Raw                                     Object
	GUID                                    *GUID
	ID, DisplayName, Description            *string
	SourceType                              *ClaimSourceType
	SourceAttributeDN, SourceOID            *string
	ValueType                               *ClaimValueType
	Enabled, IsSingleValued, RestrictValues *bool
	SuggestedValues                         *ClaimSuggestedValues
	ProtectedFromAccidentalDeletion         *bool
}
type ClaimTypeReadOptions struct {
	ResolveIdentityOptions
	IncludeProtection, IncludeSchema, IncludeCompatibleResourceTypes bool
	References                                                       CentralAccessReferenceLimits
}
type ClaimSchemaObservation struct {
	Object Object
	Ranges []ClaimSchemaRange
}
type ClaimSchemaRange struct {
	Property   string
	Attributes map[string][][]byte
	Error      error
}
type ClaimTypeResult struct {
	Claim                                *ClaimType
	Observation                          IdentityResult
	AppliesToClasses, ResourceReferences CentralAccessReferencesResult
	Schema                               []ClaimSchemaObservation
	CompatibleResourceTypes              SearchResult
	Protection                           OUProtectionResult
}
type ClaimTypesResult struct {
	Claims      []ClaimTypeResult
	Observation SearchResult
}

func claimParent(configuration string) string {
	return "CN=Claim Types,CN=Claims Configuration,CN=Services," + configuration
}
func claimProperties(extra []string) []string {
	return append(slices.Clone(extra), "objectGUID", "uSNChanged", "objectClass", "name", "displayName", "description", "enabled", claimSourceAttribute, claimSourceOID, claimSourceKind, claimValueType, claimSingle, claimRestricted, claimPossible, claimShares)
}
func claimLocation(object Object, configuration string) error {
	if err := centralAccessClassCheck(object, claimClass); err != nil {
		return errors.Join(ErrClaimType, err)
	}
	parent, err := parentDirectoryDN(object.DistinguishedName)
	if err != nil {
		return err
	}
	if !centralSameDN(parent, claimParent(configuration)) {
		return ErrIdentityScope
	}
	return nil
}
func decodeClaimType(object Object) (result ClaimType, err error) {
	result.Raw = object
	d := rootDSEDecoder{attributes: object.Attributes}
	result.ID = d.text("name")
	result.DisplayName = d.text("displayName")
	result.Description = d.text("description")
	if kind := d.text(claimSourceKind); kind != nil {
		value := ClaimSourceType(*kind)
		result.SourceType = &value
	}
	result.SourceAttributeDN = d.text(claimSourceAttribute)
	result.SourceOID = d.text(claimSourceOID)
	if value := decodeScalar(&d, claimValueType, parseInt64); value != nil {
		v := ClaimValueType(*value)
		result.ValueType = &v
	}
	result.Enabled = decodeScalar(&d, "enabled", parseLDAPBool)
	result.IsSingleValued = decodeScalar(&d, claimSingle, parseLDAPBool)
	result.RestrictValues = decodeScalar(&d, claimRestricted, parseLDAPBool)
	guid, e := centralAccessGUID(object)
	if e == nil {
		result.GUID = &guid
	}
	err = e
	if raw := d.text(claimPossible); raw != nil {
		values, e := parseClaimValues(*raw, result.ValueType)
		result.SuggestedValues = &values
		err = errors.Join(err, e)
	}
	return result, errors.Join(err, errors.Join(d.errors...), centralAccessClassCheck(object, claimClass))
}
func claimFoldKey(text string) string {
	return strings.Map(func(r rune) rune {
		minimum := r
		for next := unicode.SimpleFold(r); next != r; next = unicode.SimpleFold(next) {
			if next < minimum {
				minimum = next
			}
		}
		return minimum
	}, text)
}
func validateClaimID(id string) error {
	length := len(utf16.Encode([]rune(id)))
	if !validDirectoryText(id) || length < 10 || length > 41 || len(id) < 9 || !strings.EqualFold(id[:9], "ad://ext/") {
		return ErrClaimType
	}
	invalid := func(r rune) bool { return r < 32 || strings.ContainsRune(`"<>|:*?\/ `, r) }
	runes := []rune(id)
	for i, r := range runes {
		if r == '/' {
			if i >= 9 && (i == len(runes)-1 || invalid(runes[i-1]) || invalid(runes[i+1])) {
				return ErrClaimType
			}
		} else if r != ':' && invalid(r) {
			return ErrClaimType
		}
	}
	return nil
}
func generateClaimID(display string) (string, error) {
	var prefix strings.Builder
	units := 0
	for _, r := range display {
		if r < 32 || strings.ContainsRune(`"<>|:*?\/ `, r) {
			continue
		}
		size := 1
		if r > 0xffff {
			size = 2
		}
		if units+size > 15 {
			break
		}
		prefix.WriteRune(r)
		units += size
	}
	if prefix.Len() == 0 {
		prefix.WriteString("claim")
	}
	var suffix [8]byte
	if _, err := rand.Read(suffix[:]); err != nil {
		return "", err
	}
	id := "ad://ext/" + prefix.String() + ":" + hex.EncodeToString(suffix[:])
	return id, validateClaimID(id)
}
func (c *Client) ClaimType(ctx context.Context, identity Identity, options ClaimTypeReadOptions) (result ClaimTypeResult, err error) {
	if err := centralAccessIdentity(identity, options.ResolveIdentityOptions); err != nil {
		return result, err
	}
	limits, err := normalizeCentralAccessLimits(options.References)
	if err != nil {
		return result, err
	}
	err = c.read(ctx, func(ctx context.Context) error {
		root, e := readIdentityRoot(ctx, c.session)
		if e != nil {
			return e
		}
		configuration, e := centralAccessConfiguration(root, c.config, options.Partition)
		if e != nil {
			return e
		}
		resolve := options.ResolveIdentityOptions
		resolve.Partition = configuration
		resolve.Properties = claimProperties(resolve.Properties)
		result.Observation, e = resolveIdentitySession(ctx, c.session, c.config, root, identity, resolve)
		if e != nil {
			return e
		}
		return c.projectClaimType(ctx, root, configuration, options, limits, &result)
	})
	return result, err
}
func (c *Client) projectClaimType(ctx context.Context, root RootDSE, configuration string, options ClaimTypeReadOptions, limits CentralAccessReferenceLimits, result *ClaimTypeResult) error {
	object := *result.Observation.Object
	value, decodeErr := decodeClaimType(object)
	result.Claim = &value
	if err := claimLocation(object, configuration); err != nil {
		return errors.Join(decodeErr, err)
	}
	var err, errorRefs error
	result.AppliesToClasses, err = readCentralAccessReferences(ctx, c.session, object, claimApplies, limits)
	result.ResourceReferences, errorRefs = readCentralAccessReferences(ctx, c.session, object, claimBacklinks, limits)
	err = errors.Join(decodeErr, err, errorRefs)
	if options.IncludeSchema && err == nil {
		schema := newClaimSchemaReader(ctx, c.session, c.config, root, &result.Schema)
		source, e := claimSourceFromObject(value)
		if e == nil {
			_, e = validateClaimSchema(schema, source, claimReferences(result.AppliesToClasses), value.ValueType)
		}
		err = errors.Join(err, e)
	}
	if options.IncludeCompatibleResourceTypes {
		if value.ValueType == nil || value.RestrictValues == nil {
			err = errors.Join(err, ErrAttributeUnavailable)
		} else {
			filter := FilterAnd(FilterEqual("objectClass", FilterText("msDS-ValueType")), FilterEqual(claimValueType, FilterInteger(int64(*value.ValueType))), FilterEqual("msDS-IsPossibleValuesPresent", FilterText(strings.ToUpper(strconvClaimBool(value.SuggestedValues != nil)))))
			result.CompatibleResourceTypes, errorRefs = searchIdentitySession(ctx, c.session, SearchOptions{Base: "CN=Value Types,CN=Claims Configuration,CN=Services," + configuration, Scope: ScopeOneLevel, TypedFilter: filter, Properties: []string{"objectGUID", "name", "displayName", claimValueType, claimSingle, claimRestricted, "msDS-IsPossibleValuesPresent"}})
			err = errors.Join(err, errorRefs)
		}
	}
	if options.IncludeProtection && value.GUID != nil {
		result.Protection, errorRefs = readOUProtection(ctx, c.session, root, c.config, OrganizationalUnit{DistinguishedName: object.DistinguishedName, GUID: value.GUID}, configuration)
		value.ProtectedFromAccidentalDeletion = result.Protection.ProtectedFromAccidentalDeletion
		result.Claim = &value
		err = errors.Join(err, errorRefs)
	}
	return err
}
func (c *Client) ClaimTypes(ctx context.Context, options SearchOptions) (result ClaimTypesResult, err error) {
	query, err := options.normalized()
	if err != nil {
		return result, err
	}
	err = c.read(ctx, func(ctx context.Context) error {
		root, e := readIdentityRoot(ctx, c.session)
		if e != nil {
			return e
		}
		configuration, e := centralAccessConfiguration(root, c.config, "")
		if e != nil {
			return e
		}
		if query.Base != "" && !centralSameDN(query.Base, claimParent(configuration)) {
			return ErrIdentityScope
		}
		query.Base = claimParent(configuration)
		query.Scope = ScopeOneLevel
		query.Filter = "(&(objectClass=" + claimClass + ")" + query.Filter + ")"
		query.Properties = claimProperties(options.Properties)
		result.Observation, e = searchIdentitySession(ctx, c.session, query)
		limits, _ := normalizeCentralAccessLimits(CentralAccessReferenceLimits{})
		for _, object := range result.Observation.Objects {
			row := ClaimTypeResult{Observation: IdentityResult{Object: &object, Complete: true}}
			rowErr := c.projectClaimType(ctx, root, configuration, ClaimTypeReadOptions{}, limits, &row)
			result.Claims = append(result.Claims, row)
			e = errors.Join(e, rowErr)
		}
		return e
	})
	if err != nil {
		result.Observation.Complete = false
	}
	return result, err
}
func strconvClaimBool(value bool) string {
	if value {
		return "TRUE"
	}
	return "FALSE"
}
func claimReferences(references CentralAccessReferencesResult) []SchemaReference {
	result := make([]SchemaReference, 0, len(references.References))
	for _, ref := range references.References {
		identity, _ := IdentityByDN(ref.DistinguishedName)
		result = append(result, SchemaReference{Identity: identity})
	}
	return result
}
