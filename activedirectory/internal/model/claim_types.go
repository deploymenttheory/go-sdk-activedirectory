package model

import (
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

const (
	InternalClaimClass           = "msDS-ClaimType"
	InternalClaimSourceAttribute = "msDS-ClaimAttributeSource"
	InternalClaimSourceOID       = "msDS-ClaimSource"
	InternalClaimSourceKind      = "msDS-ClaimSourceType"
	InternalClaimValueType       = "msDS-ClaimValueType"
	InternalClaimSingle          = "msDS-ClaimIsSingleValued"
	InternalClaimRestricted      = "msDS-ClaimIsValueSpaceRestricted"
	InternalClaimPossible        = "msDS-ClaimPossibleValues"
	InternalClaimApplies         = "msDS-ClaimTypeAppliesToClass"
	InternalClaimShares          = "msDS-ClaimSharesPossibleValuesWith"
	InternalClaimBacklinks       = "msDS-ClaimSharesPossibleValuesWithBL"
)

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

func InternalClaimParent(configuration string) string {
	return "CN=Claim Types,CN=Claims Configuration,CN=Services," + configuration
}

func InternalClaimProperties(extra []string) []string {
	return append(
		slices.Clone(extra),
		"objectGUID",
		"uSNChanged",
		"objectClass",
		"name",
		"displayName",
		"description",
		"enabled",
		InternalClaimSourceAttribute,
		InternalClaimSourceOID,
		InternalClaimSourceKind,
		InternalClaimValueType,
		InternalClaimSingle,
		InternalClaimRestricted,
		InternalClaimPossible,
		InternalClaimShares,
	)
}

func InternalClaimLocation(object Object, configuration string) error {
	if err := InternalCentralAccessClassCheck(object, InternalClaimClass); err != nil {
		return errors.Join(ErrClaimType, err)
	}
	parent, err := InternalParentDirectoryDN(object.DistinguishedName)
	if err != nil {
		return err
	}
	if !InternalCentralSameDN(parent, InternalClaimParent(configuration)) {
		return ErrIdentityScope
	}
	return nil
}

func InternalDecodeClaimType(object Object) (result ClaimType, err error) {
	result.Raw = object
	d := InternalRootDSEDecoder{InternalAttributes: object.Attributes}
	result.ID = d.InternalText("name")
	result.DisplayName = d.InternalText("displayName")
	result.Description = d.InternalText("description")
	if kind := d.InternalText(InternalClaimSourceKind); kind != nil {
		value := ClaimSourceType(*kind)
		result.SourceType = &value
	}
	result.SourceAttributeDN = d.InternalText(InternalClaimSourceAttribute)
	result.SourceOID = d.InternalText(InternalClaimSourceOID)
	if value := InternalDecodeScalar(&d, InternalClaimValueType, InternalParseInt64); value != nil {
		v := ClaimValueType(*value)
		result.ValueType = &v
	}
	result.Enabled = InternalDecodeScalar(&d, "enabled", InternalParseLDAPBool)
	result.IsSingleValued = InternalDecodeScalar(&d, InternalClaimSingle, InternalParseLDAPBool)
	result.RestrictValues = InternalDecodeScalar(&d, InternalClaimRestricted, InternalParseLDAPBool)
	guid, e := InternalCentralAccessGUID(object)
	if e == nil {
		result.GUID = &guid
	}
	err = e
	if raw := d.InternalText(InternalClaimPossible); raw != nil {
		values, e := InternalParseClaimValues(*raw, result.ValueType)
		result.SuggestedValues = &values
		err = errors.Join(err, e)
	}
	return result, errors.Join(
		err,
		errors.Join(d.InternalErrors...),
		InternalCentralAccessClassCheck(object, InternalClaimClass),
	)
}

func InternalClaimFoldKey(text string) string {
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

func InternalValidateClaimID(id string) error {
	length := len(utf16.Encode([]rune(id)))
	if !InternalValidDirectoryText(id) || length < 10 || length > 41 || len(id) < 9 ||
		!strings.EqualFold(id[:9], "ad://ext/") {
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

func InternalGenerateClaimID(display string) (string, error) {
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
	return id, InternalValidateClaimID(id)
}

func InternalStrconvClaimBool(value bool) string {
	if value {
		return "TRUE"
	}
	return "FALSE"
}

func InternalClaimReferences(references CentralAccessReferencesResult) []SchemaReference {
	result := make([]SchemaReference, 0, len(references.References))
	for _, ref := range references.References {
		identity, _ := IdentityByDN(ref.DistinguishedName)
		result = append(result, SchemaReference{Identity: identity})
	}
	return result
}
