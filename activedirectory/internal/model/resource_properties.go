package model

import (
	"errors"
	"strings"
)

// Resource properties, resource property lists and value types share the
// configuration partition's Claims Configuration container with claim types.
// Value types are read-only: the reference exposes no New/Set/Remove for them,
// so this SDK does not invent one.

var (
	ErrResourceProperty       = errors.New("invalid resource property or property list operation")
	ErrResourcePropertyMember = errors.New("invalid resource property list membership change")
)

const (
	InternalResourcePropertyClass     = "msDS-ResourceProperty"
	InternalResourcePropertyListClass = "msDS-ResourcePropertyList"
	InternalResourceValueTypeClass    = "msDS-ValueType"

	InternalResourceValueTypeReference = "msDS-ValueTypeReference"
	InternalResourceSharesValuesWith   = "msDS-ClaimSharesPossibleValuesWith"
	InternalResourceAppliesTo          = "msDS-AppliesToResourceTypes"
	InternalResourceIsSecured          = "msDS-IsUsedAsResourceSecurityAttribute"
	InternalResourceListMembers        = "msDS-MembersOfResourcePropertyList"
	InternalResourcePossibleValuesFlag = "msDS-IsPossibleValuesPresent"
)

// ResourcePropertyListMemberLimit bounds one membership change. Exceeding it is
// an error rather than a silently truncated write.
const ResourcePropertyListMemberLimit = 10000

func InternalResourcePropertyParent(configuration string) string {
	return "CN=Resource Properties,CN=Claims Configuration,CN=Services," + configuration
}

func InternalResourcePropertyListParent(configuration string) string {
	return "CN=Resource Property Lists,CN=Claims Configuration,CN=Services," + configuration
}

func InternalResourceValueTypeParent(configuration string) string {
	return "CN=Value Types,CN=Claims Configuration,CN=Services," + configuration
}

// resourceContainerFor selects the container that owns a class, so location
// checks and searches cannot drift apart.
func InternalResourceContainerFor(class, configuration string) string {
	switch class {
	case InternalResourcePropertyClass:
		return InternalResourcePropertyParent(configuration)
	case InternalResourcePropertyListClass:
		return InternalResourcePropertyListParent(configuration)
	default:
		return InternalResourceValueTypeParent(configuration)
	}
}

func InternalResourcePropertyProperties(extra []string) []string {
	return append(
		append([]string(nil), extra...),
		"objectGUID",
		"uSNChanged",
		"objectClass",
		"name",
		"displayName",
		"description",
		"enabled",
		InternalResourceValueTypeReference,
		InternalResourceSharesValuesWith,
		InternalResourceAppliesTo,
		InternalResourceIsSecured,
		InternalClaimPossible,
		InternalClaimRestricted,
		InternalClaimValueType,
	)
}

func InternalResourceListProperties(extra []string) []string {
	return append(
		append([]string(nil), extra...),
		"objectGUID",
		"uSNChanged",
		"objectClass",
		"name",
		"displayName",
		"description",
		InternalResourceListMembers,
	)
}

func InternalResourceValueTypeProperties(extra []string) []string {
	return append(
		append([]string(nil), extra...),
		"objectGUID",
		"uSNChanged",
		"objectClass",
		"name",
		"displayName",
		"description",
		InternalClaimValueType,
		InternalClaimSingle,
		InternalClaimRestricted,
		InternalResourcePossibleValuesFlag,
	)
}

// resourceLocation requires the expected class and the direct container parent.
// A matching class elsewhere in the tree is out of scope, not a near match.
func InternalResourceLocation(object Object, configuration, class string) error {
	if err := InternalCentralAccessClassCheck(object, class); err != nil {
		return errors.Join(ErrResourceProperty, err)
	}
	parent, err := InternalParentDirectoryDN(object.DistinguishedName)
	if err != nil {
		return err
	}
	if !InternalCentralSameDN(parent, InternalResourceContainerFor(class, configuration)) {
		return ErrIdentityScope
	}
	return nil
}

// ResourceProperty is one msDS-ResourceProperty. Suggested values and the
// restricted value space mirror the claim-type representation because the
// directory stores them in the same attributes.
type ResourceProperty struct {
	Raw                             Object
	GUID                            *GUID
	ID, DisplayName, Description    *string
	Enabled, IsSecured              *bool
	RestrictValues                  *bool
	ValueTypeDN                     *string
	ValueType                       *ClaimValueType
	SharesValuesWithDN              *string
	AppliesToResourceTypes          []string
	SuggestedValues                 *ClaimSuggestedValues
	ProtectedFromAccidentalDeletion *bool
}

type ResourcePropertyReadOptions struct {
	ResolveIdentityOptions
	IncludeProtection bool
	// IncludeValueType resolves the referenced value type object so a caller
	// sees the settled claim value type rather than only its DN.
	IncludeValueType bool
	References       CentralAccessReferenceLimits
}

type ResourcePropertyResult struct {
	Property    *ResourceProperty
	Observation IdentityResult
	// ValueTypeObservation is populated only when IncludeValueType is set.
	ValueTypeObservation *ResourceValueTypeResult
	Protection           OUProtectionResult
}

type ResourcePropertiesResult struct {
	Properties  []ResourcePropertyResult
	Observation SearchResult
}

// ResourceValueType is one read-only msDS-ValueType.
type ResourceValueType struct {
	Raw                          Object
	GUID                         *GUID
	ID, DisplayName, Description *string
	ValueType                    *ClaimValueType
	IsSingleValued               *bool
	RestrictValues               *bool
	PossibleValuesPresent        *bool
}

type ResourceValueTypeResult struct {
	ValueType   *ResourceValueType
	Observation IdentityResult
}

type ResourceValueTypesResult struct {
	ValueTypes  []ResourceValueTypeResult
	Observation SearchResult
}

func InternalDecodeResourceProperty(object Object) (result ResourceProperty, err error) {
	result.Raw = object
	d := InternalRootDSEDecoder{InternalAttributes: object.Attributes}
	result.ID = d.InternalText("name")
	result.DisplayName = d.InternalText("displayName")
	result.Description = d.InternalText("description")
	result.Enabled = InternalDecodeScalar(&d, "enabled", InternalParseLDAPBool)
	result.IsSecured = InternalDecodeScalar(&d, InternalResourceIsSecured, InternalParseLDAPBool)
	result.RestrictValues = InternalDecodeScalar(&d, InternalClaimRestricted, InternalParseLDAPBool)
	result.ValueTypeDN = d.InternalText(InternalResourceValueTypeReference)
	result.SharesValuesWithDN = d.InternalText(InternalResourceSharesValuesWith)
	result.AppliesToResourceTypes = d.InternalTexts(InternalResourceAppliesTo)
	if value := InternalDecodeScalar(&d, InternalClaimValueType, InternalParseInt64); value != nil {
		settled := ClaimValueType(*value)
		result.ValueType = &settled
	}
	guid, guidErr := InternalCentralAccessGUID(object)
	if guidErr == nil {
		result.GUID = &guid
	}
	err = guidErr
	if raw := d.InternalText(InternalClaimPossible); raw != nil {
		values, valuesErr := InternalParseClaimValues(*raw, result.ValueType)
		result.SuggestedValues = &values
		err = errors.Join(err, valuesErr)
	}
	return result, errors.Join(
		err,
		errors.Join(d.InternalErrors...),
		InternalCentralAccessClassCheck(object, InternalResourcePropertyClass),
	)
}

func InternalDecodeResourceValueType(object Object) (result ResourceValueType, err error) {
	result.Raw = object
	d := InternalRootDSEDecoder{InternalAttributes: object.Attributes}
	result.ID = d.InternalText("name")
	result.DisplayName = d.InternalText("displayName")
	result.Description = d.InternalText("description")
	result.IsSingleValued = InternalDecodeScalar(&d, InternalClaimSingle, InternalParseLDAPBool)
	result.RestrictValues = InternalDecodeScalar(&d, InternalClaimRestricted, InternalParseLDAPBool)
	result.PossibleValuesPresent = InternalDecodeScalar(
		&d,
		InternalResourcePossibleValuesFlag,
		InternalParseLDAPBool,
	)
	if value := InternalDecodeScalar(&d, InternalClaimValueType, InternalParseInt64); value != nil {
		settled := ClaimValueType(*value)
		result.ValueType = &settled
	}
	guid, guidErr := InternalCentralAccessGUID(object)
	if guidErr == nil {
		result.GUID = &guid
	}
	return result, errors.Join(
		guidErr,
		errors.Join(d.InternalErrors...),
		InternalCentralAccessClassCheck(object, InternalResourceValueTypeClass),
	)
}

// resourceAppliesToValid rejects applies-to entries that are empty or carry
// directory-hostile text, before any write is attempted.
func InternalResourceAppliesToValid(types []string) error {
	seen := make(map[string]struct{}, len(types))
	for _, name := range types {
		if name == "" || !InternalValidDirectoryText(name) {
			return ErrResourceProperty
		}
		key := strings.ToLower(name)
		if _, duplicate := seen[key]; duplicate {
			return ErrResourceProperty
		}
		seen[key] = struct{}{}
	}
	return nil
}
