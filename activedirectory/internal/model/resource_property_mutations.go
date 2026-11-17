package model

import (
	"errors"
	"strings"
)

// Resource property writes mirror the claim-type machinery: the value type is
// settled from the referenced value-type object rather than accepted directly,
// and suggested values are encoded for that settled type.

// CreateResourcePropertyRequest creates one resource property.
type CreateResourcePropertyRequest struct {
	// DisplayName is required. ID is the directory name; when nil the display
	// name is used, matching the reference's own default.
	DisplayName string
	ID          *string
	Description *string
	// ValueType references an msDS-ValueType object by identity or by its
	// lDAPDisplayName-equivalent name. It settles the property's value type.
	ValueType SchemaReference
	// SharesValuesWith optionally references a claim type whose possible
	// values this property shares.
	SharesValuesWith                *Identity
	AppliesToResourceTypes          []string
	Enabled, IsSecured              *bool
	RestrictValues                  *bool
	SuggestedValues                 []ClaimSuggestedValue
	ProtectedFromAccidentalDeletion *bool
	Attributes                      map[string][]RawValue
	Options                         ObjectMutationOptions
}

// UpdateResourcePropertyRequest changes one resource property.
type UpdateResourcePropertyRequest struct {
	Identity                 Identity
	DisplayName, Description *string
	ClearDescription         bool
	// SharesValuesWith re-points the shared claim type; ClearSharesValuesWith
	// removes the reference. They conflict.
	SharesValuesWith      *Identity
	ClearSharesValuesWith bool
	// AppliesToResourceTypes replaces the stored list when Replace is set,
	// otherwise adds. Clear removes the attribute.
	AppliesToResourceTypes          []string
	ReplaceAppliesToResourceTypes   bool
	ClearAppliesToResourceTypes     bool
	Enabled, IsSecured              *bool
	RestrictValues                  *bool
	SuggestedValues                 []ClaimSuggestedValue
	ClearSuggestedValues            bool
	ProtectedFromAccidentalDeletion *bool
	Changes                         []AttributeChange
	Options                         ObjectMutationOptions
}

// CreateResourcePropertyListRequest creates one property list.
type CreateResourcePropertyListRequest struct {
	Name                            string
	Description                     *string
	ProtectedFromAccidentalDeletion *bool
	Options                         ObjectMutationOptions
}

// UpdateResourcePropertyListRequest changes one property list.
type UpdateResourcePropertyListRequest struct {
	Identity                        Identity
	Description                     *string
	ClearDescription                bool
	ProtectedFromAccidentalDeletion *bool
	Changes                         []AttributeChange
	Options                         ObjectMutationOptions
}

// ResourcePropertyListMembersRequest adds or removes list members. Members are
// resource properties; each is resolved and verified before any write.
type ResourcePropertyListMembersRequest struct {
	Identity   Identity
	Members    []Identity
	References CentralAccessReferenceLimits
	Options    ObjectMutationOptions
}

type ResourcePropertyMutationResult struct {
	Mutation   ObjectMutationResult
	Protection OUProtectionResult
	Property   *ResourceProperty
	// ValueTypeObservation is the value-type object the property was pointed
	// at, retained even when the write was rejected.
	ValueTypeObservation *ResourceValueTypeResult
	GeneratedID          *string
}

type ResourcePropertyListMutationResult struct {
	Mutation   ObjectMutationResult
	Protection OUProtectionResult
	List       *ResourcePropertyList
}

// ResourcePropertyList is one msDS-ResourcePropertyList.
type ResourcePropertyList struct {
	Raw                             Object
	GUID                            *GUID
	ID, DisplayName, Description    *string
	ProtectedFromAccidentalDeletion *bool
}

type ResourcePropertyListResult struct {
	List        *ResourcePropertyList
	Observation IdentityResult
	Members     CentralAccessReferencesResult
	Protection  OUProtectionResult
}

type ResourcePropertyListsResult struct {
	Lists       []ResourcePropertyListResult
	Observation SearchResult
}

type ResourcePropertyListMembersResult struct {
	Mutation ObjectMutationResult
	Before   CentralAccessReferencesResult
	After    CentralAccessReferencesResult
	Inputs   []CentralAccessMemberInput
}

func InternalDecodeResourcePropertyList(object Object) (result ResourcePropertyList, err error) {
	result.Raw = object
	d := InternalRootDSEDecoder{InternalAttributes: object.Attributes}
	result.ID = d.InternalText("name")
	result.DisplayName = d.InternalText("displayName")
	result.Description = d.InternalText("description")
	guid, guidErr := InternalCentralAccessGUID(object)
	if guidErr == nil {
		result.GUID = &guid
	}
	return result, errors.Join(
		guidErr,
		errors.Join(d.InternalErrors...),
		InternalCentralAccessClassCheck(object, InternalResourcePropertyListClass),
	)
}

// resourceManaged attributes are written only from typed fields.
var InternalResourceManaged = []string{
	"cn",
	"name",
	InternalResourceValueTypeReference,
	InternalResourceSharesValuesWith,
	InternalResourceAppliesTo,
	InternalResourceIsSecured,
	InternalResourceListMembers,
	InternalClaimPossible,
	InternalClaimRestricted,
	InternalClaimValueType,
	"nTSecurityDescriptor",
}

func InternalResourceRawChanges(changes []AttributeChange) error {
	for _, change := range changes {
		for _, managed := range InternalResourceManaged {
			if strings.EqualFold(change.Attribute, managed) {
				return ErrResourceProperty
			}
		}
	}
	return nil
}

func InternalResourceRawAttributes(attributes map[string][]RawValue) error {
	for name := range attributes {
		for _, managed := range InternalResourceManaged {
			if strings.EqualFold(name, managed) {
				return ErrResourceProperty
			}
		}
	}
	return nil
}

func InternalResourceProject(
	result ResourcePropertyMutationResult,
	err error,
) (ResourcePropertyMutationResult, error) {
	if result.Mutation.After != nil {
		value, decodeErr := InternalDecodeResourceProperty(*result.Mutation.After)
		value.ProtectedFromAccidentalDeletion = result.Protection.ProtectedFromAccidentalDeletion
		result.Property = &value
		err = errors.Join(err, decodeErr)
	}
	return result, err
}

func InternalResourceListProject(
	result ResourcePropertyListMutationResult,
	err error,
) (ResourcePropertyListMutationResult, error) {
	if result.Mutation.After != nil {
		value, decodeErr := InternalDecodeResourcePropertyList(*result.Mutation.After)
		value.ProtectedFromAccidentalDeletion = result.Protection.ProtectedFromAccidentalDeletion
		result.List = &value
		err = errors.Join(err, decodeErr)
	}
	return result, err
}

func InternalResourcePropertyUpdateChanges(
	request UpdateResourcePropertyRequest,
) ([]AttributeChange, error) {
	if request.Description != nil && request.ClearDescription {
		return nil, ErrResourceProperty
	}
	if request.SharesValuesWith != nil && request.ClearSharesValuesWith {
		return nil, ErrResourceProperty
	}
	if len(request.SuggestedValues) != 0 && request.ClearSuggestedValues {
		return nil, ErrResourceProperty
	}
	if len(request.AppliesToResourceTypes) != 0 && request.ClearAppliesToResourceTypes {
		return nil, ErrResourceProperty
	}
	if request.ReplaceAppliesToResourceTypes && request.ClearAppliesToResourceTypes {
		return nil, ErrResourceProperty
	}
	if err := InternalResourceRawChanges(request.Changes); err != nil {
		return nil, err
	}
	if err := InternalResourceAppliesToValid(request.AppliesToResourceTypes); err != nil {
		return nil, err
	}
	var changes []AttributeChange
	if request.DisplayName != nil {
		if *request.DisplayName == "" || !InternalValidDirectoryText(*request.DisplayName) {
			return nil, ErrInvalidObjectMutation
		}
		changes = append(
			changes,
			AttributeChange{
				Attribute: "displayName",
				Kind:      AttributeSet,
				Values:    []RawValue{NewRawValue([]byte(*request.DisplayName))},
			},
		)
	}
	if request.Description != nil {
		if !InternalValidDirectoryText(*request.Description) {
			return nil, ErrInvalidObjectMutation
		}
		changes = append(
			changes,
			AttributeChange{
				Attribute: "description",
				Kind:      AttributeSet,
				Values:    []RawValue{NewRawValue([]byte(*request.Description))},
			},
		)
	}
	if request.ClearDescription {
		changes = append(changes, AttributeChange{Attribute: "description", Kind: AttributeClear})
	}
	for _, flag := range []struct {
		InternalAttribute string
		InternalValue     *bool
	}{
		{"enabled", request.Enabled},
		{InternalResourceIsSecured, request.IsSecured},
		{InternalClaimRestricted, request.RestrictValues},
	} {
		if flag.InternalValue != nil {
			changes = append(
				changes,
				AttributeChange{
					Attribute: flag.InternalAttribute,
					Kind:      AttributeSet,
					Values:    []RawValue{InternalClaimBoolValue(*flag.InternalValue)},
				},
			)
		}
	}
	if request.ClearSharesValuesWith {
		changes = append(
			changes,
			AttributeChange{Attribute: InternalResourceSharesValuesWith, Kind: AttributeClear},
		)
	}
	if request.ClearSuggestedValues {
		changes = append(
			changes,
			AttributeChange{Attribute: InternalClaimPossible, Kind: AttributeClear},
		)
	}
	if request.ClearAppliesToResourceTypes {
		changes = append(
			changes,
			AttributeChange{Attribute: InternalResourceAppliesTo, Kind: AttributeClear},
		)
	}
	if len(request.AppliesToResourceTypes) != 0 {
		values := make([]RawValue, 0, len(request.AppliesToResourceTypes))
		for _, kind := range request.AppliesToResourceTypes {
			values = append(values, NewRawValue([]byte(kind)))
		}
		kind := AttributeAddValues
		if request.ReplaceAppliesToResourceTypes {
			kind = AttributeSet
		}
		changes = append(
			changes,
			AttributeChange{Attribute: InternalResourceAppliesTo, Kind: kind, Values: values},
		)
	}
	return append(changes, request.Changes...), nil
}
