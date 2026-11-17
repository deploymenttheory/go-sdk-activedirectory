package model

import (
	"errors"
	"strings"
)

// Claim type creation and update settle the value type from the source rather
// than accepting it directly, matching the reference parameter sets: ValueType
// is stated only for a transform-policy source, and no update can change the
// value type an existing claim already stores.

// CreateClaimTypeRequest creates one claim type under the configuration
// partition's Claim Types container.
type CreateClaimTypeRequest struct {
	// DisplayName is required. ID is the claim's directory name; when nil a
	// conforming ad://ext/ identifier is generated and reported back in the
	// result, including when the write is rejected or uncertain.
	DisplayName string
	ID          *string
	Description *string
	// Source selects exactly one of the attribute, certificate OID or
	// transform-policy forms. It settles the stored value type.
	Source                                  ClaimTypeSource
	AppliesToClasses                        []SchemaReference
	Enabled, IsSingleValued, RestrictValues *bool
	SuggestedValues                         []ClaimSuggestedValue
	ProtectedFromAccidentalDeletion         *bool
	// Attributes carries additional raw attributes. Managed claim attributes
	// are rejected rather than merged.
	Attributes map[string][]RawValue
	Options    ObjectMutationOptions
}

// UpdateClaimTypeRequest changes one claim type. Nil fields are left alone;
// the explicit Clear flags request removal and conflict with a stated value.
type UpdateClaimTypeRequest struct {
	Identity                 Identity
	DisplayName, Description *string
	ClearDescription         bool
	// Source re-points the claim. The new source must settle the same value
	// type the claim already stores; the reference module cannot change it.
	Source *ClaimTypeSource
	// AppliesToClasses replaces the stored class list when ReplaceAppliesToClasses
	// is set. Without it a non-empty list is added and ClearAppliesToClasses
	// removes the attribute.
	AppliesToClasses                        []SchemaReference
	ReplaceAppliesToClasses                 bool
	ClearAppliesToClasses                   bool
	Enabled, IsSingleValued, RestrictValues *bool
	SuggestedValues                         []ClaimSuggestedValue
	ClearSuggestedValues                    bool
	ProtectedFromAccidentalDeletion         *bool
	Changes                                 []AttributeChange
	Options                                 ObjectMutationOptions
}

// DeleteClaimTypeRequest removes one claim type.
type DeleteClaimTypeRequest struct {
	Identity Identity
	// Force deletes a claim type that resource properties still reference.
	// Without it an observed reference is reported as ErrClaimTypeReferenced
	// and no delete is submitted.
	Force      bool
	References CentralAccessReferenceLimits
	Options    ObjectMutationOptions
}

type ClaimTypeMutationResult struct {
	Mutation   ObjectMutationResult
	Protection OUProtectionResult
	Claim      *ClaimType
	// Schema retains every schema object read while settling the source and
	// applies-to classes, including objects that were then rejected.
	Schema []ClaimSchemaObservation
	// GeneratedID is retained even when the create is rejected or uncertain,
	// so a caller can find an object a retry must not duplicate.
	GeneratedID *string
}

// claimManagedAttributes are written only from typed request fields. Raw
// changes naming them are rejected so a caller cannot bypass source and value
// type validation.
var InternalClaimManagedAttributes = []string{
	"cn",
	"name",
	InternalClaimSourceAttribute,
	InternalClaimSourceOID,
	InternalClaimSourceKind,
	InternalClaimValueType,
	InternalClaimSingle,
	InternalClaimRestricted,
	InternalClaimPossible,
	InternalClaimApplies,
	InternalClaimBacklinks,
	"nTSecurityDescriptor",
}

func InternalClaimRawChanges(changes []AttributeChange) error {
	for _, change := range changes {
		for _, managed := range InternalClaimManagedAttributes {
			if strings.EqualFold(change.Attribute, managed) {
				return ErrClaimType
			}
		}
	}
	return nil
}

func InternalClaimRawAttributes(attributes map[string][]RawValue) error {
	for name := range attributes {
		for _, managed := range InternalClaimManagedAttributes {
			if strings.EqualFold(name, managed) {
				return ErrClaimType
			}
		}
	}
	return nil
}

func InternalClaimBoolValue(value bool) RawValue {
	return NewRawValue([]byte(InternalStrconvClaimBool(value)))
}

// claimSourceAttributes renders the stored form of a settled source.
func InternalClaimSourceAttributes(
	source ClaimTypeSource,
	resolution InternalClaimSchemaResolution,
) map[string][]RawValue {
	attributes := map[string][]RawValue{
		InternalClaimSourceKind: {NewRawValue([]byte(source.Type))},
		InternalClaimValueType: {
			NewRawValue([]byte(InternalClaimValueTypeText(resolution.ValueType))),
		},
	}
	switch source.Type {
	case ClaimSourceAttribute:
		attributes[InternalClaimSourceAttribute] = []RawValue{
			NewRawValue([]byte(resolution.SourceAttributeDN)),
		}
	case ClaimSourceCertificate:
		attributes[InternalClaimSourceOID] = []RawValue{NewRawValue([]byte(source.OID))}
	}
	return attributes
}

func InternalClaimClassValues(dns []string) []RawValue {
	values := make([]RawValue, 0, len(dns))
	for _, dn := range dns {
		values = append(values, NewRawValue([]byte(dn)))
	}
	return values
}

// claimSuggestedValueAttribute encodes suggested values for the settled value
// type. RestrictValues is the directory's own gate and is not inferred here.
func InternalClaimSuggestedValueAttribute(
	values []ClaimSuggestedValue,
	valueType ClaimValueType,
) ([]RawValue, error) {
	if len(values) == 0 {
		return nil, nil
	}
	text, err := InternalEncodeClaimValues(values, valueType)
	if err != nil {
		return nil, err
	}
	return []RawValue{NewRawValue([]byte(text))}, nil
}

func InternalClaimProject(
	result ClaimTypeMutationResult,
	err error,
) (ClaimTypeMutationResult, error) {
	if result.Mutation.After != nil {
		value, decodeErr := InternalDecodeClaimType(*result.Mutation.After)
		value.ProtectedFromAccidentalDeletion = result.Protection.ProtectedFromAccidentalDeletion
		result.Claim = &value
		err = errors.Join(err, decodeErr)
	}
	return result, err
}

// claimUpdateChanges renders every typed field that does not need the schema.
func InternalClaimUpdateChanges(request UpdateClaimTypeRequest) ([]AttributeChange, error) {
	if request.Description != nil && request.ClearDescription {
		return nil, ErrClaimType
	}
	if len(request.SuggestedValues) != 0 && request.ClearSuggestedValues {
		return nil, ErrClaimType
	}
	if len(request.AppliesToClasses) != 0 && request.ClearAppliesToClasses {
		return nil, ErrClaimType
	}
	if request.ReplaceAppliesToClasses && request.ClearAppliesToClasses {
		return nil, ErrClaimType
	}
	if err := InternalClaimRawChanges(request.Changes); err != nil {
		return nil, err
	}
	var changes []AttributeChange
	if request.DisplayName != nil {
		if !InternalValidDirectoryText(*request.DisplayName) || *request.DisplayName == "" {
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
		{InternalClaimSingle, request.IsSingleValued},
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
	if request.ClearSuggestedValues {
		changes = append(
			changes,
			AttributeChange{Attribute: InternalClaimPossible, Kind: AttributeClear},
		)
	}
	if request.ClearAppliesToClasses {
		changes = append(
			changes,
			AttributeChange{Attribute: InternalClaimApplies, Kind: AttributeClear},
		)
	}
	return append(changes, request.Changes...), nil
}

// claimStaleSourceAttributes names the source attributes a different form owns.
func InternalClaimStaleSourceAttributes(kind ClaimSourceType) []string {
	switch kind {
	case ClaimSourceAttribute:
		return []string{InternalClaimSourceOID}
	case ClaimSourceCertificate:
		return []string{InternalClaimSourceAttribute}
	default:
		return []string{InternalClaimSourceAttribute, InternalClaimSourceOID}
	}
}
