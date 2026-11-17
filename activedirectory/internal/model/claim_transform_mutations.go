package model

import (
	"errors"
	"strings"
)

// CreateClaimTransformPolicyRequest creates one policy under the configuration
// partition's Claims Transformation Policies container.
type CreateClaimTransformPolicyRequest struct {
	Name        string
	Description *string
	// Rules selects the stored rule form. The zero value creates a policy with
	// no rules rather than defaulting to allow or deny.
	Rules                           ClaimTransformRuleSet
	ProtectedFromAccidentalDeletion *bool
	// Attributes carries additional raw attributes. Managed attributes are
	// rejected rather than merged.
	Attributes map[string][]RawValue
	Options    ObjectMutationOptions
}

// UpdateClaimTransformPolicyRequest changes one policy. Nil and zero fields are
// left alone; ClearRules removes the rules attribute and conflicts with Rules.
type UpdateClaimTransformPolicyRequest struct {
	Identity                        Identity
	Description                     *string
	ClearDescription                bool
	Rules                           ClaimTransformRuleSet
	ClearRules                      bool
	ProtectedFromAccidentalDeletion *bool
	Changes                         []AttributeChange
	Options                         ObjectMutationOptions
}

type ClaimTransformPolicyMutationResult struct {
	Mutation   ObjectMutationResult
	Protection OUProtectionResult
	Policy     *ClaimTransformPolicy
}

// claimTransformManaged attributes are written only from typed fields. A raw
// change naming one would bypass rule validation and the CDATA envelope.
var InternalClaimTransformManaged = []string{
	"cn",
	"name",
	InternalClaimTransformRules,
	InternalClaimTransformCompiled,
	"nTSecurityDescriptor",
}

func InternalClaimTransformRawChanges(changes []AttributeChange) error {
	for _, change := range changes {
		for _, managed := range InternalClaimTransformManaged {
			if strings.EqualFold(change.Attribute, managed) {
				return ErrClaimTransformPolicy
			}
		}
	}
	return nil
}

func InternalClaimTransformRawAttributes(attributes map[string][]RawValue) error {
	for name := range attributes {
		for _, managed := range InternalClaimTransformManaged {
			if strings.EqualFold(name, managed) {
				return ErrClaimTransformPolicy
			}
		}
	}
	return nil
}

func InternalClaimTransformProject(
	result ClaimTransformPolicyMutationResult,
	err error,
) (ClaimTransformPolicyMutationResult, error) {
	if result.Mutation.After != nil {
		value, decodeErr := InternalDecodeClaimTransformPolicy(*result.Mutation.After)
		value.ProtectedFromAccidentalDeletion = result.Protection.ProtectedFromAccidentalDeletion
		result.Policy = &value
		err = errors.Join(err, decodeErr)
	}
	return result, err
}

func InternalClaimTransformUpdateChanges(
	request UpdateClaimTransformPolicyRequest,
) ([]AttributeChange, error) {
	if request.Description != nil && request.ClearDescription {
		return nil, ErrClaimTransformPolicy
	}
	if !InternalClaimTransformRuleSetEmpty(request.Rules) && request.ClearRules {
		return nil, ErrClaimTransformPolicy
	}
	if err := InternalClaimTransformRawChanges(request.Changes); err != nil {
		return nil, err
	}
	var changes []AttributeChange
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
	stored, present, err := InternalClaimTransformRuleSetRender(request.Rules)
	if err != nil {
		return nil, err
	}
	if present {
		changes = append(
			changes,
			AttributeChange{
				Attribute: InternalClaimTransformRules,
				Kind:      AttributeSet,
				Values:    []RawValue{NewRawValue([]byte(stored))},
			},
		)
	}
	if request.ClearRules {
		changes = append(
			changes,
			AttributeChange{Attribute: InternalClaimTransformRules, Kind: AttributeClear},
		)
	}
	return append(changes, request.Changes...), nil
}

// ClaimTransformDirection names the trust attribute a link is written to.
//
// The reference exposes TrustRole instead. Which role maps to which direction
// has NOT been qualified against the reference — it needs a second forest with
// a trust, which the current lab does not have — and getting it backwards would
// apply a policy to the wrong direction of claims flow. The direction is
// therefore stated by the caller rather than derived from a role, so this SDK
// never guesses it. A TrustRole convenience can be added once observed.
type ClaimTransformDirection uint8

const (
	// ClaimTransformEgress writes msDS-EgressClaimsTransformationPolicy:
	// claims leaving this forest across the trust.
	ClaimTransformEgress ClaimTransformDirection = iota + 1
	// ClaimTransformIngress writes msDS-IngressClaimsTransformationPolicy:
	// claims entering this forest across the trust.
	ClaimTransformIngress
)

const (
	InternalClaimTransformEgressAttribute  = "msDS-EgressClaimsTransformationPolicy"
	InternalClaimTransformIngressAttribute = "msDS-IngressClaimsTransformationPolicy"
)

func InternalClaimTransformDirectionAttribute(d ClaimTransformDirection) (string, error) {
	switch d {
	case ClaimTransformEgress:
		return InternalClaimTransformEgressAttribute, nil
	case ClaimTransformIngress:
		return InternalClaimTransformIngressAttribute, nil
	default:
		return "", ErrClaimTransformLink
	}
}

// ClaimTransformLinkRequest links or unlinks one policy on one trust.
type ClaimTransformLinkRequest struct {
	// Trust identifies a trustedDomain object. Its class and partition are
	// verified before any write.
	Trust Identity
	// Policy is the transformation policy to link. It is resolved and verified
	// to be a policy in the Claims Transformation Policies container, so a
	// link can never point at an arbitrary object. Ignored when clearing.
	Policy    Identity
	Direction ClaimTransformDirection
	Options   ObjectMutationOptions
}

type ClaimTransformLinkResult struct {
	Mutation ObjectMutationResult
	// PolicyObservation is the resolved policy the link was pointed at, or the
	// candidates seen while resolving it when that failed.
	PolicyObservation IdentityResult
	Attribute         string
}
