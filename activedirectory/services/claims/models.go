// Package claims provides the claims SDK interface.
package claims

import (
	admodel "github.com/deploymenttheory/go-sdk-activedirectory/activedirectory/internal/model"
)

// ClaimBoolean is the SDK's ClaimBoolean.
const ClaimBoolean = admodel.ClaimBoolean

// ClaimFQBN is the SDK's ClaimFQBN.
const ClaimFQBN = admodel.ClaimFQBN

// ClaimInt64 is the SDK's ClaimInt64.
const ClaimInt64 = admodel.ClaimInt64

// ClaimOctetString is the SDK's ClaimOctetString.
const ClaimOctetString = admodel.ClaimOctetString

// ClaimSID is the SDK's ClaimSID.
const ClaimSID = admodel.ClaimSID

// ClaimSchemaObservation is the SDK's ClaimSchemaObservation.
type ClaimSchemaObservation = admodel.ClaimSchemaObservation

// ClaimSchemaRange is the SDK's ClaimSchemaRange.
type ClaimSchemaRange = admodel.ClaimSchemaRange

// ClaimSourceAttribute is the SDK's ClaimSourceAttribute.
const ClaimSourceAttribute = admodel.ClaimSourceAttribute

// ClaimSourceCertificate is the SDK's ClaimSourceCertificate.
const ClaimSourceCertificate = admodel.ClaimSourceCertificate

// ClaimSourceTransform is the SDK's ClaimSourceTransform.
const ClaimSourceTransform = admodel.ClaimSourceTransform

// ClaimSourceType is the SDK's ClaimSourceType.
type ClaimSourceType = admodel.ClaimSourceType

// ClaimString is the SDK's ClaimString.
const ClaimString = admodel.ClaimString

// ClaimSuggestedValue has exactly one typed value. FQBN, SID and OctetString
// suggestions use Text, matching the reference module's StringList mapping.
// Metadata is optional and retains omission separately from an empty string.
type ClaimSuggestedValue = admodel.ClaimSuggestedValue

// ClaimSuggestedValues is the SDK's ClaimSuggestedValues.
type ClaimSuggestedValues = admodel.ClaimSuggestedValues

// ClaimTransformDirection names the trust attribute a link is written to.
//
// The reference exposes TrustRole instead. Which role maps to which direction
// has NOT been qualified against the reference — it needs a second forest with
// a trust, which the current lab does not have — and getting it backwards would
// apply a policy to the wrong direction of claims flow. The direction is
// therefore stated by the caller rather than derived from a role, so this SDK
// never guesses it. A TrustRole convenience can be added once observed.
type ClaimTransformDirection = admodel.ClaimTransformDirection

// ClaimTransformEgress writes msDS-EgressClaimsTransformationPolicy:
// claims leaving this forest across the trust.
const ClaimTransformEgress = admodel.ClaimTransformEgress

// ClaimTransformIngress writes msDS-IngressClaimsTransformationPolicy:
// claims entering this forest across the trust.
const ClaimTransformIngress = admodel.ClaimTransformIngress

// ClaimTransformLinkRequest links or unlinks one policy on one trust.
type ClaimTransformLinkRequest = admodel.ClaimTransformLinkRequest

// ClaimTransformLinkResult is the SDK's ClaimTransformLinkResult.
type ClaimTransformLinkResult = admodel.ClaimTransformLinkResult

// ClaimTransformPoliciesResult is the SDK's ClaimTransformPoliciesResult.
type ClaimTransformPoliciesResult = admodel.ClaimTransformPoliciesResult

// ClaimTransformPolicy is one msDS-ClaimsTransformationPolicyType.
type ClaimTransformPolicy = admodel.ClaimTransformPolicy

// ClaimTransformPolicyMutationResult is the SDK's ClaimTransformPolicyMutationResult.
type ClaimTransformPolicyMutationResult = admodel.ClaimTransformPolicyMutationResult

// ClaimTransformPolicyReadOptions is the SDK's ClaimTransformPolicyReadOptions.
type ClaimTransformPolicyReadOptions = admodel.ClaimTransformPolicyReadOptions

// ClaimTransformPolicyResult is the SDK's ClaimTransformPolicyResult.
type ClaimTransformPolicyResult = admodel.ClaimTransformPolicyResult

// ClaimTransformRuleSet selects which rules a policy stores. Exactly one form
// applies; the zero value writes nothing and leaves an existing policy alone.
type ClaimTransformRuleSet = admodel.ClaimTransformRuleSet

// ClaimType is the SDK's ClaimType.
type ClaimType = admodel.ClaimType

// ClaimTypeMutationResult is the SDK's ClaimTypeMutationResult.
type ClaimTypeMutationResult = admodel.ClaimTypeMutationResult

// ClaimTypeReadOptions is the SDK's ClaimTypeReadOptions.
type ClaimTypeReadOptions = admodel.ClaimTypeReadOptions

// ClaimTypeResult is the SDK's ClaimTypeResult.
type ClaimTypeResult = admodel.ClaimTypeResult

// ClaimTypeSource is the SDK's ClaimTypeSource.
type ClaimTypeSource = admodel.ClaimTypeSource

// ClaimTypesResult is the SDK's ClaimTypesResult.
type ClaimTypesResult = admodel.ClaimTypesResult

// ClaimUInt64 is the SDK's ClaimUInt64.
const ClaimUInt64 = admodel.ClaimUInt64

// ClaimValueType is the SDK's ClaimValueType.
type ClaimValueType = admodel.ClaimValueType

// CreateClaimTransformPolicyRequest creates one policy under the configuration
// partition's Claims Transformation Policies container.
type CreateClaimTransformPolicyRequest = admodel.CreateClaimTransformPolicyRequest

// CreateClaimTypeRequest creates one claim type under the configuration
// partition's Claim Types container.
type CreateClaimTypeRequest = admodel.CreateClaimTypeRequest

// DeleteClaimTypeRequest removes one claim type.
type DeleteClaimTypeRequest = admodel.DeleteClaimTypeRequest

// ErrClaimTransformLink is the SDK's ErrClaimTransformLink.
var ErrClaimTransformLink = admodel.ErrClaimTransformLink

// ErrClaimTransformPolicy is the SDK's ErrClaimTransformPolicy.
var ErrClaimTransformPolicy = admodel.ErrClaimTransformPolicy

// ErrClaimTransformRule is the SDK's ErrClaimTransformRule.
var ErrClaimTransformRule = admodel.ErrClaimTransformRule

// ErrClaimType is the SDK's ErrClaimType.
var ErrClaimType = admodel.ErrClaimType

// ErrClaimTypeReferenced is the SDK's ErrClaimTypeReferenced.
var ErrClaimTypeReferenced = admodel.ErrClaimTypeReferenced

// ErrClaimTypeSchema is the SDK's ErrClaimTypeSchema.
var ErrClaimTypeSchema = admodel.ErrClaimTypeSchema

// SchemaReference selects exactly one schema object by the shared DN/GUID
// Identity or its explicit LDAP display name. It never guesses from a string.
type SchemaReference = admodel.SchemaReference

// UpdateClaimTransformPolicyRequest changes one policy. Nil and zero fields are
// left alone; ClearRules removes the rules attribute and conflicts with Rules.
type UpdateClaimTransformPolicyRequest = admodel.UpdateClaimTransformPolicyRequest

// UpdateClaimTypeRequest changes one claim type. Nil fields are left alone;
// the explicit Clear flags request removal and conflict with a stated value.
type UpdateClaimTypeRequest = admodel.UpdateClaimTypeRequest
