// Package authentication_policies provides the authentication_policies SDK interface.
package authentication_policies

import (
	admodel "github.com/deploymenttheory/go-sdk-activedirectory/activedirectory/internal/model"
)

// AccountAuthenticationPolicyResult is the SDK's AccountAuthenticationPolicyResult.
type AccountAuthenticationPolicyResult = admodel.AccountAuthenticationPolicyResult

// AuthenticationPoliciesResult is the SDK's AuthenticationPoliciesResult.
type AuthenticationPoliciesResult = admodel.AuthenticationPoliciesResult

// AuthenticationPolicy is the SDK's AuthenticationPolicy.
type AuthenticationPolicy = admodel.AuthenticationPolicy

// Protection reuses the shared ACL workflow and its per-object outcomes.
// Attribute and parent/object protection writes are separate requests, never a
// transaction. An earlier accepted request is retained after any later error.
type AuthenticationPolicyMutationResult = admodel.AuthenticationPolicyMutationResult

// AuthenticationPolicyProperties is an explicit patch: nil omits a property,
// false/zero are values, and AttributeClear clears one. Lifetimes are positive
// 100ns counts, with zero meaning no policy override, not an infinite duration.
// Descriptor strings are SDDL; conditions.Compile builds them headlessly.
type AuthenticationPolicyProperties = admodel.AuthenticationPolicyProperties

// AuthenticationPolicyResult is the SDK's AuthenticationPolicyResult.
type AuthenticationPolicyResult = admodel.AuthenticationPolicyResult

// CreateAuthenticationPolicyRequest is the SDK's CreateAuthenticationPolicyRequest.
type CreateAuthenticationPolicyRequest = admodel.CreateAuthenticationPolicyRequest

// DeleteAuthenticationPolicyRequest is the SDK's DeleteAuthenticationPolicyRequest.
type DeleteAuthenticationPolicyRequest = admodel.DeleteAuthenticationPolicyRequest

// ErrAuthenticationPolicyDescriptor is the SDK's ErrAuthenticationPolicyDescriptor.
var ErrAuthenticationPolicyDescriptor = admodel.ErrAuthenticationPolicyDescriptor

// ErrAuthenticationPolicyPrerequisite is the SDK's ErrAuthenticationPolicyPrerequisite.
var ErrAuthenticationPolicyPrerequisite = admodel.ErrAuthenticationPolicyPrerequisite

// ErrInvalidAuthenticationPolicy is the SDK's ErrInvalidAuthenticationPolicy.
var ErrInvalidAuthenticationPolicy = admodel.ErrInvalidAuthenticationPolicy

// ErrNotAuthenticationPolicy is the SDK's ErrNotAuthenticationPolicy.
var ErrNotAuthenticationPolicy = admodel.ErrNotAuthenticationPolicy

// SetAccountAuthenticationPolicyRequest assigns Policy or explicitly clears
// the direct policy link. Exactly one of Policy/Clear must be supplied. Account
// identities use the existing DN/GUID/SID/SAM rules; Policy accepts DN/GUID.
// Silo membership/assignment is not changed and may override this direct link
// during authentication. This result never claims an effective resultant policy.
type SetAccountAuthenticationPolicyRequest = admodel.SetAccountAuthenticationPolicyRequest

// StrongNTLMDisabled is the SDK's StrongNTLMDisabled.
const StrongNTLMDisabled = admodel.StrongNTLMDisabled

// StrongNTLMOptional is the SDK's StrongNTLMOptional.
const StrongNTLMOptional = admodel.StrongNTLMOptional

// StrongNTLMPolicy preserves the stored enum, including unknown returned values.
// Rolling NTLM secrets are deprecated by Microsoft; this API never enables the
// feature implicitly and makes no claim that current clients implement it.
type StrongNTLMPolicy = admodel.StrongNTLMPolicy

// StrongNTLMRequired is the SDK's StrongNTLMRequired.
const StrongNTLMRequired = admodel.StrongNTLMRequired

// UpdateAuthenticationPolicyRequest is the SDK's UpdateAuthenticationPolicyRequest.
type UpdateAuthenticationPolicyRequest = admodel.UpdateAuthenticationPolicyRequest
