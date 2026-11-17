// Package central_access provides the central_access SDK interface.
package central_access

import (
	admodel "github.com/deploymenttheory/go-sdk-activedirectory/activedirectory/internal/model"
)

// CentralAccessMemberInput is the SDK's CentralAccessMemberInput.
type CentralAccessMemberInput = admodel.CentralAccessMemberInput

// CentralAccessMutationResult is the SDK's CentralAccessMutationResult.
type CentralAccessMutationResult = admodel.CentralAccessMutationResult

// CentralAccessPoliciesResult is the SDK's CentralAccessPoliciesResult.
type CentralAccessPoliciesResult = admodel.CentralAccessPoliciesResult

// CentralAccessPolicy is the SDK's CentralAccessPolicy.
type CentralAccessPolicy = admodel.CentralAccessPolicy

// CentralAccessPolicyMemberLimit is the SDK's CentralAccessPolicyMemberLimit.
const CentralAccessPolicyMemberLimit = admodel.CentralAccessPolicyMemberLimit

// CentralAccessPolicyMembersRequest is the SDK's CentralAccessPolicyMembersRequest.
type CentralAccessPolicyMembersRequest = admodel.CentralAccessPolicyMembersRequest

// CentralAccessPolicyMembersResult is the SDK's CentralAccessPolicyMembersResult.
type CentralAccessPolicyMembersResult = admodel.CentralAccessPolicyMembersResult

// CentralAccessPolicyResult is the SDK's CentralAccessPolicyResult.
type CentralAccessPolicyResult = admodel.CentralAccessPolicyResult

// CentralAccessReadOptions is the SDK's CentralAccessReadOptions.
type CentralAccessReadOptions = admodel.CentralAccessReadOptions

// CentralAccessReference is the SDK's CentralAccessReference.
type CentralAccessReference = admodel.CentralAccessReference

// CentralAccessReferenceLimits are per-source budgets. Zero selects a default;
// positive values override that default (they are not capped at the default).
type CentralAccessReferenceLimits = admodel.CentralAccessReferenceLimits

// CentralAccessReferenceRange is the SDK's CentralAccessReferenceRange.
type CentralAccessReferenceRange = admodel.CentralAccessReferenceRange

// Complete means contiguous retrieval at one observed source GUID/USN. It does
// not prove ACL visibility or a snapshot across the referenced objects.
type CentralAccessReferencesResult = admodel.CentralAccessReferencesResult

// Permission descriptors and resource expressions are separate Unicode LDAP
// strings. They are not nTSecurityDescriptor or binary authentication policies.
type CentralAccessRule = admodel.CentralAccessRule

// CentralAccessRuleResult is the SDK's CentralAccessRuleResult.
type CentralAccessRuleResult = admodel.CentralAccessRuleResult

// CentralAccessRulesResult is the SDK's CentralAccessRulesResult.
type CentralAccessRulesResult = admodel.CentralAccessRulesResult

// CreateCentralAccessPolicyRequest is the SDK's CreateCentralAccessPolicyRequest.
type CreateCentralAccessPolicyRequest = admodel.CreateCentralAccessPolicyRequest

// CreateCentralAccessRuleRequest is the SDK's CreateCentralAccessRuleRequest.
type CreateCentralAccessRuleRequest = admodel.CreateCentralAccessRuleRequest

// DefaultCentralAccessRuleACL is the SDK's DefaultCentralAccessRuleACL.
const DefaultCentralAccessRuleACL = admodel.DefaultCentralAccessRuleACL

// ErrCentralAccess is the SDK's ErrCentralAccess.
var ErrCentralAccess = admodel.ErrCentralAccess

// ErrCentralAccessMemberLimit is the SDK's ErrCentralAccessMemberLimit.
var ErrCentralAccessMemberLimit = admodel.ErrCentralAccessMemberLimit

// ErrCentralAccessReferences is the SDK's ErrCentralAccessReferences.
var ErrCentralAccessReferences = admodel.ErrCentralAccessReferences

// UpdateCentralAccessPolicyRequest is the SDK's UpdateCentralAccessPolicyRequest.
type UpdateCentralAccessPolicyRequest = admodel.UpdateCentralAccessPolicyRequest

// UpdateCentralAccessRuleRequest is the SDK's UpdateCentralAccessRuleRequest.
type UpdateCentralAccessRuleRequest = admodel.UpdateCentralAccessRuleRequest
