// Package password_policies provides the password_policies SDK interface.
package password_policies

import (
	admodel "github.com/deploymenttheory/go-sdk-activedirectory/activedirectory/internal/model"
)

// CreateFineGrainedPasswordPolicyRequest is the SDK's CreateFineGrainedPasswordPolicyRequest.
type CreateFineGrainedPasswordPolicyRequest = admodel.CreateFineGrainedPasswordPolicyRequest

// ErrFineGrainedPolicyChanged is the SDK's ErrFineGrainedPolicyChanged.
var ErrFineGrainedPolicyChanged = admodel.ErrFineGrainedPolicyChanged

// ErrFineGrainedPolicyLimit is the SDK's ErrFineGrainedPolicyLimit.
var ErrFineGrainedPolicyLimit = admodel.ErrFineGrainedPolicyLimit

// ErrFineGrainedPolicySubject is the SDK's ErrFineGrainedPolicySubject.
var ErrFineGrainedPolicySubject = admodel.ErrFineGrainedPolicySubject

// ErrFineGrainedPolicyTarget is the SDK's ErrFineGrainedPolicyTarget.
var ErrFineGrainedPolicyTarget = admodel.ErrFineGrainedPolicyTarget

// ErrInvalidFineGrainedPolicy is the SDK's ErrInvalidFineGrainedPolicy.
var ErrInvalidFineGrainedPolicy = admodel.ErrInvalidFineGrainedPolicy

// FineGrainedPasswordPoliciesResult is the SDK's FineGrainedPasswordPoliciesResult.
type FineGrainedPasswordPoliciesResult = admodel.FineGrainedPasswordPoliciesResult

// FineGrainedPasswordPolicy is the SDK's FineGrainedPasswordPolicy.
type FineGrainedPasswordPolicy = admodel.FineGrainedPasswordPolicy

// FineGrainedPasswordPolicyMutationResult is the SDK's FineGrainedPasswordPolicyMutationResult.
type FineGrainedPasswordPolicyMutationResult = admodel.FineGrainedPasswordPolicyMutationResult

// FineGrainedPasswordPolicyResult is the SDK's FineGrainedPasswordPolicyResult.
type FineGrainedPasswordPolicyResult = admodel.FineGrainedPasswordPolicyResult

// FineGrainedPasswordPolicySettings is a patch: nil omits a setting. Creation
// requires all ten settings explicitly. MaxPasswordAge zero requests PolicyNever;
// other intervals preserve zero. All values retain exact 100ns precision.
type FineGrainedPasswordPolicySettings = admodel.FineGrainedPasswordPolicySettings

// FineGrainedPolicySubject is the SDK's FineGrainedPolicySubject.
type FineGrainedPolicySubject = admodel.FineGrainedPolicySubject

// FineGrainedPolicySubjectInput is the SDK's FineGrainedPolicySubjectInput.
type FineGrainedPolicySubjectInput = admodel.FineGrainedPolicySubjectInput

// FineGrainedPolicySubjectRange is the SDK's FineGrainedPolicySubjectRange.
type FineGrainedPolicySubjectRange = admodel.FineGrainedPolicySubjectRange

// FineGrainedPolicySubjectsMutationResult is the SDK's FineGrainedPolicySubjectsMutationResult.
type FineGrainedPolicySubjectsMutationResult = admodel.FineGrainedPolicySubjectsMutationResult

// FineGrainedPolicySubjectsOptions is the SDK's FineGrainedPolicySubjectsOptions.
type FineGrainedPolicySubjectsOptions = admodel.FineGrainedPolicySubjectsOptions

// FineGrainedPolicySubjectsRequest is the SDK's FineGrainedPolicySubjectsRequest.
type FineGrainedPolicySubjectsRequest = admodel.FineGrainedPolicySubjectsRequest

// Complete means all contiguous ranges and subject resolutions completed at
// one observed PSO GUID/USN. It does not prove ACL visibility or a transaction.
// AttributeReturned distinguishes omission from a returned empty attribute.
type FineGrainedPolicySubjectsResult = admodel.FineGrainedPolicySubjectsResult

// UpdateFineGrainedPasswordPolicyRequest is the SDK's UpdateFineGrainedPasswordPolicyRequest.
type UpdateFineGrainedPasswordPolicyRequest = admodel.UpdateFineGrainedPasswordPolicyRequest

// UserResultantPasswordPolicyResult reports the server's constructed
// msDS-ResultantPSO value. NotReturned is an observation: it does not prove the
// default domain policy applies when ACLs hide an attribute. No local policy
// precedence or group expansion substitutes for the constructed value.
type UserResultantPasswordPolicyResult = admodel.UserResultantPasswordPolicyResult
