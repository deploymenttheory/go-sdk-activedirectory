// Package authentication_silos provides the authentication_silos SDK interface.
package authentication_silos

import (
	admodel "github.com/deploymenttheory/go-sdk-activedirectory/activedirectory/internal/model"
)

// AccountAuthenticationPolicySiloResult is the SDK's AccountAuthenticationPolicySiloResult.
type AccountAuthenticationPolicySiloResult = admodel.AccountAuthenticationPolicySiloResult

// AuthenticationPolicySilo is the SDK's AuthenticationPolicySilo.
type AuthenticationPolicySilo = admodel.AuthenticationPolicySilo

// AuthenticationPolicySiloAccessRequest is the SDK's AuthenticationPolicySiloAccessRequest.
type AuthenticationPolicySiloAccessRequest = admodel.AuthenticationPolicySiloAccessRequest

// AuthenticationPolicySiloAccessResult is the SDK's AuthenticationPolicySiloAccessResult.
type AuthenticationPolicySiloAccessResult = admodel.AuthenticationPolicySiloAccessResult

// AuthenticationPolicySiloMutationResult is the SDK's AuthenticationPolicySiloMutationResult.
type AuthenticationPolicySiloMutationResult = admodel.AuthenticationPolicySiloMutationResult

// AuthenticationPolicySiloProperties is the SDK's AuthenticationPolicySiloProperties.
type AuthenticationPolicySiloProperties = admodel.AuthenticationPolicySiloProperties

// AuthenticationPolicySiloReadOptions is the SDK's AuthenticationPolicySiloReadOptions.
type AuthenticationPolicySiloReadOptions = admodel.AuthenticationPolicySiloReadOptions

// AuthenticationPolicySiloResult is the SDK's AuthenticationPolicySiloResult.
type AuthenticationPolicySiloResult = admodel.AuthenticationPolicySiloResult

// AuthenticationPolicySiloSearchOptions is the SDK's AuthenticationPolicySiloSearchOptions.
type AuthenticationPolicySiloSearchOptions = admodel.AuthenticationPolicySiloSearchOptions

// AuthenticationPolicySilosResult is the SDK's AuthenticationPolicySilosResult.
type AuthenticationPolicySilosResult = admodel.AuthenticationPolicySilosResult

// AuthenticationSiloLinks describes one linked attribute, not effective access.
// Complete means all server-visible ranges were read without an observed change.
// AttributeReturned=false never proves that ACL-hidden links do not exist.
type AuthenticationSiloLinks = admodel.AuthenticationSiloLinks

// CreateAuthenticationPolicySiloRequest is the SDK's CreateAuthenticationPolicySiloRequest.
type CreateAuthenticationPolicySiloRequest = admodel.CreateAuthenticationPolicySiloRequest

// DeleteAuthenticationPolicySiloRequest is the SDK's DeleteAuthenticationPolicySiloRequest.
type DeleteAuthenticationPolicySiloRequest = admodel.DeleteAuthenticationPolicySiloRequest

// ErrAuthenticationSiloChanged is the SDK's ErrAuthenticationSiloChanged.
var ErrAuthenticationSiloChanged = admodel.ErrAuthenticationSiloChanged

// ErrAuthenticationSiloGrant is the SDK's ErrAuthenticationSiloGrant.
var ErrAuthenticationSiloGrant = admodel.ErrAuthenticationSiloGrant

// ErrInvalidAuthenticationSilo is the SDK's ErrInvalidAuthenticationSilo.
var ErrInvalidAuthenticationSilo = admodel.ErrInvalidAuthenticationSilo

// ErrNotAuthenticationSilo is the SDK's ErrNotAuthenticationSilo.
var ErrNotAuthenticationSilo = admodel.ErrNotAuthenticationSilo

// The two account links are independently omitted, assigned, or explicitly
// cleared. A combined change is one atomic LDAP Modify on that account.
type SetAccountAuthenticationPolicySiloRequest = admodel.SetAccountAuthenticationPolicySiloRequest

// UpdateAuthenticationPolicySiloRequest is the SDK's UpdateAuthenticationPolicySiloRequest.
type UpdateAuthenticationPolicySiloRequest = admodel.UpdateAuthenticationPolicySiloRequest
