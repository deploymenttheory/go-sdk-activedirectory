// Package users provides the users SDK interface.
package users

import (
	admodel "github.com/deploymenttheory/go-sdk-activedirectory/activedirectory/internal/model"
)

// CreateUserRequest uses the configured Users container when Parent is omitted.
// Class defaults to user;
// inetOrgPerson is also supported when installed in the selected schema.
// InitialPassword is caller-owned UTF-8 and follows PasswordResetRequest's
// lifetime rules. Nil omits password setup; an explicit empty slice does not.
type CreateUserRequest = admodel.CreateUserRequest

// DeleteUserRequest is the SDK's DeleteUserRequest.
type DeleteUserRequest = admodel.DeleteUserRequest

// ErrInvalidUser is the SDK's ErrInvalidUser.
var ErrInvalidUser = admodel.ErrInvalidUser

// ErrNotUser is the SDK's ErrNotUser.
var ErrNotUser = admodel.ErrNotUser

// ErrUserCapability is the SDK's ErrUserCapability.
var ErrUserCapability = admodel.ErrUserCapability

// ErrUserCreationIncomplete is the SDK's ErrUserCreationIncomplete.
var ErrUserCreationIncomplete = admodel.ErrUserCreationIncomplete

// UpdateUserRequest is the SDK's UpdateUserRequest.
type UpdateUserRequest = admodel.UpdateUserRequest

// User is the SDK's User.
type User = admodel.User

// UserCreationResult preserves independent stage outcomes. Nil Password/Enable
// means that stage was not entered. Complete means all requested stages and
// observations completed, not a transaction or proof of successful logon.
// An accepted Add is never automatically deleted when a later stage fails.
type UserCreationResult = admodel.UserCreationResult

// UserMutationResult is the SDK's UserMutationResult.
type UserMutationResult = admodel.UserMutationResult

// UserProperties contains optional typed properties. Nil omits an update;
// non-nil text (including empty text) is an explicit value. Use AttributeClear
// in UpdateUserRequest.Changes to clear an attribute. AccountExpires preserves
// raw FILETIME sentinels; it is not a locale-dependent expiration date string.
type UserProperties = admodel.UserProperties

// UserResult is the SDK's UserResult.
type UserResult = admodel.UserResult

// UsersResult is the SDK's UsersResult.
type UsersResult = admodel.UsersResult
