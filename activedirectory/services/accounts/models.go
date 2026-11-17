// Package accounts provides the accounts SDK interface.
package accounts

import (
	admodel "github.com/deploymenttheory/go-sdk-activedirectory/activedirectory/internal/model"
)

// AccountControlMutationResult is the SDK's AccountControlMutationResult.
type AccountControlMutationResult = admodel.AccountControlMutationResult

// AccountControlPatch changes only non-nil fields. It never exposes a raw mask
// that could overwrite account-type, computed or unknown flags. Password change
// permission is an ACL property, not a stored UAC flag.
type AccountControlPatch = admodel.AccountControlPatch

// AccountControlRequest is the SDK's AccountControlRequest.
type AccountControlRequest = admodel.AccountControlRequest

// AccountControlResult is the SDK's AccountControlResult.
type AccountControlResult = admodel.AccountControlResult

// AccountControlState retains stored and computed values separately. Nil means
// the attribute was not returned, not false. LockoutTime alone is not a current
// lockout verdict: the server's computed flags account for lockout duration.
type AccountControlState = admodel.AccountControlState

// AccountCreationParentError preserves the naming-context observation used to
// locate a default container. A missing/hidden or partial mapping never selects
// a guessed CN=Users/CN=Computers path. No creation has been submitted.
type AccountCreationParentError = admodel.AccountCreationParentError

// AccountDisabled is the SDK's AccountDisabled.
const AccountDisabled = admodel.AccountDisabled

// AccountExpiration preserves both documented never-expire sentinels. Nil
// Value/NeverExpires means accountExpires was not returned; it does not mean
// never expires. ExpiresAt is an exact UTC instant at 100ns precision.
type AccountExpiration = admodel.AccountExpiration

// AccountExpirationMutationResult is the SDK's AccountExpirationMutationResult.
type AccountExpirationMutationResult = admodel.AccountExpirationMutationResult

// AccountExpirationResult is the SDK's AccountExpirationResult.
type AccountExpirationResult = admodel.AccountExpirationResult

// AccountExpired is the SDK's AccountExpired.
const AccountExpired = admodel.AccountExpired

// AccountExpiring is the SDK's AccountExpiring.
const AccountExpiring = admodel.AccountExpiring

// AccountInactive is the SDK's AccountInactive.
const AccountInactive = admodel.AccountInactive

// AccountInactivityObservation preserves the effective criterion. AD DS reads
// the default domain's msDS-LogonTimeSyncInterval; an omitted value, or AD LDS,
// uses the module's 15-day default. Defaulted is not proof the value is unset:
// ACLs can also hide it. Domain preserves the raw interval read, including errors.
type AccountInactivityObservation = admodel.AccountInactivityObservation

// AccountLockedOut is the SDK's AccountLockedOut.
const AccountLockedOut = admodel.AccountLockedOut

// AccountPasswordExpired is the SDK's AccountPasswordExpired.
const AccountPasswordExpired = admodel.AccountPasswordExpired

// AccountPasswordNeverExpires is the SDK's AccountPasswordNeverExpires.
const AccountPasswordNeverExpires = admodel.AccountPasswordNeverExpires

// AccountPasswordPermission describes SELF/Everyone Change-Password ACEs.
// CannotChangePassword is the recognized deny-pattern observation, not an
// effective-access check or a promise that a password change will succeed.
// Nil means the descriptor/pattern is unknown; it is never a userAccountControl
// bit. The original descriptor remains available in Raw.
type AccountPasswordPermission = admodel.AccountPasswordPermission

// AccountPasswordPermissionMutationResult is the SDK's AccountPasswordPermissionMutationResult.
type AccountPasswordPermissionMutationResult = admodel.AccountPasswordPermissionMutationResult

// AccountPasswordPermissionResult is the SDK's AccountPasswordPermissionResult.
type AccountPasswordPermissionResult = admodel.AccountPasswordPermissionResult

// AccountStateAll is the SDK's AccountStateAll.
const AccountStateAll = admodel.AccountStateAll

// AccountStateComputers is the SDK's AccountStateComputers.
const AccountStateComputers = admodel.AccountStateComputers

// AccountStateCondition is the SDK's AccountStateCondition.
type AccountStateCondition = admodel.AccountStateCondition

// AccountStateKind is the SDK's AccountStateKind.
type AccountStateKind = admodel.AccountStateKind

// AccountStateQuery selects exactly one condition. Expired requires AsOf;
// Expiring requires AsOf and Boundary and matches [AsOf, Boundary). Inactive
// requires Boundary; the module-compatible synchronization allowance is
// subtracted before submitting NOT(lastLogonTimestamp >= effective cutoff).
// Other conditions use the selected server's returned state, not historical
// evaluation. Unused time fields are errors. Relative windows are explicit
// caller computations, e.g. Boundary: reference.Add(-90*24*time.Hour).
//
// Search supplies scope, extra filter/properties, paging and the match limit
// (Search.ResultLimit). ScanLimit separately bounds candidate accounts evaluated,
// default 10,000. The query scans account classes plus the caller's filter and
// evaluates computed state locally, so absent/hidden values remain unknown.
// Inactivity uses the directory predicate, including its absent-value semantics.
type AccountStateQuery = admodel.AccountStateQuery

// Observation contains every received candidate, including any unexamined tail
// of the final page after the match limit. Scanned counts evaluated candidates.
// Complete additionally requires every received candidate to be evaluated and
// no unreadable state. Limits do not prove that further matches exist. A server
// can omit objects entirely under ACLs; completeness is relative to that view.
type AccountStateSearchResult = admodel.AccountStateSearchResult

// AccountStateUnknown is the SDK's AccountStateUnknown.
type AccountStateUnknown = admodel.AccountStateUnknown

// AccountStateUsers is the SDK's AccountStateUsers.
const AccountStateUsers = admodel.AccountStateUsers

// ErrAccountControlTarget is the SDK's ErrAccountControlTarget.
var ErrAccountControlTarget = admodel.ErrAccountControlTarget

// ErrAccountControlUnsupported is the SDK's ErrAccountControlUnsupported.
var ErrAccountControlUnsupported = admodel.ErrAccountControlUnsupported

// ErrAccountCreationParent is the SDK's ErrAccountCreationParent.
var ErrAccountCreationParent = admodel.ErrAccountCreationParent

// ErrAccountPasswordPermission is the SDK's ErrAccountPasswordPermission.
var ErrAccountPasswordPermission = admodel.ErrAccountPasswordPermission

// ErrAccountStateTarget is the SDK's ErrAccountStateTarget.
var ErrAccountStateTarget = admodel.ErrAccountStateTarget

// ErrAccountStateUnreadable is the SDK's ErrAccountStateUnreadable.
var ErrAccountStateUnreadable = admodel.ErrAccountStateUnreadable

// ErrInvalidAccountControl is the SDK's ErrInvalidAccountControl.
var ErrInvalidAccountControl = admodel.ErrInvalidAccountControl

// ErrInvalidAccountExpiration is the SDK's ErrInvalidAccountExpiration.
var ErrInvalidAccountExpiration = admodel.ErrInvalidAccountExpiration

// ErrInvalidAccountStateSearch is the SDK's ErrInvalidAccountStateSearch.
var ErrInvalidAccountStateSearch = admodel.ErrInvalidAccountStateSearch

// ErrInvalidPasswordRequest is the SDK's ErrInvalidPasswordRequest.
var ErrInvalidPasswordRequest = admodel.ErrInvalidPasswordRequest

// ErrPasswordAccess is the SDK's ErrPasswordAccess.
var ErrPasswordAccess = admodel.ErrPasswordAccess

// ErrPasswordConstraint is the SDK's ErrPasswordConstraint.
var ErrPasswordConstraint = admodel.ErrPasswordConstraint

// ErrPasswordCredential is the SDK's ErrPasswordCredential.
var ErrPasswordCredential = admodel.ErrPasswordCredential

// ErrPasswordProtection is the SDK's ErrPasswordProtection.
var ErrPasswordProtection = admodel.ErrPasswordProtection

// ErrPasswordTarget is the SDK's ErrPasswordTarget.
var ErrPasswordTarget = admodel.ErrPasswordTarget

// ErrPasswordUncertain is the SDK's ErrPasswordUncertain.
var ErrPasswordUncertain = admodel.ErrPasswordUncertain

// PasswordChangeACEObservation reports a recognized ACE pattern, not the
// outcome of an access check for an arbitrary logon token or a password change.
type PasswordChangeACEObservation = admodel.PasswordChangeACEObservation

// PasswordChangeRequest requests one delete-old/add-new unicodePwd Modify.
// Passwords are caller-owned UTF-8, must not be mutated during the call, and
// are never retained in Client or Result. Nil means omitted and is rejected;
// an explicit empty slice requests an empty password, subject to server policy.
// The caller clears its own buffers. Go/Windows copies cannot be guaranteed wiped.
type PasswordChangeRequest = admodel.PasswordChangeRequest

// PasswordProtection describes measured protection, not a port-based inference.
// TransportLDAP means SASL confidentiality with an effective key >=128 bits.
type PasswordProtection = admodel.PasswordProtection

// PasswordResetRequest requests an administrative unicodePwd replacement,
// without an old password. The server enforces force-change-password rights.
type PasswordResetRequest = admodel.PasswordResetRequest

// PasswordResult reports one native write attempt. Accepted means the server
// acknowledged the password operation; no secret readback or test login is
// attempted, and acceptance does not prove replication or future login success.
type PasswordResult = admodel.PasswordResult

// SetAccountExpirationRequest accepts an absolute instant. For relative expiry,
// explicitly compute At from a caller-selected reference time using time.Add.
// The SDK never parses locale-dependent dates or chooses midnight/current time.
type SetAccountExpirationRequest = admodel.SetAccountExpirationRequest
