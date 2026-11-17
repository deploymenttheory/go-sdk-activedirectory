// Package service_accounts provides the service_accounts SDK interface.
package service_accounts

import (
	admodel "github.com/deploymenttheory/go-sdk-activedirectory/activedirectory/internal/model"
)

// ComputerServiceAccountLink is the SDK's ComputerServiceAccountLink.
type ComputerServiceAccountLink = admodel.ComputerServiceAccountLink

// ComputerServiceAccountMutationResult is the SDK's ComputerServiceAccountMutationResult.
type ComputerServiceAccountMutationResult = admodel.ComputerServiceAccountMutationResult

// ComputerServiceAccountRange is the SDK's ComputerServiceAccountRange.
type ComputerServiceAccountRange = admodel.ComputerServiceAccountRange

// These operations edit directory links only. They do not install an account,
// reset its password, or grant a computer permission to retrieve a gMSA secret.
type ComputerServiceAccountRequest = admodel.ComputerServiceAccountRequest

// ComputerServiceAccountsOptions is the SDK's ComputerServiceAccountsOptions.
type ComputerServiceAccountsOptions = admodel.ComputerServiceAccountsOptions

// Complete describes enumeration and resolution, not visibility through ACLs.
// AttributeReturned=false cannot establish that no associations exist.
type ComputerServiceAccountsResult = admodel.ComputerServiceAccountsResult

// CreateServiceAccountRequest is the SDK's CreateServiceAccountRequest.
type CreateServiceAccountRequest = admodel.CreateServiceAccountRequest

// DeleteServiceAccountRequest is the SDK's DeleteServiceAccountRequest.
type DeleteServiceAccountRequest = admodel.DeleteServiceAccountRequest

// ErrInvalidServiceAccount is the SDK's ErrInvalidServiceAccount.
var ErrInvalidServiceAccount = admodel.ErrInvalidServiceAccount

// ErrInvalidServiceAccountInstall is the SDK's ErrInvalidServiceAccountInstall.
var ErrInvalidServiceAccountInstall = admodel.ErrInvalidServiceAccountInstall

// ErrNotServiceAccount is the SDK's ErrNotServiceAccount.
var ErrNotServiceAccount = admodel.ErrNotServiceAccount

// ErrServiceAccountAssociationLimit is the SDK's ErrServiceAccountAssociationLimit.
var ErrServiceAccountAssociationLimit = admodel.ErrServiceAccountAssociationLimit

// ErrServiceAccountCreationIncomplete is the SDK's ErrServiceAccountCreationIncomplete.
var ErrServiceAccountCreationIncomplete = admodel.ErrServiceAccountCreationIncomplete

// ErrServiceAccountHost is the SDK's ErrServiceAccountHost.
var ErrServiceAccountHost = admodel.ErrServiceAccountHost

// ErrServiceAccountLocalObservation is the SDK's ErrServiceAccountLocalObservation.
var ErrServiceAccountLocalObservation = admodel.ErrServiceAccountLocalObservation

// ErrServiceAccountLocalPermission is the SDK's ErrServiceAccountLocalPermission.
var ErrServiceAccountLocalPermission = admodel.ErrServiceAccountLocalPermission

// ErrServiceAccountLocalUncertain is the SDK's ErrServiceAccountLocalUncertain.
var ErrServiceAccountLocalUncertain = admodel.ErrServiceAccountLocalUncertain

// ErrServiceAccountMigration is the SDK's ErrServiceAccountMigration.
var ErrServiceAccountMigration = admodel.ErrServiceAccountMigration

// ErrServiceAccountMigrationPaired means the two accounts do not reference
// each other, so operating on them would join unrelated migrations.
var ErrServiceAccountMigrationPaired = admodel.ErrServiceAccountMigrationPaired

// ErrServiceAccountMigrationPartial means one account was written and the
// other was not. Reconcile before another attempt; nothing is replayed.
var ErrServiceAccountMigrationPartial = admodel.ErrServiceAccountMigrationPartial

// ErrServiceAccountMigrationState means the observed pair is not in the
// state this transition requires. Nothing is written.
var ErrServiceAccountMigrationState = admodel.ErrServiceAccountMigrationState

// ErrServiceAccountNotInstalled is the SDK's ErrServiceAccountNotInstalled.
var ErrServiceAccountNotInstalled = admodel.ErrServiceAccountNotInstalled

// ErrServiceAccountOtherHost is the SDK's ErrServiceAccountOtherHost.
var ErrServiceAccountOtherHost = admodel.ErrServiceAccountOtherHost

// ErrServiceAccountPrerequisite is the SDK's ErrServiceAccountPrerequisite.
var ErrServiceAccountPrerequisite = admodel.ErrServiceAccountPrerequisite

// ErrServiceAccountReadiness is the SDK's ErrServiceAccountReadiness.
var ErrServiceAccountReadiness = admodel.ErrServiceAccountReadiness

// InstallLocalServiceAccountRequest is the SDK's InstallLocalServiceAccountRequest.
type InstallLocalServiceAccountRequest = admodel.InstallLocalServiceAccountRequest

// LocalServiceAccountAttempt is the SDK's LocalServiceAccountAttempt.
type LocalServiceAccountAttempt = admodel.LocalServiceAccountAttempt

// LocalServiceAccountHost is the SDK's LocalServiceAccountHost.
type LocalServiceAccountHost = admodel.LocalServiceAccountHost

// Native status preserves the NTSTATUS bit pattern. It is never interpreted as
// GetLastError, and formatted errors never include account/password text.
type LocalServiceAccountNativeError = admodel.LocalServiceAccountNativeError

// Directory contains the explicit LDAP resolution; Host always identifies the
// executing Windows machine. LDAP credentials are never forwarded to Net APIs.
// Before/After describe Netlogon-store presence, not password validity or a
// guarantee that a running service cannot recreate a gMSA cache entry.
type LocalServiceAccountResult = admodel.LocalServiceAccountResult

// MigrationCompleted is the SDK's MigrationCompleted.
const MigrationCompleted = admodel.MigrationCompleted

// MigrationNone is the SDK's MigrationNone.
const MigrationNone = admodel.MigrationNone

// MigrationStarted is the SDK's MigrationStarted.
const MigrationStarted = admodel.MigrationStarted

// ResetLocalServiceAccountPasswordRequest resets the host-held credential for
// one managed service account that is already installed here.
type ResetLocalServiceAccountPasswordRequest = admodel.ResetLocalServiceAccountPasswordRequest

// ServiceAccount is the SDK's ServiceAccount.
type ServiceAccount = admodel.ServiceAccount

// ServiceAccountCreationResult is the SDK's ServiceAccountCreationResult.
type ServiceAccountCreationResult = admodel.ServiceAccountCreationResult

// ServiceAccountGroupManaged is the SDK's ServiceAccountGroupManaged.
const ServiceAccountGroupManaged = admodel.ServiceAccountGroupManaged

// ServiceAccountKind is the SDK's ServiceAccountKind.
type ServiceAccountKind = admodel.ServiceAccountKind

// ServiceAccountMigrationRequest names the pair. Identity is the delegated
// account; SupersededAccount is the account it replaces.
type ServiceAccountMigrationRequest = admodel.ServiceAccountMigrationRequest

// ServiceAccountMigrationResult is the SDK's ServiceAccountMigrationResult.
type ServiceAccountMigrationResult = admodel.ServiceAccountMigrationResult

// ServiceAccountMigrationSide is one half of the observed pair.
type ServiceAccountMigrationSide = admodel.ServiceAccountMigrationSide

// ServiceAccountMigrationState is the stored migration state. Absent and zero
// are both reported as MigrationNone; the state attribute is mandatory on the
// dMSA class, so clearing it means writing zero rather than removing it.
type ServiceAccountMigrationState = admodel.ServiceAccountMigrationState

// ServiceAccountMutationResult is the SDK's ServiceAccountMutationResult.
type ServiceAccountMutationResult = admodel.ServiceAccountMutationResult

// ServiceAccountPasswordPrompt is the non-interactive SDK equivalent of
// PromptForPassword. The callback owns its UI. Returned bytes transfer to the
// SDK and are erased on every exit; do not return a shared or reusable buffer.
// Explicit AccountPassword takes precedence. Neither form is used for gMSAs.
type ServiceAccountPasswordPrompt = admodel.ServiceAccountPasswordPrompt

// Prerequisites are observations on the selected DC, not an authorization or
// password-retrieval guarantee. KDS contains metadata only, never root key data.
type ServiceAccountPrerequisites = admodel.ServiceAccountPrerequisites

// The observation accompanies failures, including invalid class/SID and ACL
// omission. No unresolved principal is converted into a grant.
type ServiceAccountPrincipalError = admodel.ServiceAccountPrincipalError

// ServiceAccountProperties changes only non-nil fields. An empty SPN slice
// clears that property. Password interval is creation-only. No password blob or
// password material is projected by these APIs, including via Properties.
type ServiceAccountProperties = admodel.ServiceAccountProperties

// ServiceAccountReadinessRequest selects one account. The account is resolved
// over the configured LDAP endpoint; the readiness reading is taken on the
// executing host.
type ServiceAccountReadinessRequest = admodel.ServiceAccountReadinessRequest

// ServiceAccountReadinessResult reports the reading and everything it was
// derived from, so a false result is explainable rather than bare.
type ServiceAccountReadinessResult = admodel.ServiceAccountReadinessResult

// ServiceAccountResult is the SDK's ServiceAccountResult.
type ServiceAccountResult = admodel.ServiceAccountResult

// ServiceAccountStandalone is the SDK's ServiceAccountStandalone.
const ServiceAccountStandalone = admodel.ServiceAccountStandalone

// ServiceAccountsResult is the SDK's ServiceAccountsResult.
type ServiceAccountsResult = admodel.ServiceAccountsResult

// UninstallLocalServiceAccountRequest is the SDK's UninstallLocalServiceAccountRequest.
type UninstallLocalServiceAccountRequest = admodel.UninstallLocalServiceAccountRequest

// UpdateServiceAccountRequest is the SDK's UpdateServiceAccountRequest.
type UpdateServiceAccountRequest = admodel.UpdateServiceAccountRequest
