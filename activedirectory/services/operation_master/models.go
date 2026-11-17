// Package operation_master provides the operation_master SDK interface.
package operation_master

import (
	admodel "github.com/deploymenttheory/go-sdk-activedirectory/activedirectory/internal/model"
)

// ErrInvalidOperationMasterRequest is the SDK's ErrInvalidOperationMasterRequest.
var ErrInvalidOperationMasterRequest = admodel.ErrInvalidOperationMasterRequest

// ErrOperationMasterCapability is the SDK's ErrOperationMasterCapability.
var ErrOperationMasterCapability = admodel.ErrOperationMasterCapability

// ErrOperationMasterChanged is the SDK's ErrOperationMasterChanged.
var ErrOperationMasterChanged = admodel.ErrOperationMasterChanged

// ErrOperationMasterPermission is the SDK's ErrOperationMasterPermission.
var ErrOperationMasterPermission = admodel.ErrOperationMasterPermission

// ErrOperationMasterRIDPool is the SDK's ErrOperationMasterRIDPool.
var ErrOperationMasterRIDPool = admodel.ErrOperationMasterRIDPool

// ErrOperationMasterReadback is the SDK's ErrOperationMasterReadback.
var ErrOperationMasterReadback = admodel.ErrOperationMasterReadback

// ErrOperationMasterUncertain is the SDK's ErrOperationMasterUncertain.
var ErrOperationMasterUncertain = admodel.ErrOperationMasterUncertain

// MoveOperationMasterRolesRequest moves roles to the Client's pinned endpoint.
// Domain roles apply to that server's default domain, independently of
// Config.Partition. Roles are processed in the requested order, stopping on
// the first error. There is no rollback of earlier roles.
type MoveOperationMasterRolesRequest = admodel.MoveOperationMasterRolesRequest

// MoveOperationMasterRolesResult is the SDK's MoveOperationMasterRolesResult.
type MoveOperationMasterRolesResult = admodel.MoveOperationMasterRolesResult

// OperationMasterAlreadyOwned is the SDK's OperationMasterAlreadyOwned.
const OperationMasterAlreadyOwned = admodel.OperationMasterAlreadyOwned

// OperationMasterAttempt preserves the native failure, including LDAP status,
// diagnostic text, and cleanup errors. Diagnostic text may be sensitive.
type OperationMasterAttempt = admodel.OperationMasterAttempt

// OperationMasterDomainNamingMaster is the SDK's OperationMasterDomainNamingMaster.
const OperationMasterDomainNamingMaster = admodel.OperationMasterDomainNamingMaster

// OperationMasterFailed is the SDK's OperationMasterFailed.
const OperationMasterFailed = admodel.OperationMasterFailed

// OperationMasterInfrastructureMaster is the SDK's OperationMasterInfrastructureMaster.
const OperationMasterInfrastructureMaster = admodel.OperationMasterInfrastructureMaster

// OperationMasterNotAttempted is the SDK's OperationMasterNotAttempted.
const OperationMasterNotAttempted = admodel.OperationMasterNotAttempted

// OperationMasterOutcome records one requested role. Accepted transfer/seizure
// responses retain their status even if subsequent readback fails; check Err
// and Verified before treating the observation as complete. Readback describes
// this server's local replica, not convergence or effective role activation.
type OperationMasterOutcome = admodel.OperationMasterOutcome

// OperationMasterPDCEmulator is the SDK's OperationMasterPDCEmulator.
const OperationMasterPDCEmulator = admodel.OperationMasterPDCEmulator

// OperationMasterRIDMaster is the SDK's OperationMasterRIDMaster.
const OperationMasterRIDMaster = admodel.OperationMasterRIDMaster

// OperationMasterRole identifies one of the five FSMO roles.
type OperationMasterRole = admodel.OperationMasterRole

// OperationMasterSchemaMaster is the SDK's OperationMasterSchemaMaster.
const OperationMasterSchemaMaster = admodel.OperationMasterSchemaMaster

// OperationMasterSeized is the SDK's OperationMasterSeized.
const OperationMasterSeized = admodel.OperationMasterSeized

// OperationMasterStatus is the SDK's OperationMasterStatus.
type OperationMasterStatus = admodel.OperationMasterStatus

// OperationMasterTransferred is the SDK's OperationMasterTransferred.
const OperationMasterTransferred = admodel.OperationMasterTransferred

// OperationMasterUncertain is the SDK's OperationMasterUncertain.
const OperationMasterUncertain = admodel.OperationMasterUncertain

// OperationMasterWriteAccepted is the SDK's OperationMasterWriteAccepted.
const OperationMasterWriteAccepted = admodel.OperationMasterWriteAccepted

// OperationMasterWriteNotAttempted is the SDK's OperationMasterWriteNotAttempted.
const OperationMasterWriteNotAttempted = admodel.OperationMasterWriteNotAttempted

// OperationMasterWriteRejected is the SDK's OperationMasterWriteRejected.
const OperationMasterWriteRejected = admodel.OperationMasterWriteRejected

// OperationMasterWriteState distinguishes a server acknowledgement from a
// missing response. Rejected means the server returned a failure; it does not
// prove that every server-side step of a transfer had no effect.
type OperationMasterWriteState = admodel.OperationMasterWriteState

// OperationMasterWriteUncertain is the SDK's OperationMasterWriteUncertain.
const OperationMasterWriteUncertain = admodel.OperationMasterWriteUncertain
