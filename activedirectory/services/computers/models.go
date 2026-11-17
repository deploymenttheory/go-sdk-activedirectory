// Package computers provides the computers SDK interface.
package computers

import (
	admodel "github.com/deploymenttheory/go-sdk-activedirectory/activedirectory/internal/model"
)

// Computer preserves raw and ranged values. AccountControl separates stored
// flags from server-computed state; nil properties were not returned.
type Computer = admodel.Computer

// ComputerCreationResult retains independent nontransactional stage outcomes.
// Nil stage pointers mean not entered. No accepted creation is rolled back.
type ComputerCreationResult = admodel.ComputerCreationResult

// ComputerMutationResult is the SDK's ComputerMutationResult.
type ComputerMutationResult = admodel.ComputerMutationResult

// ComputerProperties changes only non-nil fields. Clear and multivalue changes
// use AttributeChange. KerberosEncryptionTypes selects the low five AD cmdlet
// encryption bits; CompoundIdentitySupported owns bit 0x40 independently.
type ComputerProperties = admodel.ComputerProperties

// ComputerResult is the SDK's ComputerResult.
type ComputerResult = admodel.ComputerResult

// ComputersResult is the SDK's ComputersResult.
type ComputersResult = admodel.ComputersResult

// CreateComputerRequest creates a disabled workstation-trust account under an
// explicit parent or the configured Computers container when Parent is omitted.
// Omitted SAMAccountName derives from Name. Typed SAM names
// receive a trailing $ when absent. This never joins or configures a machine.
// InitialPassword follows PasswordResetRequest's caller-owned UTF-8 rules.
type CreateComputerRequest = admodel.CreateComputerRequest

// Recursive must be explicit. A submitted tree delete may partially succeed
// even when rejected; the SDK never repeats it to finish deleting descendants.
type DeleteComputerRequest = admodel.DeleteComputerRequest

// ErrComputerCreationIncomplete is the SDK's ErrComputerCreationIncomplete.
var ErrComputerCreationIncomplete = admodel.ErrComputerCreationIncomplete

// ErrInvalidComputer is the SDK's ErrInvalidComputer.
var ErrInvalidComputer = admodel.ErrInvalidComputer

// ErrNotComputer is the SDK's ErrNotComputer.
var ErrNotComputer = admodel.ErrNotComputer

// UpdateComputerRequest is the SDK's UpdateComputerRequest.
type UpdateComputerRequest = admodel.UpdateComputerRequest
