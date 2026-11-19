package model

import (
	"errors"
	"slices"
)

// InternalDirectoryDACLWriteControls selects a DACL-only update bound to the
// observed GUID. Ordinary writes follow the AD PowerShell update contract;
// only an explicit ExpectedVersion requires a supported server assertion.
// Readback verifies the effect, not isolation from concurrent writers.
func InternalDirectoryDACLWriteControls(root RootDSE, source Endpoint, options ObjectMutationOptions, guid GUID, before Object) ([]InternalLdapWriteControl, error) {
	if !slices.Contains(root.SupportedControls, InternalDirectorySDFlagsControl) {
		return nil, ErrObjectControlUnsupported
	}
	value, err := before.Values("objectGUID").Single()
	if err != nil {
		return nil, err
	}
	observed, err := value.GUID()
	if err != nil || observed != guid {
		return nil, errors.Join(ErrObjectConcurrency, err)
	}
	controls, err := InternalObjectWriteControls(root, source, options, guid, false)
	if err != nil {
		return nil, err
	}
	return append(controls, InternalLdapWriteControl{
		InternalOid: InternalDirectorySDFlagsControl, InternalCritical: true,
		InternalValue: []byte{0x30, 3, 2, 1, 4},
	}), nil
}
