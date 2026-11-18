package model

import (
	"errors"
	"slices"
	"strconv"
)

// InternalDirectoryDACLWriteControls guards a derived DACL edit with the GUID
// and uSNChanged from its own controlled snapshot. A preflight read cannot
// substitute for a supported critical server assertion. Each OU/parent step is
// guarded independently; no cross-object transaction or automatic retry exists.
func InternalDirectoryDACLWriteControls(root RootDSE, source Endpoint, options ObjectMutationOptions, guid GUID, before Object) ([]InternalLdapWriteControl, error) {
	if !slices.Contains(root.SupportedControls, InternalDirectorySDFlagsControl) || !slices.Contains(root.SupportedControls, InternalObjectAssertionControl) {
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
	if options.ExpectedVersion == nil {
		value, err = before.Values("uSNChanged").Single()
		if err != nil {
			return nil, err
		}
		text, textErr := value.Text()
		if textErr != nil {
			return nil, textErr
		}
		version, parseErr := strconv.ParseUint(text, 10, 64)
		if parseErr != nil {
			return nil, errors.Join(ErrInvalidResult, parseErr)
		}
		options.ExpectedVersion = &ObjectVersion{Source: source, GUID: guid, USNChanged: version}
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
