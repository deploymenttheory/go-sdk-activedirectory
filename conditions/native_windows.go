//go:build windows && (amd64 || arm64)

package conditions

import (
	"errors"
	"fmt"
	"runtime"
	"unsafe"

	"github.com/deploymenttheory/go-bindings-win32/bindings/runtime/win32"
	"github.com/deploymenttheory/go-bindings-win32/bindings/win32/foundation"
	"github.com/deploymenttheory/go-bindings-win32/bindings/win32/security"
)

// release preserves both operation and cleanup errors.
func (api nativeAPI) release(handle foundation.HLOCAL, result *error) {
	if handle == 0 {
		return
	}
	if _, err := api.free(handle); err != nil {
		*result = errors.Join(*result, fmt.Errorf("free native descriptor memory: %w", err))
	}
}

// Compile compiles one conditional allow/deny ACE into a DACL-only SDDL string.
// It creates no directory object and performs no policy-specific access check.
func Compile(ace ACE) (string, error) {
	return systemNativeAPI().compile(ace)
}

func (api nativeAPI) compile(ace ACE) (sddl string, err error) {
	condition, err := ace.validate()
	if err != nil {
		return "", err
	}
	if err := api.available(); err != nil {
		return "", err
	}
	var sid security.PSID
	if err := api.convertSID(ace.TrusteeSID, &sid); err != nil {
		return "", fmt.Errorf("parse trustee SID: %w", err)
	}
	defer api.release(foundation.HLOCAL(sid), &err)
	// ACL size is a uint16; allocate the largest aligned representable buffer.
	const aclBytes = 65528
	storage := make([]uint64, aclBytes/8)
	var pin runtime.Pinner
	pin.Pin(&storage[0])
	defer pin.Unpin()
	acl := (*security.ACL)(unsafe.Pointer(&storage[0]))
	if err := api.initializeACL(acl, aclBytes, 4); err != nil {
		return "", fmt.Errorf("initialize ACL: %w", err)
	}
	aceType := byte(9)
	if ace.Deny {
		aceType = 10
	}
	var required uint32
	if err := api.addConditionalACE(
		acl,
		4,
		0,
		aceType,
		ace.AccessMask,
		sid,
		condition,
		&required,
	); err != nil {
		return "", fmt.Errorf("compile condition: %w", err)
	}
	sdMemory, err := api.allocate(0, unsafe.Sizeof(security.SECURITY_DESCRIPTOR{}))
	if err != nil {
		return "", fmt.Errorf("allocate descriptor: %w", err)
	}
	defer api.release(sdMemory, &err)
	sd := security.PSECURITY_DESCRIPTOR(sdMemory)
	if err := api.initializeDescriptor(sd, 1); err != nil {
		return "", fmt.Errorf("initialize descriptor: %w", err)
	}
	if err := api.setDACL(sd, true, acl, false); err != nil {
		return "", fmt.Errorf("attach ACL: %w", err)
	}
	return api.stringify(sd, security.DACL_SECURITY_INFORMATION)
}

// NormalizeSDDL validates a complete SDDL descriptor and returns Windows' text
// representation, preserving owner/group/DACL/SACL information. It does not
// validate AD schema claims or suitability for AllowedToAuthenticateFrom/To.
func NormalizeSDDL(input string) (string, error) {
	return systemNativeAPI().normalize(input)
}

func (api nativeAPI) normalize(input string) (sddl string, err error) {
	if !validInput(input) {
		return "", fmt.Errorf("%w: invalid SDDL input", ErrInvalidExpression)
	}
	if err := api.available(); err != nil {
		return "", err
	}
	var sd security.PSECURITY_DESCRIPTOR
	if err := api.parseDescriptor(input, 1, &sd, nil); err != nil {
		return "", fmt.Errorf("parse SDDL: %w", err)
	}
	defer api.release(foundation.HLOCAL(sd), &err)
	return api.stringify(
		sd,
		security.OWNER_SECURITY_INFORMATION|security.GROUP_SECURITY_INFORMATION|security.DACL_SECURITY_INFORMATION|security.SACL_SECURITY_INFORMATION,
	)
}

func (api nativeAPI) stringify(
	sd security.PSECURITY_DESCRIPTOR,
	info security.OBJECT_SECURITY_INFORMATION,
) (sddl string, err error) {
	var text foundation.PWSTR
	if err := api.formatDescriptor(sd, 1, info, &text, nil); err != nil {
		return "", fmt.Errorf("format SDDL: %w", err)
	}
	defer api.release(foundation.HLOCAL(uintptr(unsafe.Pointer(text))), &err)
	return win32.UTF16ToString(text), nil
}
