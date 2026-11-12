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
	"github.com/deploymenttheory/go-bindings-win32/bindings/win32/security/authorization"
	"github.com/deploymenttheory/go-bindings-win32/bindings/win32/system/memory"
)

func available() error {
	for _, proc := range []*win32.Proc{
		security.Procs.AddConditionalAce, security.Procs.InitializeAcl,
		security.Procs.InitializeSecurityDescriptor, security.Procs.SetSecurityDescriptorDacl,
		authorization.Procs.ConvertStringSidToSid,
		authorization.Procs.ConvertStringSecurityDescriptorToSecurityDescriptor,
		authorization.Procs.ConvertSecurityDescriptorToStringSecurityDescriptor,
		memory.Procs.LocalAlloc, foundation.Procs.LocalFree,
	} {
		if err := proc.Find(); err != nil {
			return fmt.Errorf("%w: %w", ErrUnsupported, err)
		}
	}
	return nil
}

// release preserves both operation and cleanup errors.
func release(handle foundation.HLOCAL, result *error) {
	if handle == 0 {
		return
	}
	if _, err := foundation.LocalFree(handle); err != nil {
		*result = errors.Join(*result, fmt.Errorf("free native descriptor memory: %w", err))
	}
}

// Compile compiles one conditional allow/deny ACE into a DACL-only SDDL string.
// It creates no directory object and performs no policy-specific access check.
func Compile(ace ACE) (sddl string, err error) {
	condition, err := ace.validate()
	if err != nil {
		return "", err
	}
	if err := available(); err != nil {
		return "", err
	}
	var sid security.PSID
	if err := authorization.ConvertStringSidToSid(ace.TrusteeSID, &sid); err != nil {
		return "", fmt.Errorf("parse trustee SID: %w", err)
	}
	defer release(foundation.HLOCAL(sid), &err)
	// ACL size is a uint16; allocate the largest aligned representable buffer.
	const aclBytes = 65528
	storage := make([]uint64, aclBytes/8)
	var pin runtime.Pinner
	pin.Pin(&storage[0])
	defer pin.Unpin()
	acl := (*security.ACL)(unsafe.Pointer(&storage[0]))
	if err := security.InitializeAcl(acl, aclBytes, 4); err != nil {
		return "", fmt.Errorf("initialize ACL: %w", err)
	}
	aceType := byte(9)
	if ace.Deny {
		aceType = 10
	}
	var required uint32
	if err := security.AddConditionalAce(acl, 4, 0, aceType, ace.AccessMask, sid, condition, &required); err != nil {
		return "", fmt.Errorf("compile condition: %w", err)
	}
	sdMemory, err := memory.LocalAlloc(0, unsafe.Sizeof(security.SECURITY_DESCRIPTOR{}))
	if err != nil {
		return "", fmt.Errorf("allocate descriptor: %w", err)
	}
	defer release(sdMemory, &err)
	sd := security.PSECURITY_DESCRIPTOR(sdMemory)
	if err := security.InitializeSecurityDescriptor(sd, 1); err != nil {
		return "", fmt.Errorf("initialize descriptor: %w", err)
	}
	if err := security.SetSecurityDescriptorDacl(sd, true, acl, false); err != nil {
		return "", fmt.Errorf("attach ACL: %w", err)
	}
	return stringify(sd, security.DACL_SECURITY_INFORMATION)
}

// NormalizeSDDL validates a complete SDDL descriptor and returns Windows' text
// representation, preserving owner/group/DACL/SACL information. It does not
// validate AD schema claims or suitability for AllowedToAuthenticateFrom/To.
func NormalizeSDDL(input string) (sddl string, err error) {
	if !validInput(input) {
		return "", fmt.Errorf("%w: invalid SDDL input", ErrInvalidExpression)
	}
	if err := available(); err != nil {
		return "", err
	}
	var sd security.PSECURITY_DESCRIPTOR
	if err := authorization.ConvertStringSecurityDescriptorToSecurityDescriptor(input, 1, &sd, nil); err != nil {
		return "", fmt.Errorf("parse SDDL: %w", err)
	}
	defer release(foundation.HLOCAL(sd), &err)
	return stringify(sd, security.OWNER_SECURITY_INFORMATION|security.GROUP_SECURITY_INFORMATION|security.DACL_SECURITY_INFORMATION|security.SACL_SECURITY_INFORMATION)
}

func stringify(sd security.PSECURITY_DESCRIPTOR, info security.OBJECT_SECURITY_INFORMATION) (sddl string, err error) {
	var text foundation.PWSTR
	if err := authorization.ConvertSecurityDescriptorToStringSecurityDescriptor(sd, 1, info, &text, nil); err != nil {
		return "", fmt.Errorf("format SDDL: %w", err)
	}
	defer release(foundation.HLOCAL(uintptr(unsafe.Pointer(text))), &err)
	return win32.UTF16ToString(text), nil
}
