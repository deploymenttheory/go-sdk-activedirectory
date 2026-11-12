//go:build windows && (amd64 || arm64)

package conditions

import (
	"fmt"

	"github.com/deploymenttheory/go-bindings-win32/bindings/runtime/win32"
	"github.com/deploymenttheory/go-bindings-win32/bindings/win32/foundation"
	"github.com/deploymenttheory/go-bindings-win32/bindings/win32/security"
	"github.com/deploymenttheory/go-bindings-win32/bindings/win32/security/authorization"
	"github.com/deploymenttheory/go-bindings-win32/bindings/win32/system/memory"
)

// Each call owns its native boundary. Tests can audit real allocations and inject
// failures without changing process-wide callbacks or the exported API.
type nativeAPI struct {
	find                 func(*win32.Proc) error
	convertSID           func(string, *security.PSID) error
	initializeACL        func(*security.ACL, uint32, security.ACE_REVISION) error
	addConditionalACE    func(*security.ACL, security.ACE_REVISION, security.ACE_FLAGS, byte, uint32, security.PSID, string, *uint32) error
	allocate             func(memory.LOCAL_ALLOC_FLAGS, uintptr) (foundation.HLOCAL, error)
	initializeDescriptor func(security.PSECURITY_DESCRIPTOR, uint32) error
	setDACL              func(security.PSECURITY_DESCRIPTOR, bool, *security.ACL, bool) error
	parseDescriptor      func(string, uint32, *security.PSECURITY_DESCRIPTOR, *uint32) error
	formatDescriptor     func(security.PSECURITY_DESCRIPTOR, uint32, security.OBJECT_SECURITY_INFORMATION, *foundation.PWSTR, *uint32) error
	free                 func(foundation.HLOCAL) (foundation.HLOCAL, error)
}

func systemNativeAPI() nativeAPI {
	return nativeAPI{
		find:                 func(proc *win32.Proc) error { return proc.Find() },
		convertSID:           authorization.ConvertStringSidToSid,
		initializeACL:        security.InitializeAcl,
		addConditionalACE:    security.AddConditionalAce,
		allocate:             memory.LocalAlloc,
		initializeDescriptor: security.InitializeSecurityDescriptor,
		setDACL:              security.SetSecurityDescriptorDacl,
		parseDescriptor:      authorization.ConvertStringSecurityDescriptorToSecurityDescriptor,
		formatDescriptor:     authorization.ConvertSecurityDescriptorToStringSecurityDescriptor,
		free:                 foundation.LocalFree,
	}
}

func (api nativeAPI) available() error {
	for _, proc := range []*win32.Proc{
		security.Procs.AddConditionalAce, security.Procs.InitializeAcl,
		security.Procs.InitializeSecurityDescriptor, security.Procs.SetSecurityDescriptorDacl,
		authorization.Procs.ConvertStringSidToSid,
		authorization.Procs.ConvertStringSecurityDescriptorToSecurityDescriptor,
		authorization.Procs.ConvertSecurityDescriptorToStringSecurityDescriptor,
		memory.Procs.LocalAlloc, foundation.Procs.LocalFree,
	} {
		if err := api.find(proc); err != nil {
			return fmt.Errorf("%w: %w", ErrUnsupported, err)
		}
	}
	return nil
}
