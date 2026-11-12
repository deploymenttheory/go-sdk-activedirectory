//go:build windows && (amd64 || arm64)

package dccloning

import (
	"errors"
	"fmt"
	"syscall"
	"unsafe"

	"github.com/deploymenttheory/go-bindings-win32/bindings/runtime/win32"
	"github.com/deploymenttheory/go-bindings-win32/bindings/win32/foundation"
	"github.com/deploymenttheory/go-bindings-win32/bindings/win32/globalization"
	ad "github.com/deploymenttheory/go-bindings-win32/bindings/win32/networking/activedirectory"
	"github.com/deploymenttheory/go-bindings-win32/bindings/win32/storage/filesystem"
	"github.com/deploymenttheory/go-bindings-win32/bindings/win32/system/registry"
	"github.com/deploymenttheory/go-bindings-win32/bindings/win32/system/services"
	"github.com/deploymenttheory/go-bindings-win32/bindings/win32/system/systeminformation"
)

// Each operation owns its boundary; tests never replace global dispatch.
type nativeAPI struct {
	find             func(*win32.Proc) error
	getRole          func(*string, ad.DSROLE_PRIMARY_DOMAIN_INFO_LEVEL, **byte) uint32
	freeRole         func(unsafe.Pointer)
	openSCM          func(*string, *string, uint32) (services.SC_HANDLE, error)
	closeSCM         func(services.SC_HANDLE) error
	enumServices     func(services.SC_HANDLE, services.SC_ENUM_TYPE, services.ENUM_SERVICE_TYPE, services.ENUM_SERVICE_STATE, []byte, *uint32, *uint32, *uint32, *string) error
	openKey          func(registry.HKEY, *string, uint32, registry.REG_SAM_FLAGS, *registry.HKEY) foundation.WIN32_ERROR
	closeKey         func(registry.HKEY) foundation.WIN32_ERROR
	enumKey          func(registry.HKEY, uint32, foundation.PWSTR, *uint32, foundation.PWSTR, *uint32, *foundation.FILETIME) foundation.WIN32_ERROR
	queryValue       func(registry.HKEY, *string, *registry.REG_VALUE_TYPE, *byte, *uint32) foundation.WIN32_ERROR
	systemDirectory  func(foundation.PWSTR, uint32) (uint32, error)
	windowsDirectory func(foundation.PWSTR, uint32) (uint32, error)
	drives           func(uint32, foundation.PWSTR) (uint32, error)
	driveType        func(*string) uint32
	volume           func(*string, foundation.PWSTR, uint32, *uint32, *uint32, *uint32, foundation.PWSTR, uint32) error
	compare          func(string, int32, string, int32, bool) (globalization.COMPARESTRING_RESULT, error)
	move             func(string, *string, filesystem.MOVE_FILE_FLAGS) error
}

func systemAPI() nativeAPI {
	return nativeAPI{
		find:    func(p *win32.Proc) error { return p.Find() },
		getRole: ad.DsRoleGetPrimaryDomainInformation, freeRole: ad.DsRoleFreeMemory,
		openSCM: services.OpenSCManager, closeSCM: services.CloseServiceHandle, enumServices: services.EnumServicesStatusEx,
		openKey: registry.RegOpenKeyEx, closeKey: registry.RegCloseKey, enumKey: registry.RegEnumKeyEx, queryValue: registry.RegQueryValueEx,
		systemDirectory: systeminformation.GetSystemDirectory, windowsDirectory: systeminformation.GetWindowsDirectory,
		drives: filesystem.GetLogicalDriveStrings, driveType: filesystem.GetDriveType, volume: filesystem.GetVolumeInformation,
		compare: globalization.CompareStringOrdinal, move: filesystem.MoveFileEx,
	}
}

func (a nativeAPI) available(write bool) error {
	procs := []*win32.Proc{
		ad.Procs.DsRoleGetPrimaryDomainInformation, ad.Procs.DsRoleFreeMemory,
		services.Procs.OpenSCManager, services.Procs.CloseServiceHandle, services.Procs.EnumServicesStatusEx,
		registry.Procs.RegOpenKeyEx, registry.Procs.RegCloseKey, registry.Procs.RegEnumKeyEx, registry.Procs.RegQueryValueEx,
		systeminformation.Procs.GetSystemDirectory, systeminformation.Procs.GetWindowsDirectory,
		filesystem.Procs.GetLogicalDriveStrings, filesystem.Procs.GetDriveType, filesystem.Procs.GetVolumeInformation,
		globalization.Procs.CompareStringOrdinal,
	}
	if write {
		procs = append(procs, filesystem.Procs.MoveFileEx)
	}
	for _, proc := range procs {
		if err := a.find(proc); err != nil {
			return fmt.Errorf("%w: %w", ErrUnsupported, err)
		}
	}
	return nil
}

func nativeStatus(operation string, status uint32) error {
	if status == 0 {
		return nil
	}
	return &NativeError{Operation: operation, Code: status, Cause: syscall.Errno(status)}
}

func nativeFailure(operation string, err error) error {
	if err == nil {
		return nil
	}
	var code syscall.Errno
	if errors.As(err, &code) {
		return &NativeError{Operation: operation, Code: uint32(code), Cause: err}
	}
	return fmt.Errorf("%s: %w", operation, err)
}
