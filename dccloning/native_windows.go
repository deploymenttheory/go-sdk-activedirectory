//go:build windows && (amd64 || arm64)

package dccloning

import (
	"context"
	"errors"
	"fmt"
	"path/filepath"
	"runtime"
	"sort"
	"strings"
	"syscall"
	"unicode/utf16"
	"unsafe"

	"github.com/deploymenttheory/go-bindings-win32/bindings/win32/foundation"
	"github.com/deploymenttheory/go-bindings-win32/bindings/win32/globalization"
	ad "github.com/deploymenttheory/go-bindings-win32/bindings/win32/networking/activedirectory"
	"github.com/deploymenttheory/go-bindings-win32/bindings/win32/system/registry"
	"github.com/deploymenttheory/go-bindings-win32/bindings/win32/system/services"
)

const uninstallKey = `SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall`
const parametersKey = `SYSTEM\CurrentControlSet\Services\NTDS\Parameters`
const maxNativeBytes = 8 << 20

type nativeMachine struct{ api nativeAPI }

func inspectNative(ctx context.Context) (Result, error) {
	api := systemAPI()
	if err := api.available(false); err != nil {
		return Result{}, err
	}
	r, _, err := inspect(ctx, nativeMachine{api}, readList, true)
	return r, err
}

func (m nativeMachine) role(ctx context.Context) (Role, error) {
	if err := context.Cause(ctx); err != nil {
		return Role{}, err
	}
	var buffer *byte
	status := m.api.getRole(nil, ad.DsRolePrimaryDomainInfoBasic, &buffer)
	if buffer != nil {
		defer m.api.freeRole(unsafe.Pointer(buffer))
	}
	if status != 0 {
		return Role{}, nativeStatus("DsRoleGetPrimaryDomainInformation", status)
	}
	if buffer == nil {
		return Role{}, fmt.Errorf("%w: missing role buffer", ErrIncomplete)
	}
	info := (*ad.DSROLE_PRIMARY_DOMAIN_INFO_BASIC)(unsafe.Pointer(buffer))
	return Role{MachineRole: uint32(info.MachineRole), ReadOnly: info.Flags&ad.DSROLE_PRIMARY_DS_READONLY != 0}, nil
}

func (m nativeMachine) equal(a, b string) (bool, error) {
	if strings.ContainsRune(a, 0) || strings.ContainsRune(b, 0) {
		return false, fmt.Errorf("%w: NUL in inventory name", ErrIncomplete)
	}
	result, err := m.api.compare(a, -1, b, -1, true)
	return result == globalization.CSTR_EQUAL, nativeFailure("CompareStringOrdinal", err)
}

func (m nativeMachine) locations(ctx context.Context) (result locations, resultErr error) {
	system, err := nativeDirectory(m.api.systemDirectory)
	if err != nil {
		return result, nativeFailure("GetSystemDirectoryW", err)
	}
	result.defaultPath = filepath.Join(system, "DefaultDCCloneAllowList.xml")
	windows, err := nativeDirectory(m.api.windowsDirectory)
	if err != nil {
		return result, nativeFailure("GetWindowsDirectoryW", err)
	}
	var key registry.HKEY
	status := m.api.openKey(registry.HKEY_LOCAL_MACHINE, stringPointer(parametersKey), 0, registry.KEY_QUERY_VALUE|registry.KEY_WOW64_64KEY, &key)
	if status != 0 {
		return result, nativeStatus("RegOpenKeyExW(NTDS parameters)", uint32(status))
	}
	defer func() {
		resultErr = errors.Join(resultErr, nativeStatus("RegCloseKey(NTDS parameters)", uint32(m.api.closeKey(key))))
	}()
	for _, value := range []string{"AllowListFolder", "DSA Working Directory"} {
		folder, present, err := m.registryString(ctx, key, value)
		if err != nil {
			return result, err
		}
		if present {
			if !filepath.IsAbs(folder) || strings.ContainsRune(folder, 0) {
				return result, fmt.Errorf("%w: invalid %s registry directory", ErrInvalidPath, value)
			}
			result.directories = append(result.directories, filepath.Clean(folder))
		} else if value == "DSA Working Directory" {
			return result, fmt.Errorf("%w: DSA Working Directory is missing", ErrIncomplete)
		}
	}
	result.directories = append(result.directories, filepath.Join(windows, "NTDS"))
	roots, err := m.removableRoots(ctx)
	result.directories = append(result.directories, roots...)
	return result, err
}

func nativeDirectory(call func(foundation.PWSTR, uint32) (uint32, error)) (string, error) {
	buffer := make([]uint16, 260)
	for attempts := 0; attempts < 8; attempts++ {
		n, err := call(&buffer[0], uint32(len(buffer)))
		if err != nil {
			return "", err
		}
		if n == 0 {
			return "", fmt.Errorf("%w: empty system directory", ErrIncomplete)
		}
		if uint64(n) < uint64(len(buffer)) {
			return checkedUTF16(buffer[:n])
		}
		if n >= maxNativeBytes/2 {
			return "", fmt.Errorf("%w: oversized system directory", ErrIncomplete)
		}
		buffer = make([]uint16, int(n)+1)
	}
	return "", fmt.Errorf("%w: unstable system directory", ErrIncomplete)
}

func (m nativeMachine) removableRoots(ctx context.Context) ([]string, error) {
	buffer := make([]uint16, 256)
	for attempt := 0; attempt < 8; attempt++ {
		if err := context.Cause(ctx); err != nil {
			return nil, err
		}
		n, err := m.api.drives(uint32(len(buffer)), &buffer[0])
		if err != nil {
			return nil, nativeFailure("GetLogicalDriveStringsW", err)
		}
		if n == 0 {
			return nil, fmt.Errorf("%w: empty drive enumeration", ErrIncomplete)
		}
		if n >= uint32(len(buffer)) {
			if n >= maxNativeBytes/2 {
				return nil, fmt.Errorf("%w: oversized drive list", ErrIncomplete)
			}
			buffer = make([]uint16, n+1)
			continue
		}
		var roots []string
		start := 0
		for i := 0; i < int(n); i++ {
			if buffer[i] != 0 {
				continue
			}
			root, err := checkedUTF16(buffer[start:i])
			start = i + 1
			if err != nil {
				return roots, err
			}
			if m.api.driveType(&root) != 2 {
				continue
			} // DRIVE_REMOVABLE
			var flags uint32
			if err := m.api.volume(&root, nil, 0, nil, nil, &flags, nil, 0); err != nil {
				return roots, nativeFailure("GetVolumeInformationW", err)
			}
			if flags&0x80000 == 0 {
				roots = append(roots, root)
			} // FILE_READ_ONLY_VOLUME
		}
		if start != int(n) || buffer[n] != 0 {
			return roots, fmt.Errorf("%w: unterminated drive list", ErrIncomplete)
		}
		sort.Strings(roots)
		return roots, nil
	}
	return nil, fmt.Errorf("%w: unstable drive list", ErrIncomplete)
}

func (m nativeMachine) inventory(ctx context.Context) ([]Entry, error) {
	var entries []Entry
	var failures []error
	for _, view := range []struct {
		flag registry.REG_SAM_FLAGS
		kind Kind
	}{{registry.KEY_WOW64_64KEY, Program}, {registry.KEY_WOW64_32KEY, WoW64Program}} {
		items, err := m.programs(ctx, view.flag, view.kind)
		entries = append(entries, items...)
		if err != nil {
			failures = append(failures, err)
		}
	}
	items, err := m.serviceInventory(ctx)
	entries = append(entries, items...)
	return entries, errors.Join(append(failures, err)...)
}

func (m nativeMachine) serviceInventory(ctx context.Context) (entries []Entry, resultErr error) {
	if err := context.Cause(ctx); err != nil {
		return nil, err
	}
	handle, err := m.api.openSCM(nil, nil, services.SC_MANAGER_ENUMERATE_SERVICE)
	if err != nil {
		return nil, nativeFailure("OpenSCManagerW", err)
	}
	defer func() {
		resultErr = errors.Join(resultErr, nativeFailure("CloseServiceHandle", m.api.closeSCM(handle)))
	}()
	buffer := make([]byte, 256*1024)
	var resume uint32
	for {
		if err := context.Cause(ctx); err != nil {
			return entries, err
		}
		previous := resume
		var needed, count uint32
		err := m.api.enumServices(handle, services.SC_ENUM_PROCESS_INFO, services.SERVICE_WIN32, services.SERVICE_STATE_ALL, buffer, &needed, &count, &resume, nil)
		if err != nil && !errors.Is(err, syscall.ERROR_MORE_DATA) {
			return entries, nativeFailure("EnumServicesStatusExW", err)
		}
		page, decodeErr := servicePage(buffer, count)
		entries = append(entries, page...)
		if decodeErr != nil {
			return entries, decodeErr
		}
		if err == nil {
			return entries, nil
		}
		if resume == previous || count == 0 {
			return entries, fmt.Errorf("%w: service enumeration made no progress", ErrIncomplete)
		}
	}
}

func servicePage(buffer []byte, count uint32) ([]Entry, error) {
	size := unsafe.Sizeof(services.ENUM_SERVICE_STATUS_PROCESSW{})
	if uint64(count)*uint64(size) > uint64(len(buffer)) {
		return nil, fmt.Errorf("%w: invalid service count", ErrIncomplete)
	}
	if count == 0 {
		return nil, nil
	}
	rows := unsafe.Slice((*services.ENUM_SERVICE_STATUS_PROCESSW)(unsafe.Pointer(&buffer[0])), count)
	entries := make([]Entry, 0, count)
	for _, row := range rows {
		name, err := bufferString(buffer, row.LpServiceName)
		if err != nil {
			return entries, err
		}
		entries = append(entries, Entry{Name: name, Type: Service, Source: "SCM"})
	}
	runtime.KeepAlive(buffer)
	return entries, nil
}

func bufferString(buffer []byte, pointer *uint16) (string, error) {
	if len(buffer) == 0 || pointer == nil {
		return "", fmt.Errorf("%w: absent service name", ErrIncomplete)
	}
	start := uintptr(unsafe.Pointer(&buffer[0]))
	address := uintptr(unsafe.Pointer(pointer))
	if address < start || address-start >= uintptr(len(buffer)) || address%2 != 0 {
		return "", fmt.Errorf("%w: service name outside buffer", ErrIncomplete)
	}
	words := unsafe.Slice(pointer, (uintptr(len(buffer))-(address-start))/2)
	for i, value := range words {
		if value == 0 {
			return checkedUTF16(words[:i])
		}
	}
	return "", fmt.Errorf("%w: unterminated service name", ErrIncomplete)
}

func checkedUTF16(words []uint16) (string, error) {
	for i := 0; i < len(words); i++ {
		w := words[i]
		if w == 0 {
			return "", fmt.Errorf("%w: embedded NUL", ErrIncomplete)
		}
		if w >= 0xd800 && w <= 0xdbff {
			if i+1 == len(words) || words[i+1] < 0xdc00 || words[i+1] > 0xdfff {
				return "", fmt.Errorf("%w: invalid UTF-16", ErrIncomplete)
			}
			i++
		} else if w >= 0xdc00 && w <= 0xdfff {
			return "", fmt.Errorf("%w: invalid UTF-16", ErrIncomplete)
		}
	}
	return string(utf16.Decode(words)), nil
}

func stringPointer(value string) *string { return &value }
