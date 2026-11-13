//go:build windows && (amd64 || arm64)

package activedirectory

import (
	"context"
	"errors"
	"fmt"
	"runtime"
	"unicode/utf16"
	"unicode/utf8"
	"unsafe"

	"github.com/deploymenttheory/go-bindings-win32/bindings/runtime/win32"
	"github.com/deploymenttheory/go-bindings-win32/bindings/win32/foundation"
	nativead "github.com/deploymenttheory/go-bindings-win32/bindings/win32/networking/activedirectory"
	"github.com/deploymenttheory/go-bindings-win32/bindings/win32/networkmanagement/netmanagement"
	"github.com/deploymenttheory/go-bindings-win32/bindings/win32/system/systeminformation"
)

// Injectable per backend, never a replaceable process-global native table.
// Unit tests supply every callable and never invoke native account operations.
type localServiceAccountAPI struct {
	find     func(*win32.Proc) error
	role     func(*string, nativead.DSROLE_PRIMARY_DOMAIN_INFO_LEVEL, **byte) uint32
	freeRole func(unsafe.Pointer)
	name     func(systeminformation.COMPUTER_NAME_FORMAT, foundation.PWSTR, *uint32) error
	is       func(*string, string, *foundation.BOOL) foundation.NTSTATUS
	add      func(foundation.PWSTR, foundation.PWSTR, foundation.PWSTR, uint32) foundation.NTSTATUS
	remove   func(*string, string, uint32) foundation.NTSTATUS
}
type nativeLocalServiceAccountBackend struct{ api localServiceAccountAPI }

func newLocalServiceAccountBackend() localServiceAccountBackend {
	return nativeLocalServiceAccountBackend{api: localServiceAccountAPI{
		find: func(p *win32.Proc) error { return p.Find() }, role: nativead.DsRoleGetPrimaryDomainInformation, freeRole: nativead.DsRoleFreeMemory, name: systeminformation.GetComputerNameEx, is: netmanagement.NetIsServiceAccount, add: netmanagement.NetAddServiceAccountUTF16, remove: netmanagement.NetRemoveServiceAccount,
	}}
}
func (api localServiceAccountAPI) available(procs ...*win32.Proc) error {
	for _, p := range procs {
		if err := api.find(p); err != nil {
			return fmt.Errorf("%w: %w", ErrUnsupported, err)
		}
	}
	return nil
}
func (b nativeLocalServiceAccountBackend) host(ctx context.Context) (result LocalServiceAccountHost, err error) {
	if err = b.api.available(nativead.Procs.DsRoleGetPrimaryDomainInformation, nativead.Procs.DsRoleFreeMemory, systeminformation.Procs.GetComputerNameEx); err != nil {
		return
	}
	if err = context.Cause(ctx); err != nil {
		return
	}
	runtime.LockOSThread()
	defer runtime.UnlockOSThread()
	defer func() { err = errors.Join(err, context.Cause(ctx)) }()
	var owner *byte
	status := b.api.role(nil, nativead.DsRolePrimaryDomainInfoBasic, &owner)
	if owner != nil {
		defer b.api.freeRole(unsafe.Pointer(owner))
	}
	if status != 0 {
		return result, nativeStatus("DsRoleGetPrimaryDomainInformation", status)
	}
	if owner == nil {
		return result, ErrInvalidResult
	}
	info := (*nativead.DSROLE_PRIMARY_DOMAIN_INFO_BASIC)(unsafe.Pointer(owner))
	result.MachineRole = uint32(info.MachineRole)
	result.ReadOnly = info.Flags&nativead.DSROLE_PRIMARY_DS_READONLY != 0
	if info.Flags&nativead.DSROLE_PRIMARY_DOMAIN_GUID_PRESENT == 0 {
		return result, ErrServiceAccountHost
	}
	result.DomainGUID, err = ParseGUID(info.DomainGuid.String())
	if err != nil {
		return
	}
	domain, e := copyDiscoveryText(info.DomainNameDns)
	if e != nil || domain == nil {
		return result, errors.Join(ErrServiceAccountHost, e)
	}
	result.DomainDNS = *domain
	if err = context.Cause(ctx); err != nil {
		return
	}
	buffer := make([]uint16, 256)
	size := uint32(len(buffer))
	if err = b.api.name(systeminformation.ComputerNameNetBIOS, &buffer[0], &size); err != nil {
		return result, fmt.Errorf("GetComputerNameExW: %w", err)
	}
	if size == 0 || size >= uint32(len(buffer)) || buffer[size] != 0 {
		return result, ErrInvalidResult
	}
	result.ComputerName, err = decodeDiscoveryUTF16(buffer[:size])
	return
}
func (b nativeLocalServiceAccountBackend) installed(ctx context.Context, name string) (*bool, error) {
	if err := b.api.available(netmanagement.Procs.NetIsServiceAccount); err != nil {
		return nil, err
	}
	if err := context.Cause(ctx); err != nil {
		return nil, err
	}
	runtime.LockOSThread()
	defer runtime.UnlockOSThread()
	var present foundation.BOOL
	status := uint32(b.api.is(nil, name, &present))
	if status != 0 {
		return nil, errors.Join(&LocalServiceAccountNativeError{Operation: "NetIsServiceAccount", Status: status}, context.Cause(ctx))
	}
	// Ignore output on native failure; an abnormal BOOL is not a truth value.
	if present != 0 && present != 1 {
		return nil, ErrInvalidResult
	}
	value := present != 0
	return &value, context.Cause(ctx)
}
func localServiceAccountUTF16(password []byte) []uint16 {
	buffer := make([]uint16, 0, len(password)+1)
	for len(password) > 0 {
		r, n := utf8.DecodeRune(password)
		if r <= 0xffff {
			buffer = append(buffer, uint16(r))
		} else {
			high, low := utf16.EncodeRune(r)
			buffer = append(buffer, uint16(high), uint16(low))
		}
		password = password[n:]
	}
	return append(buffer, 0)
}
func (b nativeLocalServiceAccountBackend) install(ctx context.Context, name string, password []byte, flags uint32) (attempt LocalServiceAccountAttempt) {
	attempt = LocalServiceAccountAttempt{Operation: "NetAddServiceAccount", Flags: flags}
	if (flags != 1 && flags != 2) || (flags == 1 && password != nil) || (flags == 2 && password == nil) {
		attempt.Error = ErrInvalidServiceAccountInstall
		return
	}
	if password != nil {
		if err := validatePasswordBytes(password); err != nil {
			attempt.Error = err
			return
		}
	}
	if normalized, err := localServiceAccountName(name); err != nil || normalized != name {
		attempt.Error = ErrInvalidServiceAccountInstall
		return
	}
	if attempt.Error = b.api.available(netmanagement.Procs.NetAddServiceAccount); attempt.Error != nil {
		return
	}
	if attempt.Error = context.Cause(ctx); attempt.Error != nil {
		return
	}
	account := append(utf16.Encode([]rune(name)), 0)
	var secret []uint16
	var secretPtr *uint16
	if password != nil {
		secret = localServiceAccountUTF16(password)
		secretPtr = &secret[0]
		defer func() { clear(secret); runtime.KeepAlive(secret) }()
	}
	var pins runtime.Pinner
	defer pins.Unpin()
	pins.Pin(&account[0])
	if secretPtr != nil {
		pins.Pin(secretPtr)
	}
	runtime.LockOSThread()
	defer runtime.UnlockOSThread()
	if attempt.Error = context.Cause(ctx); attempt.Error != nil {
		return
	}
	// Inputs remain pinned until this synchronous call returns. Do not spawn a
	// worker that could outlive the caller and later mutate local state.
	attempt.State = ObjectWriteUncertain
	status := uint32(b.api.add(nil, &account[0], secretPtr, flags))
	runtime.KeepAlive(account)
	runtime.KeepAlive(secret)
	attempt.Status = &status
	attempt.State = ObjectWriteRejected
	if status == 0 {
		attempt.State = ObjectWriteAccepted
	}
	attempt.Error = context.Cause(ctx)
	return
}
func (b nativeLocalServiceAccountBackend) uninstall(ctx context.Context, name string, flags uint32) (attempt LocalServiceAccountAttempt) {
	attempt = LocalServiceAccountAttempt{Operation: "NetRemoveServiceAccount", Flags: flags}
	if flags != 1 && flags != 2 {
		attempt.Error = ErrInvalidServiceAccountInstall
		return
	}
	if normalized, err := localServiceAccountName(name); err != nil || normalized != name {
		attempt.Error = ErrInvalidServiceAccountInstall
		return
	}
	if attempt.Error = b.api.available(netmanagement.Procs.NetRemoveServiceAccount); attempt.Error != nil {
		return
	}
	if attempt.Error = context.Cause(ctx); attempt.Error != nil {
		return
	}
	runtime.LockOSThread()
	defer runtime.UnlockOSThread()
	attempt.State = ObjectWriteUncertain
	status := uint32(b.api.remove(nil, name, flags))
	attempt.Status = &status
	attempt.State = ObjectWriteRejected
	if status == 0 {
		attempt.State = ObjectWriteAccepted
	}
	attempt.Error = context.Cause(ctx)
	return
}
