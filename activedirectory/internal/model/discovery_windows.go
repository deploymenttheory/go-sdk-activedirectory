//go:build windows && (amd64 || arm64)

package model

import (
	"context"
	"errors"
	"fmt"
	"runtime"
	"strings"
	"unicode/utf16"
	"unsafe"

	"github.com/deploymenttheory/go-bindings-win32/bindings/runtime/win32"
	"github.com/deploymenttheory/go-bindings-win32/bindings/win32/foundation"
	"github.com/deploymenttheory/go-bindings-win32/bindings/win32/networking/activedirectory"
	"github.com/deploymenttheory/go-bindings-win32/bindings/win32/networkmanagement/netmanagement"
	"github.com/deploymenttheory/go-bindings-win32/bindings/win32/security/authentication/identity"
)

// One boundary per invocation keeps lifetime tests independent of global state.
type InternalDiscoveryAPI struct {
	InternalFind     func(*win32.Proc) error
	InternalGetDC    func(*string, *string, *win32.GUID, *string, uint32, **activedirectory.DOMAIN_CONTROLLER_INFOW) uint32
	InternalFree     func(unsafe.Pointer) uint32
	InternalJoinInfo func(*string, *foundation.PWSTR, *netmanagement.NETSETUP_JOIN_STATUS) uint32
	InternalUserName func(identity.EXTENDED_NAME_FORMAT, foundation.PWSTR, *uint32) (foundation.BOOLEAN, error)
}

func InternalSystemDiscoveryAPI() InternalDiscoveryAPI {
	return InternalDiscoveryAPI{
		InternalFind:     func(proc *win32.Proc) error { return proc.Find() },
		InternalGetDC:    activedirectory.DsGetDcName,
		InternalFree:     netmanagement.NetApiBufferFree,
		InternalJoinInfo: netmanagement.NetGetJoinInformation,
		InternalUserName: identity.GetUserNameEx,
	}
}

func (api InternalDiscoveryAPI) InternalAvailable(procs ...*win32.Proc) error {
	for _, proc := range procs {
		if err := api.InternalFind(proc); err != nil {
			return fmt.Errorf("%w: %w", ErrUnsupported, err)
		}
	}
	return nil
}

func InternalNativeStatus(operation string, code uint32) error {
	if code == 0 {
		return nil
	}
	return &NativeStatusError{Operation: operation, Code: code}
}

func InternalDiscoveryFlags(o DiscoveryOptions) uint32 {
	flags := activedirectory.DS_RETURN_DNS_NAME
	if o.Domain != nil {
		if o.Domain.Format == DomainNameDNS {
			flags |= activedirectory.DS_IS_DNS_NAME
		} else {
			flags |= activedirectory.DS_IS_FLAT_NAME
		}
	}
	for service, flag := range map[DCServices]uint32{
		ServicePrimaryDC: activedirectory.DS_PDC_REQUIRED, ServiceGlobalCatalog: activedirectory.DS_GC_SERVER_REQUIRED,
		ServiceKDC: activedirectory.DS_KDC_REQUIRED, ServiceTime: activedirectory.DS_TIMESERV_REQUIRED,
		ServiceADWS: activedirectory.DS_WEB_SERVICE_REQUIRED,
	} {
		if o.Services&service != 0 {
			flags |= flag
		}
	}
	for _, option := range []struct {
		InternalSet  bool
		InternalFlag uint32
	}{
		{o.Writable, activedirectory.DS_WRITABLE_REQUIRED},
		{o.AvoidSelf, activedirectory.DS_AVOID_SELF},
		{o.ForceDiscover, activedirectory.DS_FORCE_REDISCOVERY},
		{o.PreferReliableTimeService, activedirectory.DS_GOOD_TIMESERV_PREFERRED},
		{o.NextClosestSite, activedirectory.DS_TRY_NEXTCLOSEST_SITE},
	} {
		if option.InternalSet {
			flags |= option.InternalFlag
		}
	}
	// The generic directory-service requirement and the minimum-version
	// requirements are mutually exclusive (MS-NRPC 3.5.4.3.1, flags B/Q/U/V/W).
	versions := [...]uint32{
		activedirectory.DS_DIRECTORY_SERVICE_REQUIRED,
		activedirectory.DS_DIRECTORY_SERVICE_6_REQUIRED,
		activedirectory.DS_DIRECTORY_SERVICE_8_REQUIRED,
		activedirectory.DS_DIRECTORY_SERVICE_9_REQUIRED,
		activedirectory.DS_DIRECTORY_SERVICE_10_REQUIRED,
	}
	return flags | versions[o.MinimumVersion]
}

func InternalDiscoverDomainControllerNative(
	ctx context.Context,
	options DiscoveryOptions,
) (DiscoveredController, error) {
	return InternalDiscoverWithAPI(ctx, options, InternalSystemDiscoveryAPI())
}

func InternalDiscoverWithAPI(
	ctx context.Context,
	options DiscoveryOptions,
	api InternalDiscoveryAPI,
) (result DiscoveredController, err error) {
	options, err = InternalDiscoveryOptionsNormalized(options)
	if err != nil {
		return result, err
	}
	if err = context.Cause(ctx); err != nil {
		return result, err
	}
	if err = api.InternalAvailable(
		activedirectory.Procs.DsGetDcName,
		netmanagement.Procs.NetApiBufferFree,
	); err != nil {
		return result, err
	}
	if err = context.Cause(ctx); err != nil {
		return result, err
	}
	var domain, site *string
	if options.Domain != nil {
		domain = &options.Domain.Name
	}
	if options.SiteName != "" {
		site = &options.SiteName
	}
	var owner *activedirectory.DOMAIN_CONTROLLER_INFOW
	status := api.InternalGetDC(nil, domain, nil, site, InternalDiscoveryFlags(options), &owner)
	defer func() {
		if owner != nil {
			err = errors.Join(
				err,
				InternalNativeStatus("NetApiBufferFree", api.InternalFree(unsafe.Pointer(owner))),
			)
		}
		err = errors.Join(err, context.Cause(ctx))
	}()
	if status != 0 {
		return result, InternalNativeStatus("DsGetDcNameW", status)
	}
	if owner == nil {
		return result, fmt.Errorf("%w: DsGetDcNameW returned NULL", ErrInvalidNativeResult)
	}
	result, err = InternalDecodeDiscoveredController(owner, options)
	return result, err
}

func InternalDecodeDiscoveredController(
	info *activedirectory.DOMAIN_CONTROLLER_INFOW,
	requested DiscoveryOptions,
) (DiscoveredController, error) {
	result := DiscoveredController{
		Requested:  requested,
		DomainGUID: info.DomainGuid.String(),
		AddressType: ControllerAddressType(
			info.DomainControllerAddressType,
		),
		NativeFlags: info.Flags,
	}
	var failures []error
	read := func(ptr *uint16, name string, required bool) *string {
		value, err := InternalCopyDiscoveryText(ptr)
		if err != nil || (required && (value == nil || *value == "")) {
			failures = append(failures, fmt.Errorf("%w: invalid %s", ErrInvalidNativeResult, name))
		}
		return value
	}
	if value := read(info.DomainControllerName, "controller name", true); value != nil {
		result.ControllerName = *value
	}
	if value := read(info.DomainControllerAddress, "controller address", true); value != nil {
		result.ControllerAddress = *value
	}
	if value := read(info.DomainName, "domain name", true); value != nil {
		result.DomainName = *value
	}
	result.ForestName = read(info.DnsForestName, "forest name", false)
	result.DCSiteName = read(info.DcSiteName, "DC site name", false)
	result.ClientSiteName = read(info.ClientSiteName, "client site name", false)
	for service, flag := range map[DCServices]uint32{
		ServicePrimaryDC: activedirectory.DS_PDC_FLAG, ServiceGlobalCatalog: activedirectory.DS_GC_FLAG,
		ServiceKDC: activedirectory.DS_KDC_FLAG, ServiceTime: activedirectory.DS_TIMESERV_FLAG, ServiceADWS: activedirectory.DS_WS_FLAG,
	} {
		if info.Flags&flag != 0 {
			result.Services |= service
		}
	}
	result.Writable = info.Flags&activedirectory.DS_WRITABLE_FLAG != 0
	result.ReadOnly = info.Flags&activedirectory.DS_SELECT_SECRET_DOMAIN_6_FLAG != 0
	result.ReliableTimeService = info.Flags&activedirectory.DS_GOOD_TIMESERV_FLAG != 0
	if info.Flags&activedirectory.DS_DS_FLAG == 0 ||
		result.Services&requested.Services != requested.Services ||
		(requested.Writable && !result.Writable) {
		failures = append(
			failures,
			fmt.Errorf("%w: locator returned incompatible service flags", ErrInvalidNativeResult),
		)
	}
	if requested.PreferReliableTimeService && !result.ReliableTimeService &&
		result.Services&ServiceTime == 0 {
		failures = append(
			failures,
			fmt.Errorf(
				"%w: locator returned neither a reliable nor an ordinary time server",
				ErrInvalidNativeResult,
			),
		)
	}
	return result, errors.Join(failures...)
}

// Native pointers are borrowed only while their parent allocation is owned.
// The bound prevents an unterminated string from becoming an unbounded scan.
func InternalCopyDiscoveryText(ptr *uint16) (*string, error) {
	if ptr == nil {
		return nil, nil
	}
	units := make([]uint16, 0, 128)
	for index := 0; index < 32768; index++ {
		unit := *(*uint16)(unsafe.Add(unsafe.Pointer(ptr), index*2))
		if unit == 0 {
			value, err := InternalDecodeDiscoveryUTF16(units)
			return &value, err
		}
		units = append(units, unit)
	}
	return nil, ErrInvalidNativeResult
}

func InternalDecodeDiscoveryUTF16(units []uint16) (string, error) {
	for index := 0; index < len(units); index++ {
		unit := units[index]
		if unit >= 0xD800 && unit <= 0xDBFF {
			index++
			if index == len(units) || units[index] < 0xDC00 || units[index] > 0xDFFF {
				return "", ErrInvalidNativeResult
			}
		} else if unit >= 0xDC00 && unit <= 0xDFFF {
			return "", ErrInvalidNativeResult
		}
	}
	return string(utf16.Decode(units)), nil
}

func InternalCurrentDomainNative(ctx context.Context, mode CurrentMode) (DomainName, error) {
	return InternalCurrentDomainWithAPI(ctx, mode, InternalSystemDiscoveryAPI())
}

func InternalCurrentDomainWithAPI(
	ctx context.Context,
	mode CurrentMode,
	api InternalDiscoveryAPI,
) (result DomainName, err error) {
	if mode != CurrentLocalComputer && mode != CurrentLoggedOnUser {
		return result, ErrInvalidDiscovery
	}
	if err = context.Cause(ctx); err != nil {
		return result, err
	}
	defer func() { err = errors.Join(err, context.Cause(ctx)) }()
	if mode == CurrentLoggedOnUser {
		if err = api.InternalAvailable(identity.Procs.GetUserNameEx); err != nil {
			return result, err
		}
		// Keep resize retries on the same calling security identity. Callers that
		// establish impersonation must already be locked to their intended thread.
		runtime.LockOSThread()
		defer runtime.UnlockOSThread()
		return InternalCurrentUserDomain(ctx, api)
	}
	if err = api.InternalAvailable(
		netmanagement.Procs.NetGetJoinInformation,
		netmanagement.Procs.NetApiBufferFree,
	); err != nil {
		return result, err
	}
	if err = context.Cause(ctx); err != nil {
		return result, err
	}
	var owner foundation.PWSTR
	var status netmanagement.NETSETUP_JOIN_STATUS
	code := api.InternalJoinInfo(nil, &owner, &status)
	defer func() {
		if owner != nil {
			err = errors.Join(
				err,
				InternalNativeStatus("NetApiBufferFree", api.InternalFree(unsafe.Pointer(owner))),
			)
		}
	}()
	if code != 0 {
		return result, InternalNativeStatus("NetGetJoinInformation", code)
	}
	if status != netmanagement.NetSetupDomainName {
		if status >= netmanagement.NetSetupUnknownStatus &&
			status <= netmanagement.NetSetupWorkgroupName {
			return result, ErrNoCurrentDomain
		}
		return result, fmt.Errorf("%w: unknown join status", ErrInvalidNativeResult)
	}
	name, err := InternalCopyDiscoveryText(owner)
	if err != nil || name == nil {
		return result, ErrInvalidNativeResult
	}
	result = DomainName{Name: *name, Format: DomainNameNetBIOS}
	if InternalDomainNameValidate(result) != nil {
		return DomainName{}, fmt.Errorf("%w: invalid joined domain name", ErrInvalidNativeResult)
	}
	return result, nil
}

func InternalCurrentUserDomain(ctx context.Context, api InternalDiscoveryAPI) (DomainName, error) {
	buffer := make([]uint16, 256)
	for attempt := 0; attempt < 4; attempt++ {
		if err := context.Cause(ctx); err != nil {
			return DomainName{}, err
		}
		size := uint32(len(buffer))
		ok, callErr := api.InternalUserName(identity.NameDnsDomain, &buffer[0], &size)
		if ok != 0 {
			// GetLastError is undefined on success; the generated wrapper may
			// return that stale error even though the Boolean says it succeeded.
			if size == 0 || size >= uint32(len(buffer)) || buffer[size] != 0 {
				return DomainName{}, ErrInvalidNativeResult
			}
			value, err := InternalDecodeDiscoveryUTF16(buffer[:size])
			if err != nil {
				return DomainName{}, err
			}
			domain, account, found := strings.Cut(value, `\`)
			result := DomainName{Name: domain, Format: DomainNameDNS}
			if !found || account == "" || strings.ContainsAny(account, "\\\x00") ||
				InternalDomainNameValidate(result) != nil {
				return DomainName{}, fmt.Errorf(
					"%w: invalid current user domain name",
					ErrInvalidNativeResult,
				)
			}
			return result, nil
		}
		if errors.Is(callErr, win32.Errno(foundation.ERROR_MORE_DATA)) {
			if size <= uint32(len(buffer)) || size > 32768 {
				return DomainName{}, ErrInvalidNativeResult
			}
			buffer = make([]uint16, size)
			continue
		}
		var code win32.Errno
		if errors.As(callErr, &code) && code != 0 {
			err := InternalNativeStatus("GetUserNameExW", uint32(code))
			if code == win32.Errno(foundation.ERROR_NONE_MAPPED) {
				err = errors.Join(ErrNoCurrentDomain, err)
			}
			return DomainName{}, err
		}
		return DomainName{}, errors.Join(ErrInvalidNativeResult, callErr)
	}
	return DomainName{}, fmt.Errorf(
		"%w: current user name did not stabilize",
		ErrInvalidNativeResult,
	)
}
