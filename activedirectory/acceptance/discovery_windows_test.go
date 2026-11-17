//go:build windows && (amd64 || arm64)

package acceptance

import (
	"context"
	"errors"
	"testing"
	"unicode/utf16"
	"unsafe"

	"github.com/deploymenttheory/go-bindings-win32/bindings/runtime/win32"
	"github.com/deploymenttheory/go-bindings-win32/bindings/win32/foundation"
	"github.com/deploymenttheory/go-bindings-win32/bindings/win32/networking/activedirectory"
	"github.com/deploymenttheory/go-bindings-win32/bindings/win32/networkmanagement/netmanagement"
	"github.com/deploymenttheory/go-bindings-win32/bindings/win32/security/authentication/identity"
	admodel "github.com/deploymenttheory/go-sdk-activedirectory/activedirectory/internal/model"
)

func TestDiscoveryNativeFlagMappings(t *testing.T) {
	const base = uint32(0x40000010)
	cases := []struct {
		InternalName    string
		InternalOptions admodel.DiscoveryOptions
		InternalWant    uint32
	}{
		{"default", admodel.DiscoveryOptions{}, base},
		{
			"dns",
			admodel.DiscoveryOptions{Domain: &admodel.DomainName{Name: "ad.test"}},
			base | 0x20000,
		},
		{
			"flat",
			admodel.DiscoveryOptions{
				Domain: &admodel.DomainName{Name: "AD", Format: admodel.DomainNameNetBIOS},
			},
			base | 0x10000,
		},
		{"pdc", admodel.DiscoveryOptions{Services: admodel.ServicePrimaryDC}, base | 0x80},
		{"gc", admodel.DiscoveryOptions{Services: admodel.ServiceGlobalCatalog}, base | 0x40},
		{"kdc", admodel.DiscoveryOptions{Services: admodel.ServiceKDC}, base | 0x400},
		{"time", admodel.DiscoveryOptions{Services: admodel.ServiceTime}, base | 0x800},
		{"adws", admodel.DiscoveryOptions{Services: admodel.ServiceADWS}, base | 0x100000},
		{
			"reliable-preference",
			admodel.DiscoveryOptions{PreferReliableTimeService: true},
			base | 0x2000,
		},
		{"writable", admodel.DiscoveryOptions{Writable: true}, base | 0x1000},
		{"avoid-self", admodel.DiscoveryOptions{AvoidSelf: true}, base | 0x4000},
		{"force", admodel.DiscoveryOptions{ForceDiscover: true}, base | 1},
		{"next-site", admodel.DiscoveryOptions{NextClosestSite: true}, base | 0x40000},
		{
			"2008",
			admodel.DiscoveryOptions{MinimumVersion: admodel.DirectoryServiceWindows2008},
			0x40080000,
		},
		{
			"2012",
			admodel.DiscoveryOptions{MinimumVersion: admodel.DirectoryServiceWindows2012},
			0x40200000,
		},
		{
			"2012r2",
			admodel.DiscoveryOptions{MinimumVersion: admodel.DirectoryServiceWindows2012R2},
			0x40400000,
		},
		{
			"2016",
			admodel.DiscoveryOptions{MinimumVersion: admodel.DirectoryServiceWindows2016},
			0x40800000,
		},
	}
	for _, tc := range cases {
		t.Run(tc.InternalName, func(t *testing.T) {
			if err := tc.InternalOptions.Validate(); err != nil {
				t.Fatal(err)
			}
			if got := admodel.InternalDiscoveryFlags(tc.InternalOptions); got != tc.InternalWant {
				t.Fatalf("flags = %#x, want %#x", got, tc.InternalWant)
			}
		})
	}
}

func InternalFixtureController() *activedirectory.DOMAIN_CONTROLLER_INFOW {
	return &activedirectory.DOMAIN_CONTROLLER_INFOW{
		DomainControllerName: win32.UTF16Ptr(
			`\\dc1.ad.sdk.test`,
		),
		DomainControllerAddress:     win32.UTF16Ptr(`\\10.77.23.10`),
		DomainControllerAddressType: 1,
		DomainGuid:                  win32.GUID{Data1: 1},
		DomainName:                  win32.UTF16Ptr("ad.sdk.test"),
		DnsForestName:               win32.UTF16Ptr("ad.sdk.test"),
		DcSiteName:                  win32.UTF16Ptr("London 研发 🐉"),
		Flags:                       activedirectory.DS_DS_FLAG | activedirectory.DS_DNS_CONTROLLER_FLAG | activedirectory.DS_DNS_DOMAIN_FLAG,
	}
}

func TestDiscoveryMinimumVersionUsesExclusiveNativeRequirement(t *testing.T) {
	// MS-NRPC 3.5.4.3.1 rejects combinations of directory-service flags
	// B, Q, U, V and W with ERROR_INVALID_FLAGS (1004). The Server 2025
	// cloning probe reproduced this for a forced Windows 2012 PDC lookup.
	const requirements = uint32(0x10 | 0x80000 | 0x200000 | 0x400000 | 0x800000)
	for _, tc := range []struct {
		InternalName    string
		InternalVersion admodel.DirectoryServiceVersion
		InternalFlag    uint32
	}{
		{"default", 0, 0x10},
		{"2008", admodel.DirectoryServiceWindows2008, 0x80000},
		{"2012", admodel.DirectoryServiceWindows2012, 0x200000},
		{"2012r2", admodel.DirectoryServiceWindows2012R2, 0x400000},
		{"2016", admodel.DirectoryServiceWindows2016, 0x800000},
	} {
		t.Run(tc.InternalName, func(t *testing.T) {
			options := admodel.DiscoveryOptions{
				Services:       admodel.ServicePrimaryDC,
				MinimumVersion: tc.InternalVersion,
				ForceDiscover:  true,
			}
			calls, frees := 0, 0
			api := admodel.InternalDiscoveryAPI{
				InternalFind: func(*win32.Proc) error { return nil },
				InternalGetDC: func(_ *string, _ *string, _ *win32.GUID, _ *string, flags uint32, out **activedirectory.DOMAIN_CONTROLLER_INFOW) uint32 {
					calls++
					selected := flags & requirements
					if selected != 0 && selected&(selected-1) != 0 {
						return 1004
					}
					if selected != tc.InternalFlag || flags&0x40000081 != 0x40000081 {
						t.Fatalf(
							"locator lost minimum version, PDC, forced discovery or DNS result requirement: %#x",
							flags,
						)
					}
					*out = InternalFixtureController()
					(*out).Flags |= activedirectory.DS_PDC_FLAG
					return 0
				},
				InternalFree: func(unsafe.Pointer) uint32 { frees++; return 0 },
			}
			result, err := admodel.InternalDiscoverWithAPI(context.Background(), options, api)
			if err != nil {
				t.Fatalf("minimum-version PDC discovery failed: %v", err)
			}
			if calls != 1 || frees != 1 || result.ControllerName != `\\dc1.ad.sdk.test` ||
				result.Requested.MinimumVersion != tc.InternalVersion {
				t.Fatalf(
					"discovery result or allocation ownership lost: %#v; calls=%d frees=%d",
					result,
					calls,
					frees,
				)
			}
		})
	}
}

func TestDiscoveryCopiesAndReleasesEveryOwner(t *testing.T) {
	for _, failure := range []string{"none", "native", "native-and-free", "free", "null", "malformed", "canceled"} {
		t.Run(failure, func(t *testing.T) {
			ctx, cancel := context.WithCancel(context.Background())
			defer cancel()
			owner := InternalFixtureController()
			if failure == "malformed" {
				owner.DcSiteName = &[]uint16{0xD800, 0}[0]
			}
			frees := 0
			api := admodel.InternalDiscoveryAPI{
				InternalFind: func(*win32.Proc) error { return nil },
				InternalGetDC: func(computer, domain *string, guid *win32.GUID, site *string, flags uint32, out **activedirectory.DOMAIN_CONTROLLER_INFOW) uint32 {
					if computer != nil || domain != nil || guid != nil || site != nil ||
						flags != 0x40000010 {
						t.Fatal("implicit discovery changed its inputs")
					}
					if failure == "null" {
						return 0
					}
					*out = owner
					if failure == "canceled" {
						cancel()
					}
					if failure == "native" || failure == "native-and-free" {
						return 1355
					}
					return 0
				},
				InternalFree: func(ptr unsafe.Pointer) uint32 {
					if ptr != unsafe.Pointer(owner) {
						t.Fatal("freed a child instead of the parent owner")
					}
					frees++
					*owner.DomainControllerName = 'X'
					*owner.DomainName = 'Y'
					if failure == "free" || failure == "native-and-free" {
						return 87
					}
					return 0
				},
			}
			result, err := admodel.InternalDiscoverWithAPI(ctx, admodel.DiscoveryOptions{}, api)
			wantFrees := 1
			if failure == "null" {
				wantFrees = 0
			}
			if frees != wantFrees {
				t.Fatalf("frees = %d", frees)
			}
			if failure == "none" {
				if err != nil || result.ControllerName != `\\dc1.ad.sdk.test` ||
					result.DomainName != "ad.sdk.test" ||
					result.DCSiteName == nil ||
					*result.DCSiteName != "London 研发 🐉" ||
					result.ClientSiteName != nil {
					t.Fatalf("copied result: %#v, %v", result, err)
				}
			} else if err == nil {
				t.Fatal("lost failure")
			}
			if (failure == "native" || failure == "native-and-free") &&
				!InternalHasNativeStatus(err, 1355) {
				t.Fatalf("lost native status: %v", err)
			}
			if (failure == "free" || failure == "native-and-free") &&
				!InternalHasNativeStatus(err, 87) {
				t.Fatalf("lost free status: %v", err)
			}
			if failure == "canceled" && !errors.Is(err, context.Canceled) {
				t.Fatal(err)
			}
			if (failure == "null" || failure == "malformed") &&
				!errors.Is(err, admodel.ErrInvalidNativeResult) {
				t.Fatal(err)
			}
		})
	}
}

func InternalHasNativeStatus(err error, code uint32) bool {
	if err == nil {
		return false
	}
	if native, ok := err.(*admodel.NativeStatusError); ok {
		return native.Code == code
	}
	if joined, ok := err.(interface{ Unwrap() []error }); ok {
		for _, child := range joined.Unwrap() {
			if InternalHasNativeStatus(child, code) {
				return true
			}
		}
	}
	return InternalHasNativeStatus(errors.Unwrap(err), code)
}

func TestDiscoveryRequiredServicesAndPreferenceFallback(t *testing.T) {
	info := InternalFixtureController()
	info.Flags |= activedirectory.DS_TIMESERV_FLAG | activedirectory.DS_SELECT_SECRET_DOMAIN_6_FLAG | 0x80000000
	result, err := admodel.InternalDecodeDiscoveredController(
		info,
		admodel.DiscoveryOptions{PreferReliableTimeService: true},
	)
	if err != nil || result.ReliableTimeService || !result.ReadOnly ||
		result.NativeFlags&0x80000000 == 0 {
		t.Fatalf("fallback: %#v, %v", result, err)
	}
	for _, options := range []admodel.DiscoveryOptions{{Writable: true}, {Services: admodel.ServiceGlobalCatalog}, {Services: admodel.ServiceADWS}} {
		if _, err := admodel.InternalDecodeDiscoveredController(
			info,
			options,
		); !errors.Is(
			err,
			admodel.ErrInvalidNativeResult,
		) {
			t.Fatal("missing requirement accepted", err)
		}
	}
	info.ClientSiteName = win32.UTF16Ptr("")
	result, err = admodel.InternalDecodeDiscoveredController(info, admodel.DiscoveryOptions{})
	if err != nil || result.ClientSiteName == nil || *result.ClientSiteName != "" {
		t.Fatal("empty optional value lost presence", err)
	}
}

func TestDiscoveryPreflightsAndRejectsBeforeAllocation(t *testing.T) {
	api := admodel.InternalDiscoveryAPI{
		InternalFind: func(*win32.Proc) error { return errors.New("missing export") },
	}
	if _, err := admodel.InternalDiscoverWithAPI(
		context.Background(),
		admodel.DiscoveryOptions{},
		api,
	); !errors.Is(
		err,
		admodel.ErrUnsupported,
	) {
		t.Fatal(err)
	}
	if _, err := admodel.InternalDiscoverWithAPI(
		context.Background(),
		admodel.DiscoveryOptions{Services: 128},
		admodel.InternalDiscoveryAPI{},
	); !errors.Is(
		err,
		admodel.ErrInvalidDiscovery,
	) {
		t.Fatal(err)
	}
	for _, mode := range []admodel.CurrentMode{admodel.CurrentLocalComputer, admodel.CurrentLoggedOnUser} {
		if _, err := admodel.InternalCurrentDomainWithAPI(
			context.Background(),
			mode,
			api,
		); !errors.Is(
			err,
			admodel.ErrUnsupported,
		) {
			t.Fatal(err)
		}
	}
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	if _, err := admodel.InternalDiscoverWithAPI(
		ctx,
		admodel.DiscoveryOptions{},
		admodel.InternalDiscoveryAPI{},
	); !errors.Is(
		err,
		context.Canceled,
	) {
		t.Fatal(err)
	}
	if _, err := admodel.InternalCurrentDomainWithAPI(
		ctx,
		admodel.CurrentLocalComputer,
		admodel.InternalDiscoveryAPI{},
	); !errors.Is(
		err,
		context.Canceled,
	) {
		t.Fatal(err)
	}
}

func TestDiscoveryPreservesNamesOutsideConnectionHostSyntax(t *testing.T) {
	info := InternalFixtureController()
	info.DomainControllerName = win32.UTF16Ptr(`\\dc1.研发.test`)
	result, err := admodel.InternalDecodeDiscoveredController(info, admodel.DiscoveryOptions{})
	if err != nil || result.ControllerName != `\\dc1.研发.test` {
		t.Fatalf("native name was lost: %#v, %v", result, err)
	}
	if _, err := result.Endpoint(); !errors.Is(err, admodel.ErrInvalidNativeResult) {
		t.Fatal("connection hostname rules were bypassed", err)
	}
}

func TestDiscoveryForwardsExplicitDomainAndSiteWithoutRemoteProcessing(t *testing.T) {
	domain := admodel.DomainName{Name: "AD", Format: admodel.DomainNameNetBIOS}
	options := admodel.DiscoveryOptions{Domain: &domain, SiteName: "London 🐉"}
	frees := 0
	api := admodel.InternalDiscoveryAPI{
		InternalFind: func(*win32.Proc) error { return nil },
		InternalGetDC: func(computer, gotDomain *string, guid *win32.GUID, site *string, flags uint32, out **activedirectory.DOMAIN_CONTROLLER_INFOW) uint32 {
			if computer != nil || guid != nil || gotDomain == nil || *gotDomain != "AD" ||
				site == nil ||
				*site != options.SiteName ||
				flags != 0x40010010 {
				t.Fatal("explicit options were lost or changed to remote locator processing")
			}
			*out = InternalFixtureController()
			return 0
		},
		InternalFree: func(unsafe.Pointer) uint32 { frees++; return 0 },
	}
	result, err := admodel.InternalDiscoverWithAPI(context.Background(), options, api)
	domain.Name = "CHANGED"
	if err != nil || frees != 1 || result.Requested.Domain.Name != "AD" ||
		result.Requested.SiteName != options.SiteName {
		t.Fatalf("request was not retained independently: %#v, %v", result, err)
	}
}

func TestCurrentComputerDomainOwnsJoinResult(t *testing.T) {
	for _, status := range []netmanagement.NETSETUP_JOIN_STATUS{netmanagement.NetSetupUnknownStatus, netmanagement.NetSetupUnjoined, netmanagement.NetSetupWorkgroupName, netmanagement.NetSetupDomainName, 255} {
		frees := 0
		owner := win32.UTF16Ptr("EXAMPLE")
		api := admodel.InternalDiscoveryAPI{
			InternalFind: func(*win32.Proc) error { return nil },
			InternalJoinInfo: func(server *string, out *foundation.PWSTR, got *netmanagement.NETSETUP_JOIN_STATUS) uint32 {
				if server != nil {
					t.Fatal("local context used a remote server")
				}
				*out, *got = owner, status
				return 0
			},
			InternalFree: func(ptr unsafe.Pointer) uint32 {
				if ptr != unsafe.Pointer(owner) {
					t.Fatal("wrong owner")
				}
				frees++
				*owner = 'X'
				return 0
			},
		}
		result, err := admodel.InternalCurrentDomainWithAPI(
			context.Background(),
			admodel.CurrentLocalComputer,
			api,
		)
		if frees != 1 {
			t.Fatal("join buffer leaked")
		}
		if status == netmanagement.NetSetupDomainName {
			if err != nil || result.Name != "EXAMPLE" ||
				result.Format != admodel.DomainNameNetBIOS {
				t.Fatalf("domain: %#v, %v", result, err)
			}
		} else if status == 255 {
			if !errors.Is(err, admodel.ErrInvalidNativeResult) {
				t.Fatal(err)
			}
		} else if !errors.Is(err, admodel.ErrNoCurrentDomain) {
			t.Fatal(err)
		}
	}
}

func TestCurrentComputerDomainPreservesNativeAndCleanupFailures(t *testing.T) {
	owner := win32.UTF16Ptr("EXAMPLE")
	frees := 0
	api := admodel.InternalDiscoveryAPI{
		InternalFind: func(*win32.Proc) error { return nil },
		InternalJoinInfo: func(_ *string, out *foundation.PWSTR, _ *netmanagement.NETSETUP_JOIN_STATUS) uint32 {
			*out = owner
			return 5
		},
		InternalFree: func(unsafe.Pointer) uint32 { frees++; return 87 },
	}
	_, err := admodel.InternalCurrentDomainWithAPI(
		context.Background(),
		admodel.CurrentLocalComputer,
		api,
	)
	if frees != 1 || !InternalHasNativeStatus(err, 5) || !InternalHasNativeStatus(err, 87) {
		t.Fatalf("lost error/owner: %v, %d", err, frees)
	}
}

func TestCurrentUserDomainResizesAndIgnoresStaleSuccessError(t *testing.T) {
	calls := 0
	api := admodel.InternalDiscoveryAPI{
		InternalFind: func(*win32.Proc) error { return nil },
		InternalUserName: func(format identity.EXTENDED_NAME_FORMAT, out foundation.PWSTR, size *uint32) (foundation.BOOLEAN, error) {
			calls++
			if format != identity.NameDnsDomain {
				t.Fatal("resolved a UPN suffix instead of a domain")
			}
			if calls == 1 {
				*size = 400
				return 0, win32.Errno(foundation.ERROR_MORE_DATA)
			}
			if *size != 400 {
				t.Fatal("did not use returned capacity")
			}
			value := append(utf16.Encode([]rune(`ad.sdk.test\研发🐉`)), 0)
			copy(unsafe.Slice(out, int(*size)), value)
			*size = uint32(len(value) - 1)
			return 1, win32.Errno(5)
		},
	}
	result, err := admodel.InternalCurrentDomainWithAPI(
		context.Background(),
		admodel.CurrentLoggedOnUser,
		api,
	)
	if err != nil || result.Name != "ad.sdk.test" || result.Format != admodel.DomainNameDNS ||
		calls != 2 {
		t.Fatalf("domain: %#v, %v", result, err)
	}
}

func TestCurrentUserDomainFailuresStayBounded(t *testing.T) {
	for _, failure := range []string{"local-account", "unavailable", "bad-resize", "oversize", "unstable", "malformed", "bad-length", "missing-error", "canceled"} {
		t.Run(failure, func(t *testing.T) {
			ctx, cancel := context.WithCancel(context.Background())
			defer cancel()
			calls := 0
			api := admodel.InternalDiscoveryAPI{
				InternalFind: func(*win32.Proc) error { return nil },
				InternalUserName: func(_ identity.EXTENDED_NAME_FORMAT, out foundation.PWSTR, size *uint32) (foundation.BOOLEAN, error) {
					calls++
					if calls > 4 {
						t.Fatal("unbounded resize loop")
					}
					switch failure {
					case "local-account":
						return 0, win32.Errno(foundation.ERROR_NONE_MAPPED)
					case "unavailable":
						return 0, win32.Errno(foundation.ERROR_NO_SUCH_DOMAIN)
					case "bad-resize":
						return 0, win32.Errno(foundation.ERROR_MORE_DATA)
					case "oversize":
						*size = 0xFFFFFFFF
						return 0, win32.Errno(foundation.ERROR_MORE_DATA)
					case "unstable":
						*size += 1
						return 0, win32.Errno(foundation.ERROR_MORE_DATA)
					case "malformed":
						*out = 0xD800
						*size = 1
						return 1, nil
					case "bad-length":
						return 1, nil
					case "missing-error":
						return 0, nil
					case "canceled":
						cancel()
						*size = 400
						return 0, win32.Errno(foundation.ERROR_MORE_DATA)
					}
					panic("unknown test")
				},
			}
			_, err := admodel.InternalCurrentDomainWithAPI(ctx, admodel.CurrentLoggedOnUser, api)
			if failure == "local-account" {
				if !errors.Is(err, admodel.ErrNoCurrentDomain) ||
					!InternalHasNativeStatus(err, 1332) {
					t.Fatal(err)
				}
			} else if failure == "unavailable" {
				if !InternalHasNativeStatus(err, 1355) ||
					errors.Is(err, admodel.ErrNoCurrentDomain) {
					t.Fatal(err)
				}
			} else if failure == "canceled" {
				if !errors.Is(err, context.Canceled) {
					t.Fatal(err)
				}
			} else if !errors.Is(err, admodel.ErrInvalidNativeResult) {
				t.Fatal(err)
			}
		})
	}
}

func TestDiscoveryNativeBufferLifetimeAndLayout(t *testing.T) {
	api := admodel.InternalSystemDiscoveryAPI()
	if err := api.InternalAvailable(
		activedirectory.Procs.DsGetDcName,
		netmanagement.Procs.NetApiBufferFree,
		netmanagement.Procs.NetApiBufferAllocate,
		netmanagement.Procs.NetGetJoinInformation,
		identity.Procs.GetUserNameEx,
	); err != nil {
		t.Fatal(err)
	}
	var layout activedirectory.DOMAIN_CONTROLLER_INFOW
	if unsafe.Sizeof(layout) != 80 || unsafe.Offsetof(layout.DomainGuid) != 20 ||
		unsafe.Offsetof(layout.DomainName) != 40 ||
		unsafe.Offsetof(layout.Flags) != 56 {
		t.Fatal("unexpected Win64 DOMAIN_CONTROLLER_INFOW layout")
	}
	allocations, frees := 0, 0
	api.InternalGetDC = func(_ *string, _ *string, _ *win32.GUID, _ *string, _ uint32, out **activedirectory.DOMAIN_CONTROLLER_INFOW) uint32 {
		var buffer unsafe.Pointer
		if status := netmanagement.NetApiBufferAllocate(1024, &buffer); status != 0 {
			return status
		}
		allocations++
		info := (*activedirectory.DOMAIN_CONTROLLER_INFOW)(buffer)
		*info = activedirectory.DOMAIN_CONTROLLER_INFOW{Flags: activedirectory.DS_DS_FLAG}
		offset := unsafe.Sizeof(*info)
		put := func(value string) *uint16 {
			units := append(utf16.Encode([]rune(value)), 0)
			ptr := (*uint16)(unsafe.Add(buffer, offset))
			copy(unsafe.Slice(ptr, len(units)), units)
			offset += uintptr(len(units) * 2)
			return ptr
		}
		info.DomainControllerName = put(`\\dc1.ad.sdk.test`)
		info.DomainControllerAddress = put(`\\10.77.23.10`)
		info.DomainName = put("ad.sdk.test")
		*out = info
		return 0
	}
	free := api.InternalFree
	api.InternalFree = func(owner unsafe.Pointer) uint32 { frees++; return free(owner) }
	for range 20 {
		result, err := admodel.InternalDiscoverWithAPI(
			context.Background(),
			admodel.DiscoveryOptions{},
			api,
		)
		if err != nil || result.DomainName != "ad.sdk.test" ||
			result.ControllerName != `\\dc1.ad.sdk.test` {
			t.Fatalf("native result: %#v, %v", result, err)
		}
	}
	if allocations != 20 || frees != allocations {
		t.Fatalf("allocated %d, freed %d", allocations, frees)
	}
}
