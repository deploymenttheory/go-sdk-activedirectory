//go:build windows && (amd64 || arm64)

package dccloning

import (
	"context"
	"encoding/binary"
	"encoding/json"
	"errors"
	"os"
	"reflect"
	"syscall"
	"testing"
	"unicode/utf16"
	"unsafe"

	"github.com/deploymenttheory/go-bindings-win32/bindings/runtime/win32"
	"github.com/deploymenttheory/go-bindings-win32/bindings/win32/foundation"
	ad "github.com/deploymenttheory/go-bindings-win32/bindings/win32/networking/activedirectory"
	"github.com/deploymenttheory/go-bindings-win32/bindings/win32/system/registry"
	"github.com/deploymenttheory/go-bindings-win32/bindings/win32/system/services"
)

func TestRoleAllocationAlwaysFreed(t *testing.T) {
	for _, status := range []uint32{0, 5} {
		info := ad.DSROLE_PRIMARY_DOMAIN_INFO_BASIC{MachineRole: ad.DsRole_RoleBackupDomainController, Flags: ad.DSROLE_PRIMARY_DS_READONLY}
		frees := 0
		api := nativeAPI{getRole: func(server *string, level ad.DSROLE_PRIMARY_DOMAIN_INFO_LEVEL, out **byte) uint32 {
			if server != nil || level != ad.DsRolePrimaryDomainInfoBasic {
				t.Fatal("not local basic role")
			}
			*out = (*byte)(unsafe.Pointer(&info))
			return status
		}, freeRole: func(p unsafe.Pointer) {
			if p != unsafe.Pointer(&info) {
				t.Fatal("wrong allocation")
			}
			frees++
		}}
		role, err := (nativeMachine{api}).role(context.Background())
		if frees != 1 {
			t.Fatalf("free count %d", frees)
		}
		if status == 0 && (err != nil || role.MachineRole != 4 || !role.ReadOnly) {
			t.Fatalf("role %#v %v", role, err)
		}
		if status != 0 {
			var native *NativeError
			if !errors.As(err, &native) || native.Code != status {
				t.Fatalf("status lost: %v", err)
			}
		}
	}
}

func putService(buffer []byte, name string) {
	row := (*services.ENUM_SERVICE_STATUS_PROCESSW)(unsafe.Pointer(&buffer[0]))
	offset := int(unsafe.Sizeof(*row))
	words := utf16.Encode([]rune(name))
	words = append(words, 0)
	for i, w := range words {
		binary.LittleEndian.PutUint16(buffer[offset+i*2:], w)
	}
	row.LpServiceName = (*uint16)(unsafe.Pointer(&buffer[offset]))
}

func TestSCMPagesPartialFailureAndCleanup(t *testing.T) {
	for _, failSecond := range []bool{false, true} {
		calls, closed := 0, 0
		closeError := errors.New("close failed")
		api := nativeAPI{
			openSCM: func(host, database *string, rights uint32) (services.SC_HANDLE, error) {
				if host != nil || database != nil || rights != services.SC_MANAGER_ENUMERATE_SERVICE {
					t.Fatal("SCM arguments")
				}
				return 42, nil
			},
			closeSCM: func(h services.SC_HANDLE) error {
				if h != 42 {
					t.Fatal("wrong handle")
				}
				closed++
				if failSecond {
					return closeError
				}
				return nil
			},
			enumServices: func(h services.SC_HANDLE, level services.SC_ENUM_TYPE, kind services.ENUM_SERVICE_TYPE, state services.ENUM_SERVICE_STATE, b []byte, needed, count, resume *uint32, group *string) error {
				if state != services.SERVICE_STATE_ALL || kind != services.SERVICE_WIN32 || group != nil {
					t.Fatal("enumeration filters")
				}
				calls++
				if calls == 1 {
					putService(b, "first")
					*count = 1
					*resume = 7
					*needed = uint32(len(b))
					return syscall.ERROR_MORE_DATA
				}
				if *resume != 7 {
					t.Fatal("resume discarded")
				}
				if failSecond {
					return syscall.ERROR_ACCESS_DENIED
				}
				putService(b, "second")
				*count = 1
				*resume = 0
				return nil
			},
		}
		entries, err := (nativeMachine{api}).serviceInventory(context.Background())
		if closed != 1 || calls != 2 {
			t.Fatalf("lifetime calls=%d close=%d", calls, closed)
		}
		if failSecond {
			if len(entries) != 1 || !errors.Is(err, syscall.ERROR_ACCESS_DENIED) || !errors.Is(err, closeError) {
				t.Fatalf("partial %#v %v", entries, err)
			}
		} else if len(entries) != 2 || err != nil {
			t.Fatalf("pages %#v %v", entries, err)
		}
	}
}

func TestSCMRejectsOutOfBoundsPointersAndCounts(t *testing.T) {
	buffer := make([]byte, 128)
	putService(buffer, "valid")
	if _, err := servicePage(buffer, 100); !errors.Is(err, ErrIncomplete) {
		t.Fatal(err)
	}
	row := (*services.ENUM_SERVICE_STATUS_PROCESSW)(unsafe.Pointer(&buffer[0]))
	outside := uint16(0)
	row.LpServiceName = &outside
	if _, err := servicePage(buffer, 1); !errors.Is(err, ErrIncomplete) {
		t.Fatal(err)
	}
	row.LpServiceName = (*uint16)(unsafe.Pointer(&buffer[126]))
	buffer[126] = 'x'
	buffer[127] = 0
	if _, err := servicePage(buffer, 1); !errors.Is(err, ErrIncomplete) {
		t.Fatal(err)
	}
}

func TestRegistryGrowthLengthTypeAndStatus(t *testing.T) {
	for _, kind := range []registry.REG_VALUE_TYPE{registry.REG_SZ, registry.REG_DWORD} {
		calls := 0
		api := nativeAPI{queryValue: func(key registry.HKEY, name *string, outKind *registry.REG_VALUE_TYPE, data *byte, length *uint32) foundation.WIN32_ERROR {
			calls++
			*outKind = kind
			if calls == 1 {
				*length = 512
				return foundation.ERROR_MORE_DATA
			}
			if *length != 512 {
				t.Fatal("size not reset")
			}
			// The documented API allows non-terminated registry strings.
			copy(unsafe.Slice(data, *length), []byte{'A', 0, 'D', 0})
			*length = 4
			return 0
		}}
		value, present, err := (nativeMachine{api}).registryString(context.Background(), 1, "DisplayName")
		if kind == registry.REG_SZ {
			if value != "AD" || !present || err != nil {
				t.Fatalf("value %q %v %v", value, present, err)
			}
		} else if !errors.Is(err, ErrIncomplete) {
			t.Fatal(err)
		}
	}
	api := nativeAPI{queryValue: func(registry.HKEY, *string, *registry.REG_VALUE_TYPE, *byte, *uint32) foundation.WIN32_ERROR {
		return foundation.ERROR_ACCESS_DENIED
	}}
	_, present, err := (nativeMachine{api}).registryString(context.Background(), 1, "DisplayName")
	if present || !errors.Is(err, syscall.ERROR_ACCESS_DENIED) {
		t.Fatalf("access error %v", err)
	}
}

func TestProgramViewsAndHandleCleanup(t *testing.T) {
	for _, view := range []struct {
		flag registry.REG_SAM_FLAGS
		kind Kind
	}{{registry.KEY_WOW64_64KEY, Program}, {registry.KEY_WOW64_32KEY, WoW64Program}} {
		var closed []registry.HKEY
		api := nativeAPI{
			openKey: func(parent registry.HKEY, name *string, _ uint32, rights registry.REG_SAM_FLAGS, out *registry.HKEY) foundation.WIN32_ERROR {
				if rights&view.flag == 0 {
					t.Fatal("registry view lost")
				}
				if parent == registry.HKEY_LOCAL_MACHINE {
					*out = 1
				} else {
					*out = 2
				}
				return 0
			}, closeKey: func(h registry.HKEY) foundation.WIN32_ERROR { closed = append(closed, h); return 0 },
			enumKey: func(_ registry.HKEY, index uint32, name foundation.PWSTR, length *uint32, _ foundation.PWSTR, _ *uint32, _ *foundation.FILETIME) foundation.WIN32_ERROR {
				if index > 0 {
					return foundation.ERROR_NO_MORE_ITEMS
				}
				copy(unsafe.Slice(name, *length), []uint16{'k', 0})
				*length = 1
				return 0
			}, queryValue: func(_ registry.HKEY, name *string, kind *registry.REG_VALUE_TYPE, data *byte, length *uint32) foundation.WIN32_ERROR {
				if *name != "DisplayName" {
					t.Fatal("unexpected comparison property")
				}
				*kind = registry.REG_SZ
				copy(unsafe.Slice(data, *length), []byte{'A', 0, '&', 0, 0, 0})
				*length = 6
				return 0
			},
		}
		entries, err := (nativeMachine{api}).programs(context.Background(), view.flag, view.kind)
		if err != nil || len(entries) != 1 || entries[0].Name != "A&" || entries[0].Type != view.kind || !reflect.DeepEqual(closed, []registry.HKEY{2, 1}) {
			t.Fatalf("programs %#v cleanup %v err %v", entries, closed, err)
		}
	}
}

func TestMissingExportBeforeAcquisition(t *testing.T) {
	cause := errors.New("missing export")
	api := nativeAPI{find: func(*win32.Proc) error { return cause }}
	if err := api.available(false); !errors.Is(err, ErrUnsupported) || !errors.Is(err, cause) {
		t.Fatal(err)
	}
}

// TestNativeReference is run only by the isolated DC reference harness. The
// report path is explicit and no host/registry/service configuration is changed.
func TestNativeReference(t *testing.T) {
	path := os.Getenv("ADSDK_CLONING_REFERENCE")
	if path == "" {
		t.Skip("isolated DC reference harness supplies output path")
	}
	result, err := Inspect(context.Background())
	report := struct {
		Result Result `json:"result"`
		Error  string `json:"error,omitempty"`
	}{Result: result}
	if err != nil {
		report.Error = err.Error()
	}
	data, marshalErr := json.MarshalIndent(report, "", "  ")
	if marshalErr != nil {
		t.Fatal(marshalErr)
	}
	if writeErr := os.WriteFile(path, data, 0600); writeErr != nil {
		t.Fatal(writeErr)
	}
	if err != nil {
		t.Fatal(err)
	}
}
