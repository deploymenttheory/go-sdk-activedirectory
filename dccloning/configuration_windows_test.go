//go:build windows && (amd64 || arm64)

package dccloning

import (
	"context"
	"errors"
	"os"
	"path/filepath"
	"reflect"
	"strings"
	"syscall"
	"testing"
	"unicode/utf16"
	"unsafe"

	"github.com/deploymenttheory/go-bindings-win32/bindings/win32/foundation"
	"github.com/deploymenttheory/go-bindings-win32/bindings/win32/globalization"
	nativead "github.com/deploymenttheory/go-bindings-win32/bindings/win32/networking/activedirectory"
	"github.com/deploymenttheory/go-bindings-win32/bindings/win32/security"
	"github.com/deploymenttheory/go-bindings-win32/bindings/win32/storage/filesystem"
	"github.com/deploymenttheory/go-bindings-win32/bindings/win32/system/hypervisor"
	nativeio "github.com/deploymenttheory/go-bindings-win32/bindings/win32/system/io"
	"github.com/deploymenttheory/go-bindings-win32/bindings/win32/system/registry"
	"github.com/deploymenttheory/go-bindings-win32/bindings/win32/system/services"
	"github.com/deploymenttheory/go-bindings-win32/bindings/win32/system/systeminformation"
)

func TestCloneGenerationOwnershipAndPolling(t *testing.T) {
	for _, scenario := range []string{"success", "open denied", "invalid handle", "control denied", "short output", "long output", "close failed", "cancel before", "cancel after open", "cancel after control"} {
		t.Run(scenario, func(t *testing.T) {
			ctx, cancel := context.WithCancel(context.Background())
			defer cancel()
			opened, controlled, closed := 0, 0, 0
			api := configNativeAPI{
				open: func(path string, access uint32, share filesystem.FILE_SHARE_MODE, attributes *security.SECURITY_ATTRIBUTES, disposition filesystem.FILE_CREATION_DISPOSITION, flags filesystem.FILE_FLAGS_AND_ATTRIBUTES, template foundation.HANDLE) (foundation.HANDLE, error) {
					opened++
					if path != `\\.\VmGenerationCounter` || access != uint32(foundation.GENERIC_READ|foundation.GENERIC_WRITE) || share != filesystem.FILE_SHARE_READ|filesystem.FILE_SHARE_WRITE || attributes != nil || disposition != filesystem.OPEN_EXISTING || flags != filesystem.FILE_ATTRIBUTE_NORMAL || template != 0 {
						t.Fatal("invalid device open contract")
					}
					if scenario == "open denied" {
						return 0, syscall.ERROR_ACCESS_DENIED
					}
					if scenario == "invalid handle" {
						return ^foundation.HANDLE(0), nil
					}
					if scenario == "cancel after open" {
						cancel()
					}
					return 42, nil
				},
				control: func(handle foundation.HANDLE, code uint32, in, out []byte, returned *uint32, overlap *nativeio.OVERLAPPED) error {
					controlled++
					if handle != 42 || code != hypervisor.IOCTL_VMGENCOUNTER_READ || len(in) != 0 || len(out) != 16 || overlap != nil {
						t.Fatal("not a bounded polling read")
					}
					if scenario == "control denied" {
						return syscall.ERROR_ACCESS_DENIED
					}
					*returned = 16
					if scenario == "short output" {
						*returned = 15
					}
					if scenario == "long output" {
						*returned = 17
					}
					if scenario == "cancel after control" {
						cancel()
					}
					return nil
				},
				close: func(handle foundation.HANDLE) error {
					closed++
					if handle != 42 {
						t.Fatal("wrong handle")
					}
					if scenario == "close failed" {
						return syscall.ERROR_ACCESS_DENIED
					}
					return nil
				},
			}
			if scenario == "cancel before" {
				cancel()
			}
			available, err := readCloneGeneration(ctx, api)
			if scenario == "success" {
				if err != nil || !available {
					t.Fatalf("%v/%v", available, err)
				}
			} else if err == nil {
				t.Fatal("failure reported success")
			}
			if scenario == "open denied" || scenario == "control denied" || scenario == "close failed" {
				var native *NativeError
				if !errors.As(err, &native) || native.Code != 5 {
					t.Fatalf("lost native code: %v", err)
				}
			}
			wantClosed := 1
			if scenario == "open denied" || scenario == "invalid handle" || scenario == "cancel before" {
				wantClosed = 0
			}
			if closed != wantClosed || opened > 1 || controlled > 1 {
				t.Fatalf("calls open=%d control=%d close=%d", opened, controlled, closed)
			}
		})
	}
}

func TestCloneHostNameBoundedNativeDecoding(t *testing.T) {
	for _, scenario := range []string{"success", "grow", "huge", "empty", "invalid UTF16", "embedded NUL", "full buffer", "native error"} {
		t.Run(scenario, func(t *testing.T) {
			calls := 0
			call := func(kind systeminformation.COMPUTER_NAME_FORMAT, buffer foundation.PWSTR, size *uint32) error {
				calls++
				if kind != systeminformation.ComputerNameDnsFullyQualified {
					t.Fatal("wrong hostname format")
				}
				if scenario == "grow" && calls == 1 {
					*size = 300
					return syscall.ERROR_MORE_DATA
				}
				if scenario == "huge" {
					*size = 4097
					return syscall.ERROR_MORE_DATA
				}
				if scenario == "native error" {
					return syscall.ERROR_ACCESS_DENIED
				}
				words := utf16.Encode([]rune("dc.example.test"))
				if scenario == "invalid UTF16" {
					words = []uint16{0xd800}
				}
				if scenario == "embedded NUL" {
					words = []uint16{'d', 0, 'c'}
				}
				if scenario == "empty" {
					*size = 0
					return nil
				}
				if scenario == "full buffer" {
					return nil
				}
				copy(unsafe.Slice(buffer, *size), append(words, 0))
				*size = uint32(len(words))
				return nil
			}
			host, err := cloneHostName(context.Background(), call)
			if scenario == "success" || scenario == "grow" {
				if err != nil || host != "dc.example.test" {
					t.Fatalf("%q/%v", host, err)
				}
			} else if err == nil {
				t.Fatalf("accepted malformed output %q", host)
			}
			if calls > 2 {
				t.Fatalf("unbounded calls %d", calls)
			}
		})
	}
}

func TestCloneConfigLocationsExcludeAllowListFolder(t *testing.T) {
	machine, state := locationFixture(t)
	environment := nativeConfigEnvironment{nativeMachine: machine.native}
	dirs, err := environment.configDirectories(context.Background())
	want := []string{state.dsa, filepath.Join(filepath.Dir(state.dsa), "NTDS"), state.first, state.last}
	if err != nil || !reflect.DeepEqual(dirs, want) || state.opened != state.closed {
		t.Fatalf("%v/%v, registry %d/%d", dirs, err, state.opened, state.closed)
	}
	for _, name := range state.queries {
		if name != "DSA Working Directory" {
			t.Fatalf("queried custom inclusion path %s", name)
		}
	}
	state.volumeErrors[state.first] = syscall.ERROR_ACCESS_DENIED
	if _, err := environment.configDirectories(context.Background()); !errors.Is(err, syscall.ERROR_ACCESS_DENIED) {
		t.Fatalf("suppressed inaccessible candidate: %v", err)
	}
}

func TestCloneConfigUnsupportedHostStopsBeforeDeviceOrDirectory(t *testing.T) {
	info := nativead.DSROLE_PRIMARY_DOMAIN_INFO_BASIC{MachineRole: nativead.DsRole_RoleMemberServer}
	frees := 0
	m := nativeConfigEnvironment{nativeMachine: nativeMachine{api: nativeAPI{
		getRole: func(_ *string, _ nativead.DSROLE_PRIMARY_DOMAIN_INFO_LEVEL, out **byte) uint32 {
			*out = (*byte)(unsafe.Pointer(&info))
			return 0
		},
		freeRole: func(unsafe.Pointer) { frees++ },
	}}}
	r, err := m.prerequisites(context.Background())
	if !errors.Is(err, ErrNotDomainController) || r.Complete || frees != 1 {
		t.Fatalf("%#v/%v frees=%d", r, err, frees)
	}
}

func TestGenerateConfigOfflineNativePublication(t *testing.T) {
	directory := t.TempDir()
	for _, name := range []string{"CLONE-1", "CLONE-2"} {
		r, err := GenerateConfig(context.Background(), ConfigOptions{Offline: true, Directory: directory, Configuration: CloneConfiguration{ComputerName: name}})
		if err != nil || r.Outcome != Written || !r.ChecksSkipped || r.Prerequisites.Complete {
			t.Fatalf("%#v/%v", r, err)
		}
		data, err := os.ReadFile(r.Path)
		if err != nil {
			t.Fatal(err)
		}
		want, err := EncodeCloneConfiguration(CloneConfiguration{ComputerName: name})
		if err != nil || string(data) != string(want) {
			t.Fatalf("published bytes differ: %s/%v", data, err)
		}
	}
}

func TestCloneConfigNativePrerequisitesGatePublication(t *testing.T) {
	for _, scenario := range []string{"allowed", "RODC", "excluded", "custom included", "inventory denied"} {
		t.Run(scenario, func(t *testing.T) {
			machine, state := locationFixture(t)
			api, source, primary := cloneDirectoryFixture(t)
			info := nativead.DSROLE_PRIMARY_DOMAIN_INFO_BASIC{MachineRole: nativead.DsRole_RolePrimaryDomainController}
			if scenario == "RODC" {
				info.MachineRole = nativead.DsRole_RoleBackupDomainController
				info.Flags = nativead.DSROLE_PRIMARY_DS_READONLY
			}
			frees, deviceClosed, scmClosed, publications := 0, 0, 0, 0
			machine.native.api.getRole = func(_ *string, _ nativead.DSROLE_PRIMARY_DOMAIN_INFO_LEVEL, out **byte) uint32 {
				*out = (*byte)(unsafe.Pointer(&info))
				return 0
			}
			machine.native.api.freeRole = func(unsafe.Pointer) { frees++ }
			openKey := machine.native.api.openKey
			machine.native.api.openKey = func(root registry.HKEY, name *string, options uint32, rights registry.REG_SAM_FLAGS, key *registry.HKEY) foundation.WIN32_ERROR {
				if *name == uninstallKey {
					return foundation.ERROR_FILE_NOT_FOUND
				}
				return openKey(root, name, options, rights, key)
			}
			machine.native.api.openSCM = func(_, _ *string, _ uint32) (services.SC_HANDLE, error) { return 99, nil }
			machine.native.api.closeSCM = func(services.SC_HANDLE) error { scmClosed++; return nil }
			machine.native.api.enumServices = func(_ services.SC_HANDLE, _ services.SC_ENUM_TYPE, _ services.ENUM_SERVICE_TYPE, _ services.ENUM_SERVICE_STATE, buffer []byte, _, count, _ *uint32, _ *string) error {
				if scenario == "inventory denied" {
					return syscall.ERROR_ACCESS_DENIED
				}
				name := "Included"
				if scenario == "excluded" || scenario == "custom included" {
					name = "Excluded"
				}
				putService(buffer, name)
				*count = 1
				return nil
			}
			machine.native.api.compare = func(a string, _ int32, b string, _ int32, _ bool) (globalization.COMPARESTRING_RESULT, error) {
				if strings.EqualFold(a, b) {
					return globalization.CSTR_EQUAL, nil
				}
				return globalization.CSTR_LESS_THAN, nil
			}
			if scenario == "custom included" {
				putCustom(t, state.high)
			}
			host := configNativeAPI{
				name: func(_ systeminformation.COMPUTER_NAME_FORMAT, out foundation.PWSTR, size *uint32) error {
					words := utf16.Encode([]rune("source.example.test"))
					copy(unsafe.Slice(out, *size), append(words, 0))
					*size = uint32(len(words))
					return nil
				},
				open: func(string, uint32, filesystem.FILE_SHARE_MODE, *security.SECURITY_ATTRIBUTES, filesystem.FILE_CREATION_DISPOSITION, filesystem.FILE_FLAGS_AND_ATTRIBUTES, foundation.HANDLE) (foundation.HANDLE, error) {
					return 42, nil
				},
				control: func(_ foundation.HANDLE, _ uint32, _, _ []byte, returned *uint32, _ *nativeio.OVERLAPPED) error {
					*returned = 16
					return nil
				},
				close: func(foundation.HANDLE) error { deviceClosed++; return nil },
			}
			environment := nativeConfigEnvironment{nativeMachine: machine.native, host: host, directory: api}
			publish := func(temporary, destination string, overwrite bool) error {
				publications++
				return configPublisher(t, false)(temporary, destination, overwrite)
			}
			r, err := generateConfiguration(context.Background(), ConfigOptions{}, environment, publish)
			failure := scenario == "excluded" || scenario == "inventory denied"
			if failure {
				if err == nil || r.Outcome != NotWritten || r.Prerequisites.Complete || publications != 0 {
					t.Fatalf("failed application gate: %#v/%v calls=%d", r, err, publications)
				}
			} else if err != nil || r.Outcome != Written || !r.Prerequisites.Complete || publications != 1 {
				t.Fatalf("valid source: %#v/%v calls=%d", r, err, publications)
			}
			if !r.Prerequisites.Applications.AuthorizationLimited || source.closed != 1 || primary.closed != 1 || deviceClosed != 1 || scmClosed != 1 || frees != 2 || state.opened != state.closed {
				t.Fatalf("lost limitations or ownership: %#v; closes source=%d PDC=%d device=%d SCM=%d role=%d registry=%d/%d", r, source.closed, primary.closed, deviceClosed, scmClosed, frees, state.opened, state.closed)
			}
			if scenario == "RODC" && !r.Prerequisites.Role.ReadOnly {
				t.Fatal("RODC role lost")
			}
		})
	}
}
