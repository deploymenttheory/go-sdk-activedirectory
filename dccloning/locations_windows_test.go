//go:build windows && (amd64 || arm64)

package dccloning

import (
	"context"
	"encoding/binary"
	"errors"
	"os"
	"path/filepath"
	"reflect"
	"syscall"
	"testing"
	"unicode/utf16"
	"unsafe"

	"github.com/deploymenttheory/go-bindings-win32/bindings/win32/foundation"
	"github.com/deploymenttheory/go-bindings-win32/bindings/win32/system/registry"
)

// Exercise the real native location orchestration with isolated filesystem
// fixtures and per-call native seams; no host registry or volumes are queried.
type locationMachine struct {
	fakeMachine
	native nativeMachine
}

func (m locationMachine) locations(ctx context.Context) (locations, error) {
	return m.native.locations(ctx)
}

type locationCalls struct {
	parameters          map[string]string
	queries, volumes    []string
	volumeErrors        map[string]error
	closeError          foundation.WIN32_ERROR
	opened, closed      int
	driveCalls, windows int
	high, dsa           string
	first, last         string
}

func locationFixture(t *testing.T) (locationMachine, *locationCalls) {
	t.Helper()
	m := locationMachine{fakeMachine: fixtureMachine(t)}
	base := m.paths.directories[0]
	state := &locationCalls{
		high: filepath.Join(base, "high"), dsa: filepath.Join(base, "dsa"),
		first: filepath.Join(base, "drive-a"), last: filepath.Join(base, "drive-z"),
		volumeErrors: map[string]error{},
	}
	for _, dir := range []string{state.high, state.dsa, state.first, state.last, filepath.Join(base, "NTDS")} {
		if err := os.Mkdir(dir, 0700); err != nil {
			t.Fatal(err)
		}
	}
	if err := os.WriteFile(filepath.Join(base, "DefaultDCCloneAllowList.xml"), []byte(defaultFixture), 0600); err != nil {
		t.Fatal(err)
	}
	state.parameters = map[string]string{"AllowListFolder": state.high, "DSA Working Directory": state.dsa}
	directory := func(out foundation.PWSTR, count uint32) (uint32, error) {
		words := utf16.Encode([]rune(base))
		copy(unsafe.Slice(out, count), append(words, 0))
		return uint32(len(words)), nil
	}
	m.native.api = nativeAPI{
		systemDirectory: directory,
		windowsDirectory: func(out foundation.PWSTR, count uint32) (uint32, error) {
			state.windows++
			return directory(out, count)
		},
		openKey: func(_ registry.HKEY, name *string, _ uint32, _ registry.REG_SAM_FLAGS, key *registry.HKEY) foundation.WIN32_ERROR {
			if *name != parametersKey {
				t.Fatalf("unexpected key %s", *name)
			}
			state.opened++
			*key = 1
			return 0
		},
		closeKey: func(registry.HKEY) foundation.WIN32_ERROR { state.closed++; return state.closeError },
		queryValue: func(_ registry.HKEY, name *string, kind *registry.REG_VALUE_TYPE, data *byte, size *uint32) foundation.WIN32_ERROR {
			state.queries = append(state.queries, *name)
			value, present := state.parameters[*name]
			if !present {
				return foundation.ERROR_FILE_NOT_FOUND
			}
			words := append(utf16.Encode([]rune(value)), 0)
			needed := uint32(len(words) * 2)
			*kind = registry.REG_SZ
			if needed > *size {
				*size = needed
				return foundation.ERROR_MORE_DATA
			}
			buffer := unsafe.Slice(data, *size)
			for i, word := range words {
				binary.LittleEndian.PutUint16(buffer[i*2:], word)
			}
			*size = needed
			return 0
		},
		drives: func(count uint32, out foundation.PWSTR) (uint32, error) {
			state.driveCalls++
			// Deliberately reverse input: selection must use drive-letter order.
			words := utf16.Encode([]rune(state.last + "\x00" + state.first + "\x00"))
			if uint32(len(words)+1) > count {
				return uint32(len(words) + 1), nil
			}
			copy(unsafe.Slice(out, count), append(words, 0))
			return uint32(len(words)), nil
		},
		driveType: func(*string) uint32 { return 2 },
		volume: func(root *string, _ foundation.PWSTR, _ uint32, _, _, flags *uint32, _ foundation.PWSTR, _ uint32) error {
			state.volumes = append(state.volumes, *root)
			*flags = 0
			return state.volumeErrors[*root]
		},
	}
	return m, state
}

func putCustom(t *testing.T, directory string) {
	t.Helper()
	data, err := EncodeCustomAllowList([]Entry{{Name: "Excluded", Type: Service}})
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(directory, CustomFileName), data, 0600); err != nil {
		t.Fatal(err)
	}
}

func TestNativeLocationsStopAtSelectedFile(t *testing.T) {
	for _, useDSA := range []bool{false, true} {
		m, calls := locationFixture(t)
		selected := calls.high
		if useDSA {
			delete(calls.parameters, "AllowListFolder")
			selected = calls.dsa
		}
		putCustom(t, selected)
		calls.volumeErrors[calls.first] = syscall.Errno(21) // ERROR_NOT_READY
		r, _, err := inspect(context.Background(), m, readList, "")
		if err != nil || !r.Complete || len(r.Entries) != 0 || r.CustomListPath != filepath.Join(selected, CustomFileName) {
			t.Fatalf("selected higher list: %#v, %v", r, err)
		}
		if calls.driveCalls != 0 || calls.windows != 0 || calls.opened != calls.closed {
			t.Fatalf("unnecessary lookup or leaked key: %#v", calls)
		}
		if !useDSA && len(calls.queries) != 1 {
			t.Fatalf("resolved lower registry value: %v", calls.queries)
		}
	}
}

func TestNativeRemovableLocationsAreClassifiedInOrder(t *testing.T) {
	for _, cause := range []error{syscall.Errno(21), syscall.ERROR_ACCESS_DENIED} {
		m, calls := locationFixture(t)
		putCustom(t, calls.first)
		calls.volumeErrors[calls.last] = cause
		r, _, err := inspect(context.Background(), m, readList, "")
		if err != nil || !r.Complete || len(r.Entries) != 0 || !reflect.DeepEqual(calls.volumes, []string{calls.first}) {
			t.Fatalf("lower volume gated selected list: %v, volumes %v", err, calls.volumes)
		}
		if err := os.Remove(filepath.Join(calls.first, CustomFileName)); err != nil {
			t.Fatal(err)
		}
		calls.volumes = nil
		r, _, err = inspect(context.Background(), m, readList, "")
		if !errors.Is(err, cause) || r.Complete || !reflect.DeepEqual(calls.volumes, []string{calls.first, calls.last}) {
			t.Fatalf("necessary volume error discarded: %v, volumes %v", err, calls.volumes)
		}
	}
}

func TestNativeGenerationResolvesOnlyThroughExplicitOutput(t *testing.T) {
	for _, removable := range []bool{false, true} {
		m, calls := locationFixture(t)
		directory := calls.high
		if removable {
			directory = calls.first
		}
		calls.volumeErrors[calls.last] = syscall.ERROR_ACCESS_DENIED
		r, err := generate(context.Background(), m, GenerateOptions{Directory: directory}, readList, func(temp, dest string, _ bool) error { return os.Rename(temp, dest) })
		if err != nil || r.Outcome != Written {
			t.Fatalf("unrelated volume gated generation: %s, %v", r.Outcome, err)
		}
		if (!removable && calls.driveCalls != 0) || (removable && !reflect.DeepEqual(calls.volumes, []string{calls.first})) {
			t.Fatalf("resolved lower candidate: %#v", calls)
		}
	}
}

func TestNativeGenerationRetainsPrecedenceAndNecessaryErrors(t *testing.T) {
	never := func(string, string, bool) error { t.Fatal("unexpected publication"); return nil }
	m, calls := locationFixture(t)
	putCustom(t, calls.high)
	r, err := generate(context.Background(), m, GenerateOptions{Directory: calls.dsa, Overwrite: true}, readList, never)
	if !errors.Is(err, ErrPrecedence) || r.Outcome != NotWritten || calls.driveCalls != 0 {
		t.Fatalf("precedence bypass: %s, %v", r.Outcome, err)
	}
	if err := os.Remove(filepath.Join(calls.high, CustomFileName)); err != nil {
		t.Fatal(err)
	}
	calls.volumeErrors[calls.first] = syscall.ERROR_ACCESS_DENIED
	r, err = generate(context.Background(), m, GenerateOptions{Directory: calls.last, Overwrite: true}, readList, never)
	if !errors.Is(err, syscall.ERROR_ACCESS_DENIED) || r.Outcome != NotWritten || !reflect.DeepEqual(calls.volumes, []string{calls.first}) {
		t.Fatalf("necessary higher volume error bypass: %s, %v", r.Outcome, err)
	}
	deniedRead := func(path string) ([]byte, error) {
		if path == filepath.Join(calls.high, CustomFileName) {
			return nil, os.ErrPermission
		}
		return readList(path)
	}
	r, err = generate(context.Background(), m, GenerateOptions{Directory: calls.dsa, Overwrite: true}, deniedRead, never)
	if !errors.Is(err, os.ErrPermission) || r.Outcome != NotWritten {
		t.Fatalf("necessary higher file error bypass: %s, %v", r.Outcome, err)
	}
	putCustom(t, calls.high)
	calls.closeError = foundation.ERROR_ACCESS_DENIED
	_, _, err = inspect(context.Background(), m, readList, "")
	if !errors.Is(err, syscall.ERROR_ACCESS_DENIED) || calls.opened != calls.closed {
		t.Fatalf("lazy registry cleanup lost: %v, %#v", err, calls)
	}
}
