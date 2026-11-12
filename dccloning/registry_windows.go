//go:build windows && (amd64 || arm64)

package dccloning

import (
	"context"
	"encoding/binary"
	"errors"
	"fmt"
	"syscall"

	"github.com/deploymenttheory/go-bindings-win32/bindings/win32/foundation"
	"github.com/deploymenttheory/go-bindings-win32/bindings/win32/system/registry"
)

func (m nativeMachine) programs(ctx context.Context, view registry.REG_SAM_FLAGS, kind Kind) (entries []Entry, resultErr error) {
	if err := context.Cause(ctx); err != nil {
		return nil, err
	}
	var key registry.HKEY
	status := m.api.openKey(registry.HKEY_LOCAL_MACHINE, stringPointer(uninstallKey), 0, registry.KEY_ENUMERATE_SUB_KEYS|view, &key)
	if uint32(status) == uint32(syscall.ERROR_FILE_NOT_FOUND) {
		return nil, nil
	}
	if status != 0 {
		return nil, nativeStatus("RegOpenKeyExW(Uninstall)", uint32(status))
	}
	defer func() {
		resultErr = errors.Join(resultErr, nativeStatus("RegCloseKey(Uninstall)", uint32(m.api.closeKey(key))))
	}()
	names := make([]uint16, 256)
	for index := uint32(0); ; index++ {
		if err := context.Cause(ctx); err != nil {
			return entries, err
		}
		var name string
		for {
			length := uint32(len(names))
			status = m.api.enumKey(key, index, &names[0], &length, nil, nil, nil)
			if status == foundation.ERROR_NO_MORE_ITEMS {
				return entries, nil
			}
			if uint32(status) == uint32(syscall.ERROR_MORE_DATA) {
				if len(names) >= 32768 {
					return entries, fmt.Errorf("%w: oversized registry subkey", ErrIncomplete)
				}
				names = make([]uint16, len(names)*2)
				continue
			}
			if status != 0 {
				return entries, nativeStatus("RegEnumKeyExW(Uninstall)", uint32(status))
			}
			if uint64(length) >= uint64(len(names)) {
				return entries, fmt.Errorf("%w: invalid registry subkey length", ErrIncomplete)
			}
			var err error
			name, err = checkedUTF16(names[:length])
			if err != nil {
				return entries, err
			}
			break
		}
		entry, present, err := m.program(ctx, key, name, view, kind)
		if present {
			entries = append(entries, entry)
		}
		if err != nil {
			return entries, err
		}
		if index == ^uint32(0) {
			return entries, fmt.Errorf("%w: registry index overflow", ErrIncomplete)
		}
	}
}

func (m nativeMachine) program(ctx context.Context, parent registry.HKEY, name string, view registry.REG_SAM_FLAGS, kind Kind) (entry Entry, present bool, resultErr error) {
	var key registry.HKEY
	status := m.api.openKey(parent, &name, 0, registry.KEY_QUERY_VALUE|view, &key)
	if status != 0 {
		return entry, false, nativeStatus("RegOpenKeyExW(program)", uint32(status))
	}
	defer func() {
		resultErr = errors.Join(resultErr, nativeStatus("RegCloseKey(program)", uint32(m.api.closeKey(key))))
	}()
	displayName, found, err := m.registryString(ctx, key, "DisplayName")
	if err != nil || !found {
		return entry, false, err
	}
	return Entry{Name: displayName, Type: kind, Source: string(kind), Location: uninstallKey + `\` + name}, true, nil
}

func (m nativeMachine) registryString(ctx context.Context, key registry.HKEY, name string) (string, bool, error) {
	buffer := make([]byte, 256)
	for attempts := 0; attempts < 16; attempts++ {
		if err := context.Cause(ctx); err != nil {
			return "", false, err
		}
		length := uint32(len(buffer))
		var kind registry.REG_VALUE_TYPE
		status := m.api.queryValue(key, &name, &kind, &buffer[0], &length)
		if uint32(status) == uint32(syscall.ERROR_FILE_NOT_FOUND) {
			return "", false, nil
		}
		if uint32(status) == uint32(syscall.ERROR_MORE_DATA) {
			if length <= uint32(len(buffer)) {
				length = uint32(len(buffer)) * 2
			}
			if length > maxNativeBytes {
				return "", false, fmt.Errorf("%w: oversized registry value", ErrIncomplete)
			}
			buffer = make([]byte, length)
			continue
		}
		if status != 0 {
			return "", false, nativeStatus("RegQueryValueExW("+name+")", uint32(status))
		}
		if kind != registry.REG_SZ || length%2 != 0 || uint64(length) > uint64(len(buffer)) {
			return "", false, fmt.Errorf("%w: invalid registry string type/length for %s", ErrIncomplete, name)
		}
		words := make([]uint16, length/2)
		for i := range words {
			words[i] = binary.LittleEndian.Uint16(buffer[i*2:])
		}
		if len(words) > 0 && words[len(words)-1] == 0 {
			words = words[:len(words)-1]
		}
		value, err := checkedUTF16(words)
		return value, err == nil, err
	}
	return "", false, fmt.Errorf("%w: registry value changed repeatedly", ErrIncomplete)
}
