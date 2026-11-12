//go:build windows && (amd64 || arm64)

package activedirectory

import (
	"fmt"
	"unicode/utf16"
	"unsafe"

	"github.com/deploymenttheory/go-bindings-win32/bindings/win32/foundation"
)

// WinLDAP returns a NUL-terminated native allocation without a length. Limit
// text reads to 4096 UTF-16 code units including the terminator. Reject
// malformed or over-limit detail without replacing the original LDAP status.
// Callers own the native allocation and must release it even if copying fails.
func copyLDAPText(pointer foundation.PWSTR) (string, error) {
	if pointer == nil {
		return "", nil
	}
	units := make([]uint16, 0, 128)
	for index := range 4096 {
		unit := *(*uint16)(unsafe.Add(unsafe.Pointer(pointer), uintptr(index)*unsafe.Sizeof(uint16(0))))
		if unit == 0 {
			return decodeLDAPText(units)
		}
		units = append(units, unit)
	}
	return "", fmt.Errorf("%w: LDAP output exceeds its UTF-16 limit", ErrInvalidResult)
}

func decodeLDAPText(units []uint16) (string, error) {
	for index := 0; index < len(units); index++ {
		unit := units[index]
		if unit >= 0xd800 && unit <= 0xdbff {
			if index+1 >= len(units) || units[index+1] < 0xdc00 || units[index+1] > 0xdfff {
				return "", fmt.Errorf("%w: malformed UTF-16 LDAP output", ErrInvalidResult)
			}
			index++
		} else if unit >= 0xdc00 && unit <= 0xdfff {
			return "", fmt.Errorf("%w: malformed UTF-16 LDAP output", ErrInvalidResult)
		}
	}
	return string(utf16.Decode(units)), nil
}
