//go:build windows && (amd64 || arm64)

package activedirectory

import (
	"fmt"
	"unicode/utf16"
	"unsafe"

	"github.com/deploymenttheory/go-bindings-win32/bindings/win32/foundation"
)

// WinLDAP string outputs have no length. Bound native reads and reject malformed
// UTF-16 rather than silently replacing code units in DNs or server diagnostics.
func copySearchText(pointer foundation.PWSTR) (string, error) {
	if pointer == nil {
		return "", nil
	}
	units := make([]uint16, 0, 128)
	for index := range 4096 {
		unit := *(*uint16)(unsafe.Add(unsafe.Pointer(pointer), uintptr(index)*unsafe.Sizeof(uint16(0))))
		if unit == 0 {
			for i := 0; i < len(units); i++ {
				if units[i] >= 0xd800 && units[i] <= 0xdbff {
					if i+1 >= len(units) || units[i+1] < 0xdc00 || units[i+1] > 0xdfff {
						return "", fmt.Errorf("%w: malformed UTF-16 LDAP output", ErrInvalidResult)
					}
					i++
				} else if units[i] >= 0xdc00 && units[i] <= 0xdfff {
					return "", fmt.Errorf("%w: malformed UTF-16 LDAP output", ErrInvalidResult)
				}
			}
			return string(utf16.Decode(units)), nil
		}
		units = append(units, unit)
	}
	return "", fmt.Errorf("%w: LDAP output exceeds its UTF-16 limit", ErrInvalidResult)
}
