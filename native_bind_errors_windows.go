//go:build windows && (amd64 || arm64)

package activedirectory

import (
	"errors"
	"fmt"
	"syscall"
	"unicode/utf16"
	"unsafe"

	"github.com/deploymenttheory/go-bindings-win32/bindings/win32/foundation"
	"github.com/deploymenttheory/go-bindings-win32/bindings/win32/networking/ldap"
)

func (s *ldapSession) bindFailure(code uint32) error {
	// Keep the actual bind status first for errors.As, independently of failures
	// while obtaining optional detail. Capture session state before unbind.
	bindError := &LDAPError{Operation: "ldap_bind_sW", Code: code}
	var diagnostic foundation.PWSTR
	diagnosticStatus := s.api.getOption(
		s.handle,
		int32(ldap.LDAP_OPT_SERVER_ERROR),
		unsafe.Pointer(&diagnostic),
	)
	if diagnostic != nil {
		// SERVER_ERROR is allocated, unlike borrowed ERROR_STRING/HOST_NAME.
		// Even a failing getter may have supplied storage that we must release.
		defer s.api.memoryFree(diagnostic)
	}
	var copyErr error
	if diagnosticStatus == 0 {
		bindError.Diagnostic, copyErr = copyBindDiagnostic(diagnostic)
	}
	var extended uint32
	extendedStatus := s.api.getOption(
		s.handle,
		int32(ldap.LDAP_OPT_SERVER_EXT_ERROR),
		unsafe.Pointer(&extended),
	)
	err := errors.Join(
		bindError,
		ldapStatus("ldap_get_optionW(SERVER_ERROR)", diagnosticStatus),
		copyErr,
		ldapStatus("ldap_get_optionW(SERVER_EXT_ERROR)", extendedStatus),
	)
	if extendedStatus == 0 && extended != 0 {
		err = errors.Join(err, fmt.Errorf("LDAP bind server status: %w", syscall.Errno(extended)))
	}
	return err
}

// WinLDAP returns a NUL-terminated native allocation without a length. Limit
// diagnostic reads to 4096 UTF-16 code units including the terminator. Reject
// malformed or over-limit detail without replacing the original LDAP status.
// The copied text is available only through LDAPError.Diagnostic; Error omits it.
func copyBindDiagnostic(pointer foundation.PWSTR) (string, error) {
	if pointer == nil {
		return "", nil
	}
	units := make([]uint16, 0, 128)
	for index := range 4096 {
		unit := *(*uint16)(unsafe.Add(unsafe.Pointer(pointer), uintptr(index)*unsafe.Sizeof(uint16(0))))
		if unit == 0 {
			return decodeBindDiagnostic(units)
		}
		units = append(units, unit)
	}
	return "", fmt.Errorf("%w: LDAP bind diagnostic exceeds its UTF-16 limit", ErrInvalidResult)
}

func decodeBindDiagnostic(units []uint16) (string, error) {
	for index := 0; index < len(units); index++ {
		unit := units[index]
		if unit >= 0xd800 && unit <= 0xdbff {
			if index+1 >= len(units) || units[index+1] < 0xdc00 || units[index+1] > 0xdfff {
				return "", fmt.Errorf("%w: malformed UTF-16 LDAP bind diagnostic", ErrInvalidResult)
			}
			index++
		} else if unit >= 0xdc00 && unit <= 0xdfff {
			return "", fmt.Errorf("%w: malformed UTF-16 LDAP bind diagnostic", ErrInvalidResult)
		}
	}
	return string(utf16.Decode(units)), nil
}
