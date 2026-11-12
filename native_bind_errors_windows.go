//go:build windows && (amd64 || arm64)

package activedirectory

import (
	"errors"
	"fmt"
	"syscall"
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
		bindError.Diagnostic, copyErr = copyLDAPText(diagnostic)
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
