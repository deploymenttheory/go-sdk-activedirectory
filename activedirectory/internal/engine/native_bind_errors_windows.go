//go:build windows && (amd64 || arm64)

package engine

import (
	"errors"
	"fmt"
	"syscall"
	"unsafe"

	"github.com/deploymenttheory/go-bindings-win32/bindings/win32/foundation"
	"github.com/deploymenttheory/go-bindings-win32/bindings/win32/networking/ldap"
	admodel "github.com/deploymenttheory/go-sdk-activedirectory/activedirectory/internal/model"
)

func (s *InternalLdapSession) InternalBindFailure(code uint32) error {
	// Keep the actual bind status first for errors.As, independently of failures
	// while obtaining optional detail. Capture session state before unbind.
	bindError := &admodel.LDAPError{Operation: "ldap_bind_sW", Code: code}
	var diagnostic foundation.PWSTR
	diagnosticStatus := s.InternalGetRawOption(
		int32(ldap.LDAP_OPT_SERVER_ERROR),
		unsafe.Pointer(&diagnostic),
	)
	if diagnostic != nil {
		// SERVER_ERROR is allocated, unlike borrowed ERROR_STRING/HOST_NAME.
		// Even a failing getter may have supplied storage that we must release.
		defer s.InternalApi.InternalMemoryFree(diagnostic)
	}
	var copyErr error
	if diagnosticStatus == 0 {
		bindError.Diagnostic, copyErr = InternalCopyLDAPText(diagnostic)
	}
	var extended uint32
	extendedStatus := s.InternalGetRawOption(
		int32(ldap.LDAP_OPT_SERVER_EXT_ERROR),
		unsafe.Pointer(&extended),
	)
	err := errors.Join(
		bindError,
		InternalLdapStatus("ldap_get_optionW(SERVER_ERROR)", diagnosticStatus),
		copyErr,
		InternalLdapStatus("ldap_get_optionW(SERVER_EXT_ERROR)", extendedStatus),
	)
	if extendedStatus == 0 && extended != 0 {
		err = errors.Join(err, fmt.Errorf("LDAP bind server status: %w", syscall.Errno(extended)))
	}
	return err
}
