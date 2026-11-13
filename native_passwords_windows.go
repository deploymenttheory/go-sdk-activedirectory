//go:build windows && (amd64 || arm64)

package activedirectory

import (
	"context"
	"errors"
	"fmt"
	"unsafe"

	"github.com/deploymenttheory/go-bindings-win32/bindings/runtime/win32"
	"github.com/deploymenttheory/go-bindings-win32/bindings/win32/networking/ldap"
	"github.com/deploymenttheory/go-bindings-win32/bindings/win32/security/authentication/identity"
	"github.com/deploymenttheory/go-bindings-win32/bindings/win32/security/credentials"
)

type passwordSecurityAPI struct {
	find  func(*win32.Proc) error
	query func(*credentials.SecHandle, identity.SECPKG_ATTR, unsafe.Pointer) error
	free  func(unsafe.Pointer) error
}

func (s *ldapSession) passwordProtection(ctx context.Context, transport Transport) (PasswordProtection, error) {
	return s.passwordProtectionWith(ctx, transport, passwordSecurityAPI{find: s.api.find, query: identity.QueryContextAttributes, free: identity.FreeContextBuffer})
}

func (s *ldapSession) passwordProtectionWith(ctx context.Context, transport Transport, api passwordSecurityAPI) (protection PasswordProtection, err error) {
	protection.Transport = transport
	if err := context.Cause(ctx); err != nil {
		return protection, err
	}
	if s.handle == nil {
		return protection, ErrClosed
	}
	if transport == TransportLDAPS || transport == TransportStartTLS {
		if err := s.verifyTLS(transport); err != nil {
			return protection, errors.Join(ErrPasswordProtection, err)
		}
		var connection identity.SecPkgContext_ConnectionInfo
		if status := s.getRawOption(int32(ldap.LDAP_OPT_SSL_INFO), unsafe.Pointer(&connection)); status != 0 {
			return protection, errors.Join(ErrPasswordProtection, ldapStatus("ldap_get_optionW(SSL_INFO)", status))
		}
		protection.CipherBits = connection.DwCipherStrength
		if protection.CipherBits < 128 {
			return protection, ErrPasswordProtection
		}
		return protection, context.Cause(ctx)
	}
	if transport != TransportLDAP {
		return protection, ErrPasswordProtection
	}
	var encrypted uint32
	if status := s.getRawOption(int32(ldap.LDAP_OPT_ENCRYPT), unsafe.Pointer(&encrypted)); status != 0 {
		return protection, errors.Join(ErrPasswordProtection, ldapStatus("ldap_get_optionW(ENCRYPT)", status))
	}
	if encrypted == 0 {
		return protection, ErrPasswordProtection
	}
	// LDAP owns this security context. Borrow it under the session gate and
	// never delete it or retrieve/export the secret session key itself.
	// LDAP_OPT_SECURITY_CONTEXT writes a CtxtHandle (two pointer-sized
	// words) into caller storage, as also used by .NET's WinLDAP interop.
	// It does not return a pointer requiring an extra dereference.
	var securityContext credentials.SecHandle
	if status := s.getRawOption(int32(ldap.LDAP_OPT_SECURITY_CONTEXT), unsafe.Pointer(&securityContext)); status != 0 {
		return protection, errors.Join(ErrPasswordProtection, ldapStatus("ldap_get_optionW(SECURITY_CONTEXT)", status))
	}
	if securityContext == (credentials.SecHandle{}) || (securityContext.DwLower == ^uintptr(0) && securityContext.DwUpper == ^uintptr(0)) {
		return protection, ErrPasswordProtection
	}
	for _, proc := range []*win32.Proc{identity.Procs.QueryContextAttributes, identity.Procs.FreeContextBuffer} {
		if err := api.find(proc); err != nil {
			return protection, errors.Join(ErrPasswordProtection, ErrUnsupported, err)
		}
	}
	var flags identity.SecPkgContext_Flags
	if err := api.query(&securityContext, identity.SECPKG_ATTR_FLAGS, unsafe.Pointer(&flags)); err != nil {
		return protection, errors.Join(ErrPasswordProtection, fmt.Errorf("QueryContextAttributesW(FLAGS): %w", err))
	}
	if flags.Flags&identity.ISC_RET_CONFIDENTIALITY == 0 {
		return protection, ErrPasswordProtection
	}
	var keyInfo identity.SecPkgContext_KeyInfoW
	if err := api.query(&securityContext, identity.SECPKG_ATTR_KEY_INFO, unsafe.Pointer(&keyInfo)); err != nil {
		return protection, errors.Join(ErrPasswordProtection, fmt.Errorf("QueryContextAttributesW(KEY_INFO): %w", err))
	}
	defer func() {
		if keyInfo.SSignatureAlgorithmName != nil {
			err = errors.Join(err, api.free(unsafe.Pointer(keyInfo.SSignatureAlgorithmName)))
		}
		if keyInfo.SEncryptAlgorithmName != nil && keyInfo.SEncryptAlgorithmName != keyInfo.SSignatureAlgorithmName {
			err = errors.Join(err, api.free(unsafe.Pointer(keyInfo.SEncryptAlgorithmName)))
		}
		err = errors.Join(err, context.Cause(ctx))
	}()
	protection.CipherBits = keyInfo.KeySize
	if protection.CipherBits < 128 {
		return protection, ErrPasswordProtection
	}
	return protection, nil
}
