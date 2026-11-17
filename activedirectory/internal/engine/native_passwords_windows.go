//go:build windows && (amd64 || arm64)

package engine

import (
	"context"
	"errors"
	"fmt"
	"unsafe"

	"github.com/deploymenttheory/go-bindings-win32/bindings/runtime/win32"
	"github.com/deploymenttheory/go-bindings-win32/bindings/win32/networking/ldap"
	"github.com/deploymenttheory/go-bindings-win32/bindings/win32/security/authentication/identity"
	"github.com/deploymenttheory/go-bindings-win32/bindings/win32/security/credentials"
	admodel "github.com/deploymenttheory/go-sdk-activedirectory/activedirectory/internal/model"
)

type InternalPasswordSecurityAPI struct {
	InternalFind  func(*win32.Proc) error
	InternalQuery func(*credentials.SecHandle, identity.SECPKG_ATTR, unsafe.Pointer) error
	InternalFree  func(unsafe.Pointer) error
}

func (s *InternalLdapSession) InternalPasswordProtection(
	ctx context.Context,
	transport admodel.Transport,
) (admodel.PasswordProtection, error) {
	return s.InternalPasswordProtectionWith(
		ctx,
		transport,
		InternalPasswordSecurityAPI{
			InternalFind:  s.InternalApi.InternalFind,
			InternalQuery: identity.QueryContextAttributes,
			InternalFree:  identity.FreeContextBuffer,
		},
	)
}

func (s *InternalLdapSession) InternalPasswordProtectionWith(
	ctx context.Context,
	transport admodel.Transport,
	api InternalPasswordSecurityAPI,
) (protection admodel.PasswordProtection, err error) {
	protection.Transport = transport
	if err := context.Cause(ctx); err != nil {
		return protection, err
	}
	if s.InternalHandle == nil {
		return protection, admodel.ErrClosed
	}
	if transport == admodel.TransportLDAPS || transport == admodel.TransportStartTLS {
		if err := s.InternalVerifyTLS(transport); err != nil {
			return protection, errors.Join(admodel.ErrPasswordProtection, err)
		}
		var connection identity.SecPkgContext_ConnectionInfo
		if status := s.InternalGetRawOption(
			int32(ldap.LDAP_OPT_SSL_INFO),
			unsafe.Pointer(&connection),
		); status != 0 {
			return protection, errors.Join(
				admodel.ErrPasswordProtection,
				InternalLdapStatus("ldap_get_optionW(SSL_INFO)", status),
			)
		}
		protection.CipherBits = connection.DwCipherStrength
		if protection.CipherBits < 128 {
			return protection, admodel.ErrPasswordProtection
		}
		return protection, context.Cause(ctx)
	}
	if transport != admodel.TransportLDAP {
		return protection, admodel.ErrPasswordProtection
	}
	var encrypted uint32
	if status := s.InternalGetRawOption(
		int32(ldap.LDAP_OPT_ENCRYPT),
		unsafe.Pointer(&encrypted),
	); status != 0 {
		return protection, errors.Join(
			admodel.ErrPasswordProtection,
			InternalLdapStatus("ldap_get_optionW(ENCRYPT)", status),
		)
	}
	if encrypted == 0 {
		return protection, admodel.ErrPasswordProtection
	}
	// LDAP owns this security context. Borrow it under the session gate and
	// never delete it or retrieve/export the secret session key itself.
	// LDAP_OPT_SECURITY_CONTEXT writes a CtxtHandle (two pointer-sized
	// words) into caller storage, as also used by .NET's WinLDAP interop.
	// It does not return a pointer requiring an extra dereference.
	var securityContext credentials.SecHandle
	if status := s.InternalGetRawOption(
		int32(ldap.LDAP_OPT_SECURITY_CONTEXT),
		unsafe.Pointer(&securityContext),
	); status != 0 {
		return protection, errors.Join(
			admodel.ErrPasswordProtection,
			InternalLdapStatus("ldap_get_optionW(SECURITY_CONTEXT)", status),
		)
	}
	if securityContext == (credentials.SecHandle{}) ||
		(securityContext.DwLower == ^uintptr(0) && securityContext.DwUpper == ^uintptr(0)) {
		return protection, admodel.ErrPasswordProtection
	}
	for _, proc := range []*win32.Proc{identity.Procs.QueryContextAttributes, identity.Procs.FreeContextBuffer} {
		if err := api.InternalFind(proc); err != nil {
			return protection, errors.Join(
				admodel.ErrPasswordProtection,
				admodel.ErrUnsupported,
				err,
			)
		}
	}
	var flags identity.SecPkgContext_Flags
	if err := api.InternalQuery(
		&securityContext,
		identity.SECPKG_ATTR_FLAGS,
		unsafe.Pointer(&flags),
	); err != nil {
		return protection, errors.Join(
			admodel.ErrPasswordProtection,
			fmt.Errorf("QueryContextAttributesW(FLAGS): %w", err),
		)
	}
	if flags.Flags&identity.ISC_RET_CONFIDENTIALITY == 0 {
		return protection, admodel.ErrPasswordProtection
	}
	var keyInfo identity.SecPkgContext_KeyInfoW
	if err := api.InternalQuery(
		&securityContext,
		identity.SECPKG_ATTR_KEY_INFO,
		unsafe.Pointer(&keyInfo),
	); err != nil {
		return protection, errors.Join(
			admodel.ErrPasswordProtection,
			fmt.Errorf("QueryContextAttributesW(KEY_INFO): %w", err),
		)
	}
	defer func() {
		if keyInfo.SSignatureAlgorithmName != nil {
			err = errors.Join(
				err,
				api.InternalFree(unsafe.Pointer(keyInfo.SSignatureAlgorithmName)),
			)
		}
		if keyInfo.SEncryptAlgorithmName != nil &&
			keyInfo.SEncryptAlgorithmName != keyInfo.SSignatureAlgorithmName {
			err = errors.Join(err, api.InternalFree(unsafe.Pointer(keyInfo.SEncryptAlgorithmName)))
		}
		err = errors.Join(err, context.Cause(ctx))
	}()
	protection.CipherBits = keyInfo.KeySize
	if protection.CipherBits < 128 {
		return protection, admodel.ErrPasswordProtection
	}
	return protection, nil
}
