//go:build windows && (amd64 || arm64)

package engine

import (
	"context"
	"errors"
	"fmt"
	"strings"
	"unsafe"

	"github.com/deploymenttheory/go-bindings-win32/bindings/runtime/win32"
	"github.com/deploymenttheory/go-bindings-win32/bindings/win32/networking/ldap"
	"github.com/deploymenttheory/go-bindings-win32/bindings/win32/security/authentication/identity"
	"github.com/deploymenttheory/go-bindings-win32/bindings/win32/security/credentials"
	admodel "github.com/deploymenttheory/go-sdk-activedirectory/activedirectory/internal/model"
)

type InternalMoveSecurityAPI struct {
	InternalFind  func(*win32.Proc) error
	InternalQuery func(*credentials.SecHandle, identity.SECPKG_ATTR, unsafe.Pointer) error
	InternalFree  func(unsafe.Pointer) error
}

func (s *InternalLdapSession) InternalMoveSecurity(
	ctx context.Context,
) (admodel.MoveSecurity, error) {
	return s.InternalMoveSecurityWith(
		ctx,
		InternalMoveSecurityAPI{
			InternalFind:  s.InternalApi.InternalFind,
			InternalQuery: identity.QueryContextAttributes,
			InternalFree:  identity.FreeContextBuffer,
		},
	)
}

func (s *InternalLdapSession) InternalMoveSecurityWith(
	ctx context.Context,
	api InternalMoveSecurityAPI,
) (result admodel.MoveSecurity, err error) {
	if err := context.Cause(ctx); err != nil {
		return result, err
	}
	if s.InternalHandle == nil {
		return result, admodel.ErrClosed
	}
	// Same borrowed-context convention as password protection: WinLDAP writes
	// a SecHandle into caller storage. LDAP owns it; never delete/export it.
	var securityContext credentials.SecHandle
	if status := s.InternalGetRawOption(
		int32(ldap.LDAP_OPT_SECURITY_CONTEXT),
		unsafe.Pointer(&securityContext),
	); status != 0 {
		return result, errors.Join(
			admodel.ErrMoveDelegation,
			InternalLdapStatus("ldap_get_optionW(SECURITY_CONTEXT)", status),
		)
	}
	if securityContext == (credentials.SecHandle{}) ||
		(securityContext.DwLower == ^uintptr(0) && securityContext.DwUpper == ^uintptr(0)) {
		return result, admodel.ErrMoveDelegation
	}
	for _, proc := range []*win32.Proc{identity.Procs.QueryContextAttributes, identity.Procs.FreeContextBuffer} {
		if err := api.InternalFind(proc); err != nil {
			return result, errors.Join(admodel.ErrMoveDelegation, admodel.ErrUnsupported, err)
		}
	}
	var flags identity.SecPkgContext_Flags
	if err := api.InternalQuery(
		&securityContext,
		identity.SECPKG_ATTR_FLAGS,
		unsafe.Pointer(&flags),
	); err != nil {
		return result, errors.Join(
			admodel.ErrMoveDelegation,
			fmt.Errorf("QueryContextAttributesW(FLAGS): %w", err),
		)
	}
	result.ContextFlags = flags.Flags
	result.Delegated = flags.Flags&identity.ISC_RET_DELEGATE != 0
	var negotiation identity.SecPkgContext_NegotiationInfoW
	if err := api.InternalQuery(
		&securityContext,
		identity.SECPKG_ATTR_NEGOTIATION_INFO,
		unsafe.Pointer(&negotiation),
	); err != nil {
		return result, errors.Join(
			admodel.ErrMoveDelegation,
			fmt.Errorf("QueryContextAttributesW(NEGOTIATION_INFO): %w", err),
		)
	}
	defer func() {
		if negotiation.PackageInfo != nil {
			err = errors.Join(err, api.InternalFree(unsafe.Pointer(negotiation.PackageInfo)))
		}
		err = errors.Join(err, context.Cause(ctx))
		result.Complete = err == nil
	}()
	if negotiation.PackageInfo == nil ||
		negotiation.NegotiationState != identity.SECPKG_NEGOTIATION_COMPLETE {
		return result, admodel.ErrMoveDelegation
	}
	result.Package, err = InternalCopyLDAPText(negotiation.PackageInfo.Name)
	if err != nil {
		return result, errors.Join(admodel.ErrMoveDelegation, err)
	}
	if !strings.EqualFold(result.Package, "Kerberos") || !result.Delegated ||
		flags.Flags&identity.ISC_RET_MUTUAL_AUTH == 0 {
		return result, admodel.ErrMoveDelegation
	}
	return result, nil
}
