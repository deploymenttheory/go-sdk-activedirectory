//go:build windows && (amd64 || arm64)

package engine

import (
	"context"
	"errors"
	"fmt"
	"runtime"
	"time"
	"unsafe"

	"github.com/deploymenttheory/go-bindings-win32/bindings/win32/networking/ldap"
	"github.com/deploymenttheory/go-bindings-win32/bindings/win32/security/authentication/identity"
	admodel "github.com/deploymenttheory/go-sdk-activedirectory/activedirectory/internal/model"
)

type InternalLdapSession struct {
	InternalApi      InternalLdapAPI
	InternalHandle   *ldap.LDAP
	InternalTimeout  time.Duration
	InternalCloseErr error
}

func InternalLdapStatus(operation string, code uint32) error {
	if code == 0 {
		return nil
	}
	return &admodel.LDAPError{Operation: operation, Code: code}
}

func InternalDialNative(
	ctx context.Context,
	config admodel.Config,
) (admodel.InternalDirectorySession, error) {
	return InternalDialWithAPI(ctx, config, InternalSystemLDAPAPI())
}

func InternalDialWithAPI(
	ctx context.Context,
	config admodel.Config,
	api InternalLdapAPI,
) (result admodel.InternalDirectorySession, err error) {
	config, err = admodel.InternalConfigNormalized(config)
	if err != nil {
		return nil, err
	}
	if err := api.InternalAvailable(); err != nil {
		return nil, err
	}
	if err := api.InternalTlsAvailable(config.Transport); err != nil {
		return nil, err
	}
	if config.Credentials != nil {
		if err := admodel.InternalCredentialsValidate(config.Credentials); err != nil {
			return nil, err
		}
		if err := api.InternalCredentialAvailable(); err != nil {
			return nil, err
		}
	}
	if err := context.Cause(ctx); err != nil {
		return nil, err
	}
	// Keep authentication on the calling OS thread, including when the caller
	// has explicitly locked it for Windows impersonation. Never move bind to a
	// background goroutine to pretend a synchronous native call is cancellable.
	runtime.LockOSThread()
	defer runtime.UnlockOSThread()
	var handle *ldap.LDAP
	initOperation := "ldap_initW"
	if config.Transport == admodel.TransportLDAPS {
		initOperation = "ldap_sslinitW"
		handle = api.InternalSslInit(config.Endpoint.Host, uint32(config.Endpoint.Port), 1)
	} else {
		handle = api.InternalInit(config.Endpoint.Host, uint32(config.Endpoint.Port))
	}
	if handle == nil {
		status := api.InternalLastError()
		if status == 0 {
			return nil, fmt.Errorf(
				"%w: %s returned NULL without an error", admodel.ErrInvalidResult, initOperation,
			)
		}
		return nil, InternalLdapStatus(initOperation, status)
	}
	session := &InternalLdapSession{
		InternalApi:     api,
		InternalHandle:  handle,
		InternalTimeout: config.Timeout,
	}
	defer func() {
		if err != nil {
			err = errors.Join(err, session.InternalClose())
		}
	}()
	for _, option := range []struct{ InternalCode, InternalValue uint32 }{
		{ldap.LDAP_OPT_PROTOCOL_VERSION, ldap.LDAP_VERSION3},
		{ldap.LDAP_OPT_AREC_EXCLUSIVE, 1},
		{ldap.LDAP_OPT_AUTO_RECONNECT, 0},
		{ldap.LDAP_OPT_PROMPT_CREDENTIALS, 0},
		{ldap.LDAP_OPT_REFERRALS, 0},
		{ldap.LDAP_OPT_ROOTDSE_CACHE, 0},
	} {
		if err := session.InternalSetUint(option.InternalCode, option.InternalValue); err != nil {
			return nil, err
		}
	}
	if config.Transport == admodel.TransportLDAP {
		for _, option := range []uint32{ldap.LDAP_OPT_SIGN, ldap.LDAP_OPT_ENCRYPT} {
			if err := session.InternalSetUint(option, 1); err != nil {
				return nil, err
			}
		}
	} else if err := session.InternalConfigureTLS(); err != nil {
		return nil, err
	}
	if config.AllowDelegation {
		// Preserve existing signing/sealing flags. Both bits are required for
		// Kerberos delegation; the established context is checked before use.
		var flags uint32
		if status := session.InternalGetRawOption(
			int32(ldap.LDAP_OPT_SSPI_FLAGS),
			unsafe.Pointer(&flags),
		); status != 0 {
			return nil, InternalLdapStatus("ldap_get_optionW(SSPI_FLAGS)", status)
		}
		flags |= uint32(identity.ISC_REQ_DELEGATE | identity.ISC_REQ_MUTUAL_AUTH)
		if err := session.InternalSetUint(ldap.LDAP_OPT_SSPI_FLAGS, flags); err != nil {
			return nil, err
		}
	}
	wait, err := InternalRemainingWait(ctx, config.Timeout)
	if err != nil {
		return nil, err
	}
	if err := session.InternalSetTimeouts(wait); err != nil {
		return nil, err
	}
	timeout := InternalNativeTimeval(wait)
	status := api.InternalConnect(handle, &timeout)
	if status != 0 && config.Transport != admodel.TransportLDAP {
		return nil, errors.Join(
			session.InternalTlsFailure("ldap_connect", status),
			context.Cause(ctx),
		)
	}
	if err := errors.Join(
		InternalLdapStatus("ldap_connect", status),
		context.Cause(ctx),
	); err != nil {
		return nil, err
	}
	if config.Transport == admodel.TransportStartTLS {
		if err := session.InternalStartTLS(ctx); err != nil {
			return nil, err
		}
	}
	if config.Transport != admodel.TransportLDAP {
		if err := errors.Join(
			session.InternalVerifyTLS(config.Transport),
			context.Cause(ctx),
		); err != nil {
			return nil, err
		}
	}
	wait, err = InternalRemainingWait(ctx, config.Timeout)
	if err != nil {
		return nil, err
	}
	if err := session.InternalSetTimeouts(wait); err != nil {
		return nil, err
	}
	if err := context.Cause(ctx); err != nil {
		return nil, err
	}
	// This SDK-header macro is absent from WinMD's projected constants:
	// LDAP_AUTH_NEGOTIATE = LDAP_AUTH_OTHERKIND | 0x0400.
	// https://github.com/microsoft/win32metadata/blob/main/generation/WinSDK/RecompiledIdlHeaders/um/Winldap.h
	const negotiate = uint32(ldap.LDAP_AUTH_OTHERKIND) | 0x0400
	method := negotiate
	if config.Authentication == admodel.AuthenticationSimple {
		method = uint32(ldap.LDAP_AUTH_SIMPLE)
	}
	status = InternalBindIdentity(api, handle, config.Credentials, method)
	var bindErr error
	if status != 0 {
		bindErr = session.InternalBindFailure(status)
	}
	if err := errors.Join(bindErr, context.Cause(ctx)); err != nil {
		return nil, err
	}
	return session, nil
}

// setRawOption and getRawOption anchor the caller's value for the duration
// of the WinLDAP call. WinLDAP dereferences the option pointer, and the
// conversion to uintptr happens inside the generated binding rather than at
// this call site, so the referent is held reachable here instead of relying
// on that keepalive crossing the package boundary. Every other native call
// site in this package anchors the pointers it lends out the same way.
func (s *InternalLdapSession) InternalSetRawOption(option int32, value unsafe.Pointer) uint32 {
	status := s.InternalApi.InternalSetOption(s.InternalHandle, option, value)
	runtime.KeepAlive(value)
	return status
}

func (s *InternalLdapSession) InternalGetRawOption(option int32, value unsafe.Pointer) uint32 {
	status := s.InternalApi.InternalGetOption(s.InternalHandle, option, value)
	runtime.KeepAlive(value)
	return status
}

func (s *InternalLdapSession) InternalSetUint(option, value uint32) error {
	return InternalLdapStatus(
		fmt.Sprintf("ldap_set_optionW(%d)", option),
		s.InternalSetRawOption(int32(option), unsafe.Pointer(&value)),
	)
}

func (s *InternalLdapSession) InternalSetTimeouts(wait time.Duration) error {
	seconds := InternalSecondsCeiling(wait)
	if err := s.InternalSetUint(ldap.LDAP_OPT_SEND_TIMEOUT, seconds); err != nil {
		return err
	}
	return s.InternalSetUint(ldap.LDAP_OPT_TIMELIMIT, seconds)
}

func InternalRemainingWait(ctx context.Context, limit time.Duration) (time.Duration, error) {
	if err := context.Cause(ctx); err != nil {
		return 0, err
	}
	if deadline, ok := ctx.Deadline(); ok {
		remaining := time.Until(deadline)
		if remaining <= 0 {
			return 0, context.DeadlineExceeded
		}
		if remaining < limit {
			limit = remaining
		}
	}
	return limit, nil
}

func InternalSecondsCeiling(wait time.Duration) uint32 {
	return uint32((wait + time.Second - 1) / time.Second)
}

func InternalNativeTimeval(wait time.Duration) ldap.LDAP_TIMEVAL {
	microseconds := (wait + time.Microsecond - 1) / time.Microsecond
	return ldap.LDAP_TIMEVAL{
		Tv_sec:  int32(microseconds / 1000000),
		Tv_usec: int32(microseconds % 1000000),
	}
}

func (s *InternalLdapSession) InternalClose() error {
	if s.InternalHandle == nil {
		return s.InternalCloseErr
	}
	handle := s.InternalHandle
	s.InternalHandle = nil
	s.InternalCloseErr = InternalLdapStatus("ldap_unbind", s.InternalApi.InternalUnbind(handle))
	return s.InternalCloseErr
}

func (s *InternalLdapSession) InternalSessionError(operation string) error {
	var code uint32
	if status := s.InternalGetRawOption(
		int32(ldap.LDAP_OPT_ERROR_NUMBER),
		unsafe.Pointer(&code),
	); status != 0 {
		return InternalLdapStatus("ldap_get_optionW(ERROR_NUMBER)", status)
	}
	return InternalLdapStatus(operation, code)
}
