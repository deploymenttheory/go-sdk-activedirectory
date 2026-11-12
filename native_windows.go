//go:build windows && (amd64 || arm64)

package activedirectory

import (
	"context"
	"errors"
	"fmt"
	"runtime"
	"time"
	"unsafe"

	"github.com/deploymenttheory/go-bindings-win32/bindings/win32/networking/ldap"
)

type ldapSession struct {
	api      ldapAPI
	handle   *ldap.LDAP
	timeout  time.Duration
	closeErr error
}

func ldapStatus(operation string, code uint32) error {
	if code == 0 {
		return nil
	}
	return &LDAPError{Operation: operation, Code: code}
}

func dialNative(ctx context.Context, config Config) (directorySession, error) {
	return dialWithAPI(ctx, config, systemLDAPAPI())
}

func dialWithAPI(ctx context.Context, config Config, api ldapAPI) (result directorySession, err error) {
	if err := api.available(); err != nil {
		return nil, err
	}
	if config.Credentials != nil {
		if err := config.Credentials.validate(); err != nil {
			return nil, err
		}
		if err := api.credentialAvailable(); err != nil {
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
	handle := api.init(config.Endpoint.Host, uint32(config.Endpoint.Port))
	if handle == nil {
		status := api.lastError()
		if status == 0 {
			return nil, fmt.Errorf("%w: ldap_initW returned NULL without an error", ErrInvalidResult)
		}
		return nil, ldapStatus("ldap_initW", status)
	}
	session := &ldapSession{api: api, handle: handle, timeout: config.Timeout}
	defer func() {
		if err != nil {
			err = errors.Join(err, session.close())
		}
	}()
	for _, option := range []struct{ code, value uint32 }{
		{ldap.LDAP_OPT_PROTOCOL_VERSION, ldap.LDAP_VERSION3},
		{ldap.LDAP_OPT_AREC_EXCLUSIVE, 1},
		{ldap.LDAP_OPT_AUTO_RECONNECT, 0},
		{ldap.LDAP_OPT_PROMPT_CREDENTIALS, 0},
		{ldap.LDAP_OPT_REFERRALS, 0},
		{ldap.LDAP_OPT_ROOTDSE_CACHE, 0},
		{ldap.LDAP_OPT_SIGN, 1},
		{ldap.LDAP_OPT_ENCRYPT, 1},
	} {
		if err := session.setUint(option.code, option.value); err != nil {
			return nil, err
		}
	}
	wait, err := remainingWait(ctx, config.Timeout)
	if err != nil {
		return nil, err
	}
	if err := session.setTimeouts(wait); err != nil {
		return nil, err
	}
	timeout := nativeTimeval(wait)
	status := api.connect(handle, &timeout)
	if err := errors.Join(ldapStatus("ldap_connect", status), context.Cause(ctx)); err != nil {
		return nil, err
	}
	wait, err = remainingWait(ctx, config.Timeout)
	if err != nil {
		return nil, err
	}
	if err := session.setTimeouts(wait); err != nil {
		return nil, err
	}
	// This SDK-header macro is absent from WinMD's projected constants:
	// LDAP_AUTH_NEGOTIATE = LDAP_AUTH_OTHERKIND | 0x0400.
	// https://github.com/microsoft/win32metadata/blob/main/generation/WinSDK/RecompiledIdlHeaders/um/Winldap.h
	const negotiate = uint32(ldap.LDAP_AUTH_OTHERKIND) | 0x0400
	status = bindIdentity(api, handle, config.Credentials, negotiate)
	if err := errors.Join(ldapStatus("ldap_bind_sW", status), context.Cause(ctx)); err != nil {
		return nil, err
	}
	return session, nil
}

func (s *ldapSession) setUint(option, value uint32) error {
	return ldapStatus(fmt.Sprintf("ldap_set_optionW(%d)", option), s.api.setOption(s.handle, int32(option), unsafe.Pointer(&value)))
}

func (s *ldapSession) setTimeouts(wait time.Duration) error {
	seconds := secondsCeiling(wait)
	if err := s.setUint(ldap.LDAP_OPT_SEND_TIMEOUT, seconds); err != nil {
		return err
	}
	return s.setUint(ldap.LDAP_OPT_TIMELIMIT, seconds)
}

func remainingWait(ctx context.Context, limit time.Duration) (time.Duration, error) {
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

func secondsCeiling(wait time.Duration) uint32 {
	return uint32((wait + time.Second - 1) / time.Second)
}

func nativeTimeval(wait time.Duration) ldap.LDAP_TIMEVAL {
	microseconds := (wait + time.Microsecond - 1) / time.Microsecond
	return ldap.LDAP_TIMEVAL{Tv_sec: int32(microseconds / 1000000), Tv_usec: int32(microseconds % 1000000)}
}

func (s *ldapSession) close() error {
	if s.handle == nil {
		return s.closeErr
	}
	handle := s.handle
	s.handle = nil
	s.closeErr = ldapStatus("ldap_unbind", s.api.unbind(handle))
	return s.closeErr
}

func (s *ldapSession) sessionError(operation string) error {
	var code uint32
	if status := s.api.getOption(s.handle, int32(ldap.LDAP_OPT_ERROR_NUMBER), unsafe.Pointer(&code)); status != 0 {
		return ldapStatus("ldap_get_optionW(ERROR_NUMBER)", status)
	}
	return ldapStatus(operation, code)
}
