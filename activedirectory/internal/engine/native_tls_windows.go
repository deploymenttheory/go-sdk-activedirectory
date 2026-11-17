//go:build windows && (amd64 || arm64)

package engine

import (
	"context"
	"errors"
	"fmt"
	"sync"
	"syscall"
	"unsafe"

	"github.com/deploymenttheory/go-bindings-win32/bindings/win32/networking/ldap"
	"github.com/deploymenttheory/go-bindings-win32/bindings/win32/security/authentication/identity"
	"github.com/deploymenttheory/go-bindings-win32/bindings/win32/security/cryptography"
	admodel "github.com/deploymenttheory/go-sdk-activedirectory/activedirectory/internal/model"
)

const InternalSchannelFlags = uint32(
	identity.SCH_CRED_AUTO_CRED_VALIDATION | identity.SCH_CRED_NO_DEFAULT_CREDS | identity.SCH_USE_STRONG_CRYPTO,
)

// Go callback thunks are not released. One lazy, process-wide callback has no
// captured session state and remains valid through every unbind.
var InternalNoTLSClientCertificate = sync.OnceValue(func() ldap.QUERYCLIENTCERT {
	return ldap.QUERYCLIENTCERT(syscall.NewCallbackCDecl(InternalDeclineTLSClientCertificate))
})

func InternalDeclineTLSClientCertificate(
	*ldap.LDAP,
	*identity.SecPkgContext_IssuerListInfoEx,
	**cryptography.CERT_CONTEXT,
) uintptr {
	return 0
}

func (s *InternalLdapSession) InternalConfigureTLS() error {
	// WinLDAP derives the default-client-credential flags from callback presence.
	// Decline client certificates explicitly; leave the SERVER callback unset so
	// Schannel validates Windows trust and the configured endpoint automatically.
	if status := s.InternalApi.InternalSetClientCertificate(
		s.InternalHandle,
		InternalNoTLSClientCertificate(),
	); status != 0 {
		return InternalLdapStatus("ldap_set_optionW(CLIENT_CERTIFICATE)", status)
	}
	return s.InternalSetUint(ldap.LDAP_OPT_SCH_FLAGS, InternalSchannelFlags)
}

func (s *InternalLdapSession) InternalStartTLS(ctx context.Context) error {
	wait, err := InternalRemainingWait(ctx, s.InternalTimeout)
	if err != nil {
		return err
	}
	if err := s.InternalSetTimeouts(wait); err != nil {
		return err
	}
	if err := context.Cause(ctx); err != nil {
		return err
	}
	var serverCode uint32
	var message *ldap.LDAPMessage
	status := s.InternalApi.InternalStartTLS(s.InternalHandle, &serverCode, &message, nil, nil)
	err = errors.Join(
		InternalLdapStatus("ldap_start_tls_sW", status),
		InternalLdapStatus("ldap_start_tls_sW server", serverCode),
		context.Cause(ctx),
	)
	if message != nil {
		err = errors.Join(err, s.InternalReadTLSResponse(message))
	}
	if err != nil {
		return errors.Join(err, s.InternalTlsFailure("ldap_start_tls_sW", 0))
	}
	return nil
}

func (s *InternalLdapSession) InternalReadTLSResponse(message *ldap.LDAPMessage) (err error) {
	defer func() {
		err = errors.Join(
			err,
			InternalLdapStatus("ldap_msgfree", s.InternalApi.InternalMessageFree(message)),
		)
	}()
	return s.InternalParseResponse(message, "ldap_start_tls_sW server")
}

func (s *InternalLdapSession) InternalVerifyTLS(transport admodel.Transport) error {
	// SSL_INFO is negotiated state. The SSL option is also required for direct
	// LDAPS; its value after StartTLS is not specified by the native contract.
	if transport == admodel.TransportLDAPS {
		var enabled uint32
		if status := s.InternalGetRawOption(
			int32(ldap.LDAP_OPT_SSL),
			unsafe.Pointer(&enabled),
		); status != 0 {
			return errors.Join(
				admodel.ErrTLSNegotiation,
				InternalLdapStatus("ldap_get_optionW(TLS)", status),
			)
		}
		if enabled == 0 {
			return fmt.Errorf("%w: LDAPS is not enabled", admodel.ErrTLSNegotiation)
		}
	}
	var flags uint32
	if status := s.InternalGetRawOption(
		int32(ldap.LDAP_OPT_SCH_FLAGS),
		unsafe.Pointer(&flags),
	); status != 0 {
		return errors.Join(
			admodel.ErrTLSNegotiation,
			InternalLdapStatus("ldap_get_optionW(SCH_FLAGS)", status),
		)
	}
	if flags&InternalSchannelFlags != InternalSchannelFlags ||
		flags&uint32(
			identity.SCH_CRED_MANUAL_CRED_VALIDATION|identity.SCH_CRED_NO_SERVERNAME_CHECK|identity.SCH_CRED_USE_DEFAULT_CREDS,
		) != 0 {
		return fmt.Errorf(
			"%w: requested certificate validation policy is not enabled (Schannel flags %#x)",
			admodel.ErrTLSNegotiation,
			flags,
		)
	}
	var connection identity.SecPkgContext_ConnectionInfo
	if status := s.InternalGetRawOption(
		int32(ldap.LDAP_OPT_SSL_INFO),
		unsafe.Pointer(&connection),
	); status != 0 {
		return errors.Join(
			admodel.ErrTLSNegotiation,
			InternalLdapStatus("ldap_get_optionW(SSL_INFO)", status),
		)
	}
	if connection.DwProtocol != identity.SP_PROT_TLS1_2_CLIENT &&
		connection.DwProtocol != identity.SP_PROT_TLS1_3_CLIENT {
		return fmt.Errorf(
			"%w: negotiated protocol %#x is not TLS 1.2 or 1.3",
			admodel.ErrTLSNegotiation,
			connection.DwProtocol,
		)
	}
	if connection.DwCipherStrength < 128 {
		return fmt.Errorf(
			"%w: negotiated cipher strength is below 128 bits",
			admodel.ErrTLSNegotiation,
		)
	}
	return nil
}

func (s *InternalLdapSession) InternalTlsFailure(operation string, code uint32) error {
	err := errors.Join(admodel.ErrTLSNegotiation, InternalLdapStatus(operation, code))
	var extended uint32
	status := s.InternalGetRawOption(
		int32(ldap.LDAP_OPT_SERVER_EXT_ERROR),
		unsafe.Pointer(&extended),
	)
	err = errors.Join(err, InternalLdapStatus("ldap_get_optionW(SERVER_EXT_ERROR)", status))
	if status == 0 && extended != 0 {
		err = errors.Join(err, fmt.Errorf("LDAP TLS server status: %w", syscall.Errno(extended)))
	}
	return err
}
