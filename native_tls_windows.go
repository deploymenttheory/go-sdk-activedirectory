//go:build windows && (amd64 || arm64)

package activedirectory

import (
	"context"
	"errors"
	"fmt"
	"syscall"
	"unsafe"

	"github.com/deploymenttheory/go-bindings-win32/bindings/win32/networking/ldap"
	"github.com/deploymenttheory/go-bindings-win32/bindings/win32/security/authentication/identity"
)

const schannelFlags = uint32(identity.SCH_CRED_AUTO_CRED_VALIDATION | identity.SCH_CRED_NO_DEFAULT_CREDS | identity.SCH_USE_STRONG_CRYPTO)

func (s *ldapSession) configureTLS() error {
	// Leave certificate callbacks unset: Schannel validates the certificate using
	// Windows trust and the single configured endpoint. No manual/name bypass.
	return s.setUint(ldap.LDAP_OPT_SCH_FLAGS, schannelFlags)
}

func (s *ldapSession) startTLS(ctx context.Context) error {
	wait, err := remainingWait(ctx, s.timeout)
	if err != nil {
		return err
	}
	if err := s.setTimeouts(wait); err != nil {
		return err
	}
	if err := context.Cause(ctx); err != nil {
		return err
	}
	var serverCode uint32
	var message *ldap.LDAPMessage
	status := s.api.startTLS(s.handle, &serverCode, &message, nil, nil)
	err = errors.Join(ldapStatus("ldap_start_tls_sW", status), ldapStatus("ldap_start_tls_sW server", serverCode), context.Cause(ctx))
	if message != nil {
		err = errors.Join(err, s.readTLSResponse(message))
	}
	if err != nil {
		return errors.Join(err, s.tlsFailure("ldap_start_tls_sW", 0))
	}
	return nil
}

func (s *ldapSession) readTLSResponse(message *ldap.LDAPMessage) (err error) {
	defer func() { err = errors.Join(err, ldapStatus("ldap_msgfree", s.api.messageFree(message))) }()
	return s.parseResponse(message, "ldap_start_tls_sW server")
}

func (s *ldapSession) verifyTLS(transport Transport) error {
	// SSL_INFO is negotiated state. The SSL option is also required for direct
	// LDAPS; its value after StartTLS is not specified by the native contract.
	if transport == TransportLDAPS {
		var enabled uint32
		if status := s.api.getOption(s.handle, int32(ldap.LDAP_OPT_SSL), unsafe.Pointer(&enabled)); status != 0 {
			return errors.Join(ErrTLSNegotiation, ldapStatus("ldap_get_optionW(TLS)", status))
		}
		if enabled == 0 {
			return fmt.Errorf("%w: LDAPS is not enabled", ErrTLSNegotiation)
		}
	}
	var flags uint32
	if status := s.api.getOption(s.handle, int32(ldap.LDAP_OPT_SCH_FLAGS), unsafe.Pointer(&flags)); status != 0 {
		return errors.Join(ErrTLSNegotiation, ldapStatus("ldap_get_optionW(SCH_FLAGS)", status))
	}
	if flags&schannelFlags != schannelFlags ||
		flags&uint32(identity.SCH_CRED_MANUAL_CRED_VALIDATION|identity.SCH_CRED_NO_SERVERNAME_CHECK|identity.SCH_CRED_USE_DEFAULT_CREDS) != 0 {
		return fmt.Errorf("%w: requested certificate validation policy is not enabled", ErrTLSNegotiation)
	}
	var connection identity.SecPkgContext_ConnectionInfo
	if status := s.api.getOption(s.handle, int32(ldap.LDAP_OPT_SSL_INFO), unsafe.Pointer(&connection)); status != 0 {
		return errors.Join(ErrTLSNegotiation, ldapStatus("ldap_get_optionW(SSL_INFO)", status))
	}
	if connection.DwProtocol != identity.SP_PROT_TLS1_2_CLIENT && connection.DwProtocol != identity.SP_PROT_TLS1_3_CLIENT {
		return fmt.Errorf("%w: negotiated protocol %#x is not TLS 1.2 or 1.3", ErrTLSNegotiation, connection.DwProtocol)
	}
	if connection.DwCipherStrength < 128 {
		return fmt.Errorf("%w: negotiated cipher strength is below 128 bits", ErrTLSNegotiation)
	}
	return nil
}

func (s *ldapSession) tlsFailure(operation string, code uint32) error {
	err := errors.Join(ErrTLSNegotiation, ldapStatus(operation, code))
	var extended uint32
	status := s.api.getOption(s.handle, int32(ldap.LDAP_OPT_SERVER_EXT_ERROR), unsafe.Pointer(&extended))
	err = errors.Join(err, ldapStatus("ldap_get_optionW(SERVER_EXT_ERROR)", status))
	if status == 0 && extended != 0 {
		err = errors.Join(err, fmt.Errorf("LDAP TLS server status: %w", syscall.Errno(extended)))
	}
	return err
}
