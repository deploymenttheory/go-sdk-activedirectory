package engine

import (
	"context"
	"errors"
	"time"

	"github.com/deploymenttheory/go-sdk-activedirectory/3rd_party/gokrb5/v8/messages"
	ldap "github.com/deploymenttheory/go-sdk-activedirectory/3rd_party/ldap/v3"
	"github.com/deploymenttheory/go-sdk-activedirectory/3rd_party/ldap/v3/gssapi"
	admodel "github.com/deploymenttheory/go-sdk-activedirectory/activedirectory/internal/model"
)

func internalPortableKerberosFailure(err error) error {
	var protocol messages.KRBError
	if errors.As(err, &protocol) {
		return admodel.InternalKerberosError(protocol.ErrorCode, err)
	}
	if errors.Is(err, admodel.ErrConnection) || errors.Is(err, context.Canceled) || errors.Is(err, context.DeadlineExceeded) {
		return err
	}
	return admodel.InternalKerberosError(0, err)
}

func internalDialPortableKerberos(ctx context.Context, c admodel.Config, dialer InternalPortableDialer) (admodel.InternalDirectorySession, error) {
	mode, err := internalPortableSASLMode(c)
	if err != nil {
		return nil, err
	}
	bounded, cancel := context.WithTimeout(ctx, c.Timeout)
	defer cancel()
	client, cleanup, err := internalPortableKerberosClient(bounded, c, internalPortableKerberosConfig(c), dialer)
	if err != nil {
		return nil, internalPortableKerberosFailure(err)
	}
	defer cleanup()
	mechanism, err := gssapi.NewClient(client)
	if err != nil {
		return nil, internalPortableKerberosFailure(err)
	}
	defer mechanism.Close()
	transport, err := InternalOpenPortableTransportWithDial(bounded, c, dialer)
	if err != nil {
		return nil, err
	}
	if !transport.InternalProtection.TLSVerified && mode == ldap.SASLSecurityNone {
		return nil, errors.Join(admodel.ErrTLSNegotiation, transport.InternalConn.Close())
	}
	session := internalNewPortableSession(transport, c.Timeout)
	var result *ldap.GSSAPIBindResult
	err = session.invoke(bounded, "Kerberos bind", func() error {
		var bindErr error
		result, bindErr = session.ldap.GSSAPIBindRequestWithResult(mechanism, &ldap.GSSAPIBindRequest{
			ServicePrincipalName: c.Kerberos.SPN, SASLSecurity: mode, ChannelBinding: transport.InternalProtection.TLSVerified,
		}, nil)
		return bindErr
	})
	if err != nil {
		return nil, errors.Join(internalPortableKerberosFailure(err), session.InternalClose())
	}
	if result == nil || !result.ProtectionEstablished || !result.Authentication.Complete || !result.Authentication.MutualAuthentication ||
		result.Authentication.ChannelBindingSent != transport.InternalProtection.TLSVerified || result.Authentication.ChannelBound || result.Authentication.Delegated ||
		result.Authentication.ExpiresAt.IsZero() || !time.Now().Before(result.Authentication.ExpiresAt) || result.SASLSecurity != mode {
		return nil, errors.Join(admodel.InternalKerberosError(0, admodel.ErrInvalidResult), session.InternalClose())
	}
	observedSASL, err := internalPortableObservedSASL(result.SASLSecurity)
	if err != nil {
		return nil, errors.Join(err, session.InternalClose())
	}
	session.kerberosExpiresAt = result.Authentication.ExpiresAt
	session.protection.Authentication = admodel.AuthenticationKerberos
	session.protection.SASLProtection = observedSASL
	session.protection.SASLCipherBits = result.SASLCipherBits
	session.protection.SASLEncryptionType = result.SASLEncryptionType
	session.protection.MutualAuthentication = result.Authentication.MutualAuthentication
	session.protection.ChannelBindingSent = result.Authentication.ChannelBindingSent
	session.protection.Complete = true
	return session, nil
}
