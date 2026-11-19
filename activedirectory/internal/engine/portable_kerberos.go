package engine

import (
	"context"
	"errors"
	"time"

	krbclient "github.com/deploymenttheory/go-sdk-activedirectory/3rd_party/gokrb5/v8/client"
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
	return internalDialPortableKerberosWithFactory(ctx, c, dialer, internalPortableKerberosMechanism)
}

type internalKerberosMechanismFactory func(*krbclient.Client) (ldap.GSSAPIClient, func() error, error)

func internalPortableKerberosMechanism(client *krbclient.Client) (ldap.GSSAPIClient, func() error, error) {
	mechanism, err := gssapi.NewClient(client)
	if err != nil {
		return nil, nil, err
	}
	return mechanism, mechanism.Close, nil
}

// The production caller always supplies the fixed factory above. An engine
// test binary may supply a per-call mechanism to prove server refusal of a
// missing or tampered binding, without a public opt-out or mutable global.
func internalDialPortableKerberosWithFactory(
	ctx context.Context,
	c admodel.Config,
	dialer InternalPortableDialer,
	factory internalKerberosMechanismFactory,
) (admodel.InternalDirectorySession, error) {
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
	mechanism, closeMechanism, err := factory(client)
	if err != nil {
		return nil, internalPortableKerberosFailure(err)
	}
	// The production mechanism cleanup only retires local keys; it performs no
	// network I/O. Socket ownership remains with the session below.
	defer func() { _ = closeMechanism() }()
	if c.AllowDelegation {
		forwarder, ok := mechanism.(interface{ SetDelegation(bool) error })
		if !ok {
			return nil, admodel.ErrMoveDelegation
		}
		if err := forwarder.SetDelegation(true); err != nil {
			return nil, errors.Join(admodel.ErrMoveDelegation, err)
		}
	}
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
		result.Authentication.ChannelBindingSent != transport.InternalProtection.TLSVerified || result.Authentication.ChannelBound ||
		result.Authentication.Delegated != c.AllowDelegation || result.Authentication.DelegationSent != c.AllowDelegation ||
		result.Authentication.ExpiresAt.IsZero() || !time.Now().Before(result.Authentication.ExpiresAt) || result.SASLSecurity != mode {
		return nil, errors.Join(admodel.InternalKerberosError(0, admodel.ErrInvalidResult), session.InternalClose())
	}
	if c.AllowDelegation && (result.Authentication.DelegationExpiresAt.IsZero() || !time.Now().Before(result.Authentication.DelegationExpiresAt)) {
		return nil, errors.Join(admodel.ErrMoveDelegation, session.InternalClose())
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
	session.protection.DelegationSent = result.Authentication.DelegationSent
	session.protection.Delegated = result.Authentication.Delegated
	session.protection.DelegationExpiresAt = result.Authentication.DelegationExpiresAt
	session.protection.Complete = true
	return session, nil
}
