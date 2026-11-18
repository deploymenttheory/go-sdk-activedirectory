package engine

import (
	"context"
	"errors"
	"net"

	ldap "github.com/deploymenttheory/go-sdk-activedirectory/3rd_party/ldap/v3"
	admodel "github.com/deploymenttheory/go-sdk-activedirectory/activedirectory/internal/model"
)

// InternalDialPortable establishes one verified TLS channel, then explicitly
// binds the selected identity. Unsupported authentication never falls back.
func InternalDialPortable(ctx context.Context, config admodel.Config) (admodel.InternalDirectorySession, error) {
	return InternalDialPortableWithDial(ctx, config, &net.Dialer{})
}

// InternalDialPortableWithDial supplies the same owned transport boundary for
// actual-socket fixtures; the dialer never receives authentication material.
func InternalDialPortableWithDial(ctx context.Context, config admodel.Config, dialer InternalPortableDialer) (admodel.InternalDirectorySession, error) {
	config, err := admodel.InternalConfigNormalized(config)
	if err != nil {
		return nil, err
	}
	if config.Backend != admodel.BackendPortable {
		return nil, admodel.ErrInvalidConfig
	}
	if config.Authentication != admodel.AuthenticationSimple {
		return nil, &admodel.BackendUnavailableError{
			Backend:        admodel.BackendPortable,
			Authentication: config.Authentication,
			Feature:        "the selected portable authentication mechanism",
		}
	}
	transport, err := InternalOpenPortableTransportWithDial(ctx, config, dialer)
	if err != nil {
		return nil, err
	}
	if !transport.InternalProtection.TLSVerified {
		return nil, errors.Join(admodel.ErrTLSNegotiation, transport.InternalConn.Close())
	}
	session := internalNewPortableSession(transport, config.Timeout)
	err = session.invoke(ctx, "bind", func() error {
		_, bindErr := session.ldap.SimpleBind(&ldap.SimpleBindRequest{Username: config.Credentials.Username, Password: string(config.Credentials.Password)})
		return bindErr
	})
	if err != nil {
		return nil, errors.Join(err, session.InternalClose())
	}
	session.protection.Authentication = admodel.AuthenticationSimple
	session.protection.SASLProtection = admodel.SASLProtectionNone
	session.protection.Complete = true
	return session, nil
}
