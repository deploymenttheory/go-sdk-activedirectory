package engine

import (
	"context"
	"crypto/tls"
	"errors"
	"fmt"
	"net"
	"strconv"
	"sync"
	"time"

	admodel "github.com/deploymenttheory/go-sdk-activedirectory/activedirectory/internal/model"
)

// InternalPortableDialer supplies one owned connection. It must obey cancellation
// and must never reconnect, chase referrals, or send authentication material.
type InternalPortableDialer interface {
	DialContext(context.Context, string, string) (net.Conn, error)
}

// InternalPortableTransport transfers an owned socket only after the selected
// transport is established. TLS facts are measured; Complete and authentication
// facts remain unset until the LDAP backend actually binds. TLSState is internal
// input for certificate-derived channel binding, not caller-visible key material.
type InternalPortableTransport struct {
	InternalConn       net.Conn
	InternalTLSState   tls.ConnectionState
	InternalProtection admodel.SessionProtection
}

type portableOwnedConn struct {
	net.Conn
	closeOnce sync.Once
	closeErr  error
}

func (c *portableOwnedConn) Close() error {
	c.closeOnce.Do(func() { c.closeErr = c.Conn.Close() })
	return c.closeErr
}

// InternalOpenPortableTransport establishes exactly one endpoint connection.
// StartTLS is completed before a library reader starts, and no bind/write is sent.
func InternalOpenPortableTransport(ctx context.Context, config admodel.Config) (*InternalPortableTransport, error) {
	return InternalOpenPortableTransportWithDial(ctx, config, &net.Dialer{})
}

// InternalOpenPortableTransportWithDial is the same ownership boundary with an
// explicit dialer for actual-socket fixtures. Failed establishment closes the
// connection once and returns no usable socket; plaintext fallback is forbidden.
func InternalOpenPortableTransportWithDial(
	ctx context.Context,
	config admodel.Config,
	dialer InternalPortableDialer,
) (result *InternalPortableTransport, err error) {
	config, err = admodel.InternalConfigNormalized(config)
	if err != nil {
		return nil, err
	}
	if config.Backend != admodel.BackendPortable || dialer == nil {
		return nil, fmt.Errorf("%w: portable transport requires a portable backend and dialer", admodel.ErrInvalidConfig)
	}
	if config.Authentication == admodel.AuthenticationNegotiate {
		return nil, &admodel.BackendUnavailableError{
			Backend: config.Backend, Authentication: config.Authentication, Feature: "Windows integrated authentication",
		}
	}
	bounded, cancel := context.WithTimeout(ctx, config.Timeout)
	defer cancel()
	if cause := InternalConnectionContextCause(bounded); cause != nil {
		return nil, errors.Join(admodel.ErrConnection, cause)
	}
	raw, err := dialer.DialContext(bounded, "tcp", net.JoinHostPort(config.Endpoint.Host, strconv.Itoa(int(config.Endpoint.Port))))
	if err != nil {
		if raw != nil {
			err = errors.Join(err, raw.Close())
		}
		return nil, errors.Join(admodel.ErrConnection, fmt.Errorf("connect portable LDAP: %w", err), InternalConnectionContextCause(bounded))
	}
	if raw == nil {
		return nil, fmt.Errorf("%w: transport dialer returned no connection", admodel.ErrConnection)
	}
	owned := &portableOwnedConn{Conn: raw}
	cancelledClose := make(chan struct{})
	stop := context.AfterFunc(bounded, func() {
		defer close(cancelledClose)
		_ = owned.Close()
	})
	defer func() {
		if !stop() {
			<-cancelledClose
		}
		if cause := InternalConnectionContextCause(bounded); cause != nil {
			err = errors.Join(err, admodel.ErrConnection, cause)
		}
		if err != nil {
			err = errors.Join(err, owned.Close())
			result = nil
		}
	}()
	if cause := InternalConnectionContextCause(bounded); cause != nil {
		return nil, cause
	}
	deadline, _ := bounded.Deadline()
	if err := owned.SetDeadline(deadline); err != nil {
		return nil, errors.Join(admodel.ErrConnection, fmt.Errorf("bound portable connection: %w", err))
	}
	result = &InternalPortableTransport{
		InternalConn:       owned,
		InternalProtection: admodel.SessionProtection{Backend: admodel.BackendPortable, Transport: config.Transport},
	}
	if config.Transport == admodel.TransportStartTLS {
		if err := InternalRequestPortableStartTLS(owned); err != nil {
			return nil, errors.Join(admodel.ErrConnection, admodel.ErrTLSNegotiation, err)
		}
	}
	if config.Transport != admodel.TransportLDAP {
		secured, state, err := internalVerifyPortableTLS(bounded, owned, config)
		if err != nil {
			return nil, errors.Join(admodel.ErrConnection, admodel.ErrTLSNegotiation, err)
		}
		result.InternalConn, result.InternalTLSState = secured, state
		result.InternalProtection.TLSVerified = true
		result.InternalProtection.TLSVersion = state.Version
		result.InternalProtection.TLSCipherSuite = state.CipherSuite
		result.InternalProtection.CipherBits = internalPortableCipherBits(state.CipherSuite)
	}
	if err := result.InternalConn.SetDeadline(time.Time{}); err != nil {
		return nil, errors.Join(admodel.ErrConnection, fmt.Errorf("release portable connection deadline: %w", err))
	}
	return result, nil
}

func internalVerifyPortableTLS(ctx context.Context, raw net.Conn, config admodel.Config) (*tls.Conn, tls.ConnectionState, error) {
	options := &tls.Config{
		MinVersion: tls.VersionTLS12,
		ServerName: config.Endpoint.Host,
		CipherSuites: []uint16{
			tls.TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256, tls.TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256,
			tls.TLS_ECDHE_ECDSA_WITH_AES_256_GCM_SHA384, tls.TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384,
			tls.TLS_ECDHE_ECDSA_WITH_CHACHA20_POLY1305_SHA256, tls.TLS_ECDHE_RSA_WITH_CHACHA20_POLY1305_SHA256,
		},
	}
	if config.TLS != nil && config.TLS.RootCAs != nil {
		options.RootCAs = config.TLS.RootCAs.Clone()
	}
	secured := tls.Client(raw, options)
	if err := secured.HandshakeContext(ctx); err != nil {
		return nil, tls.ConnectionState{}, fmt.Errorf("verify portable TLS: %w", err)
	}
	state := secured.ConnectionState()
	if !state.HandshakeComplete || state.Version < tls.VersionTLS12 || len(state.VerifiedChains) == 0 ||
		internalPortableCipherBits(state.CipherSuite) < 128 {
		return nil, state, fmt.Errorf("%w: negotiated TLS state does not establish the required protection", admodel.ErrTLSNegotiation)
	}
	return secured, state, nil
}

func internalPortableCipherBits(suite uint16) uint32 {
	switch suite {
	case tls.TLS_AES_128_GCM_SHA256, tls.TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256, tls.TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256:
		return 128
	case tls.TLS_AES_256_GCM_SHA384, tls.TLS_CHACHA20_POLY1305_SHA256,
		tls.TLS_ECDHE_ECDSA_WITH_AES_256_GCM_SHA384, tls.TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384,
		tls.TLS_ECDHE_ECDSA_WITH_CHACHA20_POLY1305_SHA256, tls.TLS_ECDHE_RSA_WITH_CHACHA20_POLY1305_SHA256:
		return 256
	default:
		return 0
	}
}
