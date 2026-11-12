package activedirectory

import (
	"context"
	"errors"
	"sync"
)

var (
	ErrUnsupported      = errors.New("Active Directory native API unavailable; execution requires Windows amd64 or arm64")
	ErrClosed           = errors.New("Active Directory client is closed")
	ErrInvalidResult    = errors.New("invalid LDAP result")
	ErrInvalidProperty  = errors.New("invalid LDAP attribute selection")
	ErrIncompleteResult = errors.New("LDAP result requires additional retrieval")
	ErrTLSNegotiation   = errors.New("validated TLS connection could not be established")
)

// LDAPError preserves LDAP status separately from Windows system error codes.
// Diagnostic and MatchedDN may contain directory information; Error deliberately
// omits them so ordinary error logging does not disclose server diagnostics.
type LDAPError struct {
	Operation  string
	Code       uint32
	Diagnostic string
	MatchedDN  string
}

type directorySession interface {
	baseObject(context.Context, string, []string) (map[string][][]byte, error)
	close() error
}

// Client owns one authenticated LDAP session pinned to its configured endpoint.
// Calls are serialized. A Client must not be copied after construction. Close
// cancels active reads and waits for their native calls before releasing memory.
type Client struct {
	config    Config
	session   directorySession
	gate      chan struct{}
	lifetime  context.Context
	cancel    context.CancelCauseFunc
	closeOnce sync.Once
	closeErr  error
}

// Dial connects using the configured transport and authentication. Plain LDAP
// uses Negotiate signing/sealing; TLS completes before credentials are sent.
// It disables automatic reconnect and referral chasing.
// No PowerShell, RSAT, or remote agent is involved. Context cancellation is
// observed between native calls; synchronous connect/bind calls must return
// before cancellation can be reported. See Config.Timeout for their bounds.
func Dial(ctx context.Context, config Config) (*Client, error) {
	config, err := config.normalized()
	if err != nil {
		return nil, err
	}
	if err := context.Cause(ctx); err != nil {
		return nil, err
	}
	session, err := dialNative(ctx, config)
	if err != nil {
		return nil, err
	}
	return newClient(config, session), nil
}

func newClient(config Config, session directorySession) *Client {
	config.Credentials = nil
	lifetime, cancel := context.WithCancelCause(context.Background())
	client := &Client{config: config, session: session, gate: make(chan struct{}, 1), lifetime: lifetime, cancel: cancel}
	client.gate <- struct{}{}
	return client
}

// RootDSE reads the server's root entry. The result contains copied raw values
// and typed fields. On failure it may contain partial data; callers must inspect
// the error before treating the projection as complete.
func (c *Client) RootDSE(ctx context.Context, options RootDSEOptions) (RootDSE, error) {
	if c == nil || c.session == nil {
		return RootDSE{}, ErrClosed
	}
	properties, err := options.attributes()
	if err != nil {
		return RootDSE{}, err
	}
	var result RootDSE
	err = c.read(ctx, func(bounded context.Context) error {
		attributes, readErr := c.session.baseObject(bounded, "", properties)
		var decodeErr error
		result, decodeErr = decodeRootDSE(attributes, properties)
		return errors.Join(readErr, decodeErr)
	})
	return result, err
}

// read holds the session gate across every stage of one read operation.
func (c *Client) read(ctx context.Context, operationRead func(context.Context) error) error {
	if c == nil || c.session == nil {
		return ErrClosed
	}
	select {
	case <-ctx.Done():
		return context.Cause(ctx)
	case <-c.lifetime.Done():
		return ErrClosed
	case <-c.gate:
	}
	defer func() { c.gate <- struct{}{} }()
	if err := context.Cause(ctx); err != nil {
		return err
	}
	if err := context.Cause(c.lifetime); err != nil {
		return err
	}
	operation, cancel := context.WithCancelCause(ctx)
	stop := context.AfterFunc(c.lifetime, func() { cancel(ErrClosed) })
	defer stop()
	defer cancel(nil)
	bounded, finish := context.WithTimeout(operation, c.config.Timeout)
	defer finish()
	return errors.Join(operationRead(bounded), context.Cause(bounded))
}

// Close prevents new operations, cancels an active read, and unbinds exactly
// once after native use ends. Concurrent/repeated calls return the same error.
// A native synchronous call can delay Close until its configured wait returns.
func (c *Client) Close() error {
	if c == nil || c.session == nil {
		return nil
	}
	c.closeOnce.Do(func() {
		c.cancel(ErrClosed)
		<-c.gate
		defer func() { c.gate <- struct{}{} }()
		c.closeErr = c.session.close()
	})
	return c.closeErr
}
