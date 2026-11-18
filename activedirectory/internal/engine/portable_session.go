package engine

import (
	"context"
	"crypto/tls"
	"errors"
	"fmt"
	"net"
	"strings"
	"sync"
	"sync/atomic"
	"time"
	"unicode/utf8"

	ldap "github.com/deploymenttheory/go-sdk-activedirectory/3rd_party/ldap/v3"
	admodel "github.com/deploymenttheory/go-sdk-activedirectory/activedirectory/internal/model"
)

type portableSessionConn struct {
	net.Conn
	state     tls.ConnectionState
	closeOnce sync.Once
	closeErr  error
}

func (c *portableSessionConn) ConnectionState() tls.ConnectionState { return c.state }
func (c *portableSessionConn) Close() error {
	c.closeOnce.Do(func() { c.closeErr = c.Conn.Close() })
	return c.closeErr
}

// InternalPortableSession owns one endpoint-pinned LDAP stream. Client serializes
// operations; cancellation and terminal protocol failures retire the socket.
type InternalPortableSession struct {
	ldap              *ldap.Conn
	raw               *portableSessionConn
	timeout           time.Duration
	protection        admodel.SessionProtection
	kerberosExpiresAt time.Time
	closed            atomic.Bool
	closeOnce         sync.Once
	closeErr          error
}

func internalNewPortableSession(transport *InternalPortableTransport, timeout time.Duration) *InternalPortableSession {
	raw := &portableSessionConn{Conn: transport.InternalConn, state: transport.InternalTLSState}
	connection := ldap.NewConn(raw, transport.InternalProtection.TLSVerified)
	connection.SetTimeout(timeout)
	connection.Start()
	return &InternalPortableSession{ldap: connection, raw: raw, timeout: timeout, protection: transport.InternalProtection}
}

// invoke has no retry. Cancellation closes the owned socket before waiting for
// library shutdown, so a blocked reader/writer cannot outlive the operation.
func (s *InternalPortableSession) invoke(ctx context.Context, operation string, call func() error) error {
	if s.closed.Load() {
		return admodel.ErrClosed
	}
	if !s.kerberosExpiresAt.IsZero() && !time.Now().Before(s.kerberosExpiresAt) {
		return errors.Join(admodel.ErrKerberosExpired, s.InternalClose())
	}
	if !s.kerberosExpiresAt.IsZero() {
		var cancel context.CancelFunc
		ctx, cancel = context.WithDeadlineCause(ctx, s.kerberosExpiresAt, admodel.ErrKerberosExpired)
		defer cancel()
	}
	bounded, cancel := context.WithTimeout(ctx, s.timeout)
	defer cancel()
	if cause := InternalConnectionContextCause(bounded); cause != nil {
		return cause
	}
	deadline, _ := bounded.Deadline()
	if err := s.raw.SetDeadline(deadline); err != nil {
		return errors.Join(admodel.ErrConnection, s.InternalClose())
	}
	finished := make(chan struct{})
	stop := context.AfterFunc(bounded, func() { _ = s.InternalClose(); close(finished) })
	rawErr := call()
	if !stop() {
		<-finished
	}
	if rawErr != nil && !internalPortableServerRefusal(rawErr) {
		_ = s.InternalClose()
	}
	if !s.closed.Load() {
		if err := s.raw.SetDeadline(time.Time{}); err != nil {
			return errors.Join(internalPortableError(operation, rawErr), admodel.ErrConnection, s.InternalClose())
		}
	}
	return errors.Join(internalPortableError(operation, rawErr), InternalConnectionContextCause(bounded))
}

// InternalClose retires the raw transport before waiting for the library reader,
// releasing the stream exactly once even when cancellation races with Close.
func (s *InternalPortableSession) InternalClose() error {
	s.closeOnce.Do(func() {
		s.closed.Store(true)
		s.closeErr = errors.Join(s.raw.Close(), s.ldap.Close())
	})
	return s.closeErr
}

func (s *InternalPortableSession) InternalSessionProtection(ctx context.Context) (admodel.SessionProtection, error) {
	protection := s.protection
	if s.closed.Load() {
		protection.Complete = false
		return protection, admodel.ErrClosed
	}
	if !s.kerberosExpiresAt.IsZero() && !time.Now().Before(s.kerberosExpiresAt) {
		protection.Complete = false
		return protection, errors.Join(admodel.ErrKerberosExpired, s.InternalClose())
	}
	if err := InternalConnectionContextCause(ctx); err != nil {
		protection.Complete = false
		return protection, err
	}
	return protection, nil
}

func (s *InternalPortableSession) InternalPasswordProtection(ctx context.Context, transport admodel.Transport) (admodel.PasswordProtection, error) {
	observed, err := s.InternalSessionProtection(ctx)
	result := admodel.PasswordProtection{Transport: observed.Transport, CipherBits: observed.CipherBits}
	if err != nil {
		return result, err
	}
	if !observed.Complete || !observed.TLSVerified || observed.Transport != transport || observed.CipherBits < 128 {
		return result, admodel.ErrPasswordProtection
	}
	return result, nil
}

type portableConnectionError struct {
	operation string
	cause     error
}

func (e *portableConnectionError) Error() string {
	return "portable LDAP " + e.operation + " connection failed"
}

func (e *portableConnectionError) Unwrap() []error { return []error{admodel.ErrConnection, e.cause} }

func internalPortableServerRefusal(err error) bool {
	var server *ldap.Error
	return errors.As(err, &server) && server.IsServerResult() && !errors.Is(err, ldap.ErrMalformedPacket)
}

func internalPortableError(operation string, err error) error {
	if err == nil {
		return nil
	}
	var server *ldap.Error
	if internalPortableServerRefusal(err) && errors.As(err, &server) {
		diagnostic := ""
		if server.Err != nil {
			diagnostic = server.Err.Error()
		}
		return &admodel.LDAPError{Operation: operation, Code: uint32(server.ResultCode), MatchedDN: server.MatchedDN, Diagnostic: diagnostic}
	}
	if errors.Is(err, ldap.ErrMalformedPacket) || (errors.As(err, &server) && server.Packet != nil && !server.IsServerResult()) {
		err = errors.Join(admodel.ErrInvalidResult, err)
	}
	return &portableConnectionError{operation: operation, cause: err}
}

func internalPortableObject(entry *ldap.Entry, allowRanges, rangeConsumer bool) (admodel.Object, error) {
	if entry == nil {
		return admodel.Object{}, admodel.ErrInvalidResult
	}
	result := admodel.Object{DistinguishedName: entry.DN, Attributes: make(map[string][][]byte, len(entry.Attributes))}
	if !utf8.ValidString(entry.DN) || strings.ContainsRune(entry.DN, 0) {
		return result, admodel.ErrInvalidResult
	}
	var incomplete error
	for _, attribute := range entry.Attributes {
		if attribute == nil {
			return result, admodel.ErrInvalidResult
		}
		key := strings.ToLower(attribute.Name)
		if strings.Contains(key, ";range=") {
			if !allowRanges {
				return result, admodel.ErrIncompleteResult
			}
			if !rangeConsumer {
				incomplete = admodel.ErrIncompleteResult
			}
		}
		if !admodel.InternalAttributeDescription.MatchString(key) && (!allowRanges || !InternalValidRangedAttribute(key)) {
			return result, admodel.ErrInvalidResult
		}
		if _, duplicate := result.Attributes[key]; duplicate {
			return result, admodel.ErrInvalidResult
		}
		values := make([][]byte, len(attribute.ByteValues))
		for i, value := range attribute.ByteValues {
			values[i] = append([]byte{}, value...)
		}
		result.Attributes[key] = values
	}
	return result, incomplete
}

func (s *InternalPortableSession) InternalBaseObject(ctx context.Context, base string, properties []string) (map[string][][]byte, error) {
	return s.internalBaseObject(ctx, base, properties, false)
}

func (s *InternalPortableSession) InternalRangedBaseObject(ctx context.Context, base string, properties []string) (map[string][][]byte, error) {
	return s.internalBaseObject(ctx, base, properties, true)
}

func (s *InternalPortableSession) internalBaseObject(ctx context.Context, base string, properties []string, ranged bool) (map[string][][]byte, error) {
	var response *ldap.SearchResult
	err := s.invoke(ctx, "base-object read", func() error {
		var readErr error
		response, readErr = s.ldap.Search(ldap.NewSearchRequest(base, ldap.ScopeBaseObject, ldap.NeverDerefAliases, 0, 0, false, "(objectClass=*)", properties, nil))
		return readErr
	})
	if response == nil {
		return nil, errors.Join(err, admodel.ErrIncompleteResult)
	}
	if len(response.Entries) != 1 {
		return nil, errors.Join(err, fmt.Errorf("%w: base-object read did not return exactly one entry", admodel.ErrInvalidResult))
	}
	object, decodeErr := internalPortableObject(response.Entries[0], ranged, ranged)
	if errors.Is(decodeErr, admodel.ErrInvalidResult) {
		decodeErr = errors.Join(decodeErr, s.InternalClose())
	}
	if len(response.Referrals) != 0 {
		err = errors.Join(err, admodel.ErrSearchReferences)
	}
	return object.Attributes, errors.Join(err, decodeErr)
}
