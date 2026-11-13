package main

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"errors"
	"flag"
	"fmt"
	"io"
	"net"
	"net/netip"
	"os"
	"path/filepath"
	"time"
)

type peerResult struct {
	Mode                     string             `json:"mode"`
	Address                  string             `json:"address"`
	ConfiguredCertificate    certificateInfo    `json:"configured_certificate"`
	TimeoutSeconds           float64            `json:"timeout_seconds"`
	ConnectionTimeoutSeconds float64            `json:"connection_timeout_seconds"`
	ConnectionLimit          int                `json:"connection_limit"`
	Outcome                  string             `json:"outcome"`
	Connections              []connectionResult `json:"connections"`
}

type connectionResult struct {
	SelectedCertificate       *certificateInfo `json:"selected_certificate,omitempty"`
	StartTLSAccepted          bool             `json:"starttls_accepted"`
	HandshakeComplete         bool             `json:"handshake_complete"`
	TLSVersion                uint16           `json:"tls_version"`
	CipherSuite               uint16           `json:"cipher_suite"`
	BindRequests              int              `json:"bind_requests"`
	PlaintextBinds            int              `json:"plaintext_bind_requests"`
	LDAPBytesReceived         int64            `json:"ldap_bytes_received"`
	LDAPBytesForwarded        int64            `json:"ldap_bytes_forwarded"`
	UpstreamHandshakeComplete bool             `json:"upstream_handshake_complete"`
	UpstreamCertificate       *certificateInfo `json:"upstream_certificate,omitempty"`
	UpstreamBytesReceived     int64            `json:"upstream_bytes_received"`
	UpstreamErrorCategory     string           `json:"upstream_error_category,omitempty"`
	ErrorCategory             string           `json:"error_category,omitempty"`
}

type serveOptions struct {
	mode, listen, cert, key, ready, result string
	upstream, upstreamCA, upstreamName     string
	connections                            int
	timeout, connectionTimeout             time.Duration
}

func parseServe(args []string) (serveOptions, error) {
	var cfg serveOptions
	fs := flag.NewFlagSet("serve", flag.ContinueOnError)
	fs.SetOutput(io.Discard)
	fs.StringVar(&cfg.mode, "mode", "", "ldaps or starttls")
	fs.StringVar(&cfg.listen, "listen", "", "numeric private or loopback address:port")
	fs.StringVar(&cfg.cert, "cert", "", "owned leaf PEM")
	fs.StringVar(&cfg.key, "key", "", "owned private key PEM")
	fs.StringVar(&cfg.ready, "ready", "", "new readiness JSON path")
	fs.StringVar(&cfg.result, "result", "", "new result JSON path")
	fs.StringVar(&cfg.upstream, "upstream", "", "optional owned LDAPS endpoint")
	fs.StringVar(&cfg.upstreamCA, "upstream-ca", "", "explicit public CA PEM for upstream")
	fs.StringVar(&cfg.upstreamName, "upstream-name", "", "expected upstream certificate FQDN")
	fs.IntVar(&cfg.connections, "connections", 1, "bounded sequential connection count")
	fs.DurationVar(&cfg.timeout, "timeout", time.Minute, "total listener lifetime")
	fs.DurationVar(
		&cfg.connectionTimeout,
		"connection-timeout",
		15*time.Second,
		"maximum connection lifetime",
	)
	if err := fs.Parse(args); err != nil || fs.NArg() != 0 {
		return cfg, errArguments
	}
	address, err := netip.ParseAddrPort(cfg.listen)
	if err != nil || (!address.Addr().IsPrivate() && !address.Addr().IsLoopback()) ||
		(cfg.mode != "ldaps" && cfg.mode != "starttls") || cfg.cert == "" || cfg.key == "" ||
		cfg.connections < 1 || cfg.connections > 16 || cfg.timeout < time.Second || cfg.timeout > 10*time.Minute ||
		cfg.connectionTimeout < time.Second || cfg.connectionTimeout > time.Minute {
		return cfg, errArguments
	}
	if cfg.ready == "" || cfg.result == "" ||
		filepath.Clean(cfg.ready) == filepath.Clean(cfg.result) {
		return cfg, errArguments
	}
	for _, path := range []string{cfg.ready, cfg.result} {
		if _, err := os.Lstat(path); !errors.Is(err, os.ErrNotExist) {
			return cfg, errArguments
		}
	}
	if err := validateUpstream(cfg); err != nil {
		return cfg, err
	}
	return cfg, nil
}

func serve(parent context.Context, args []string) error {
	cfg, err := parseServe(args)
	if err != nil {
		return err
	}
	cert, err := tls.LoadX509KeyPair(cfg.cert, cfg.key)
	if err != nil {
		return fmt.Errorf("load fixture identity: %w", err)
	}
	leaf, err := x509.ParseCertificate(cert.Certificate[0])
	if err != nil {
		return fmt.Errorf("parse fixture identity: %w", err)
	}
	ctx, cancel := context.WithTimeout(parent, cfg.timeout)
	defer cancel()
	var lc net.ListenConfig
	listener, err := lc.Listen(ctx, "tcp", cfg.listen)
	if err != nil {
		return fmt.Errorf("listen: %w", err)
	}
	defer func() { _ = listener.Close() }()
	stop := context.AfterFunc(ctx, func() { _ = listener.Close() })
	defer stop()
	result := peerResult{
		Mode:                     cfg.mode,
		Address:                  listener.Addr().String(),
		ConfiguredCertificate:    describeCertificate(leaf),
		TimeoutSeconds:           cfg.timeout.Seconds(),
		ConnectionTimeoutSeconds: cfg.connectionTimeout.Seconds(),
		ConnectionLimit:          cfg.connections,
		Outcome:                  "connection_limit",
		Connections:              []connectionResult{},
	}
	if err := publishJSON(cfg.ready, struct {
		Address string `json:"address"`
		Mode    string `json:"mode"`
		PID     int    `json:"pid"`
	}{result.Address, cfg.mode, os.Getpid()}); err != nil {
		return err
	}
	for range cfg.connections {
		conn, err := listener.Accept()
		if err != nil {
			result.Outcome = errorCategory(err, ctx)
			break
		}
		result.Connections = append(
			result.Connections,
			handleConnection(ctx, conn, cfg, &cert, leaf),
		)
	}
	return publishJSON(cfg.result, result)
}

func handleConnection(
	ctx context.Context,
	raw net.Conn,
	cfg serveOptions,
	cert *tls.Certificate,
	leaf *x509.Certificate,
) connectionResult {
	ctx, cancel := context.WithTimeout(ctx, cfg.connectionTimeout)
	defer cancel()
	var result connectionResult
	defer func() { _ = raw.Close() }()
	stop := context.AfterFunc(ctx, func() { _ = raw.Close() })
	defer stop()
	if err := raw.SetDeadline(time.Now().Add(cfg.connectionTimeout)); err != nil {
		result.ErrorCategory = "deadline_failure"
		return result
	}
	if cfg.mode == "starttls" {
		message, err := readLDAP(raw)
		if err != nil {
			result.ErrorCategory = errorCategory(err, ctx)
			return result
		}
		defer message.clear()
		if message.op == 0x60 {
			result.BindRequests++
			result.PlaintextBinds++
		}
		if !message.startTLS() {
			result.ErrorCategory = "starttls_required"
			return result
		}
		if err := writeAll(raw, message.startTLSResponse()); err != nil {
			result.ErrorCategory = errorCategory(err, ctx)
			return result
		}
		result.StartTLSAccepted = true
	}
	secure := tls.Server(raw, &tls.Config{
		MinVersion: tls.VersionTLS12, SessionTicketsDisabled: true,
		GetCertificate: func(*tls.ClientHelloInfo) (*tls.Certificate, error) {
			selected := describeCertificate(leaf)
			result.SelectedCertificate = &selected
			return cert, nil
		},
	})
	if err := secure.HandshakeContext(ctx); err != nil {
		result.ErrorCategory = errorCategory(err, ctx)
		return result
	}
	state := secure.ConnectionState()
	result.HandshakeComplete, result.TLSVersion, result.CipherSuite = state.HandshakeComplete, state.Version, state.CipherSuite
	if cfg.upstream != "" {
		upstream, err := connectUpstream(ctx, cfg)
		if err != nil {
			result.UpstreamErrorCategory = errorCategory(err, ctx)
			return result
		}
		result.UpstreamHandshakeComplete = true
		upstreamCert := describeCertificate(upstream.ConnectionState().PeerCertificates[0])
		result.UpstreamCertificate = &upstreamCert
		relayLDAP(ctx, secure, upstream, &result)
		return result
	}
	readClientLDAP(ctx, secure, nil, &result)
	return result
}

func readClientLDAP(
	ctx context.Context,
	secure net.Conn,
	upstream net.Conn,
	result *connectionResult,
) {
	for result.LDAPBytesReceived < maxLDAPBytes {
		message, err := readLDAP(secure)
		if err != nil {
			result.ErrorCategory = errorCategory(err, ctx)
			return
		}
		result.LDAPBytesReceived += int64(len(message.frame))
		if message.op == 0x60 {
			result.BindRequests++
		}
		if result.LDAPBytesReceived > maxLDAPBytes {
			message.clear()
			break
		}
		if upstream != nil {
			n, err := upstream.Write(message.frame)
			result.LDAPBytesForwarded += int64(n)
			if err != nil || n != len(message.frame) {
				message.clear()
				result.UpstreamErrorCategory = "upstream_write_failure"
				return
			}
		}
		unbind := message.op == 0x42
		message.clear()
		if unbind {
			return
		}
	}
	result.ErrorCategory = "byte_limit"
}

func writeAll(w io.Writer, data []byte) error {
	for len(data) != 0 {
		n, err := w.Write(data)
		if err != nil {
			return fmt.Errorf("write protocol bytes: %w", err)
		}
		if n == 0 {
			return io.ErrShortWrite
		}
		data = data[n:]
	}
	return nil
}

func errorCategory(err error, ctx context.Context) string {
	// Read the context error once. Reading it per case lets a deadline that
	// fires between two reads look like a cancellation: the first read sees
	// nil and the second a non-nil DeadlineExceeded, which then falls
	// through to "canceled". A connection's socket deadline and its context
	// deadline come from the same budget, so the socket error routinely
	// arrives inside that window.
	ctxErr := ctx.Err()
	switch {
	case errors.Is(ctxErr, context.DeadlineExceeded):
		return "timeout"
	case ctxErr != nil:
		return "canceled"
	case errors.Is(err, io.EOF):
		return "peer_closed"
	case errors.Is(err, errFraming), errors.Is(err, io.ErrUnexpectedEOF):
		return "invalid_ldap_frame"
	}
	var netError net.Error
	if errors.As(err, &netError) && netError.Timeout() {
		return "timeout"
	}
	var opError *net.OpError
	if errors.As(err, &opError) && opError.Op == "remote error" {
		return "peer_tls_alert"
	}
	return "transport_or_tls_failure"
}
