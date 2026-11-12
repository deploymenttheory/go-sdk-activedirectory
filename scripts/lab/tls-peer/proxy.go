package main

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"fmt"
	"io"
	"net"
	"net/netip"
	"os"
	"strconv"
	"strings"
)

func validateUpstream(cfg serveOptions) error {
	if cfg.upstream == "" {
		if cfg.upstreamCA != "" || cfg.upstreamName != "" {
			return errArguments
		}
		return nil
	}
	host, port, err := net.SplitHostPort(cfg.upstream)
	if err != nil || cfg.upstreamCA == "" || !labName.MatchString(cfg.upstreamName) ||
		!strings.HasSuffix(cfg.upstreamName, ".ad.sdk.test") {
		return errArguments
	}
	number, err := strconv.Atoi(port)
	if err != nil || number < 1 || number > 65535 {
		return errArguments
	}
	address, err := netip.ParseAddr(host)
	if err == nil {
		if !address.IsPrivate() && !address.IsLoopback() {
			return errArguments
		}
	} else if !labName.MatchString(host) || !strings.HasSuffix(host, ".ad.sdk.test") {
		return errArguments
	}
	return nil
}

func connectUpstream(ctx context.Context, cfg serveOptions) (*tls.Conn, error) {
	publicCA, err := os.ReadFile(cfg.upstreamCA)
	if err != nil {
		return nil, fmt.Errorf("read upstream public root: %w", err)
	}
	roots := x509.NewCertPool()
	if !roots.AppendCertsFromPEM(publicCA) {
		return nil, errArguments
	}
	host, port, err := net.SplitHostPort(cfg.upstream)
	if err != nil {
		return nil, errArguments
	}
	addresses, err := net.DefaultResolver.LookupNetIP(ctx, "ip", host)
	if err != nil || len(addresses) == 0 {
		return nil, errArguments
	}
	for _, address := range addresses {
		if !address.IsPrivate() && !address.IsLoopback() {
			return nil, errArguments
		}
	}
	// Dial the verified numeric address so DNS cannot change between the check
	// and connection. Certificate hostname verification uses the explicit name.
	dialer := &tls.Dialer{
		Config: &tls.Config{
			RootCAs:    roots,
			ServerName: cfg.upstreamName,
			MinVersion: tls.VersionTLS12,
		},
	}
	conn, err := dialer.DialContext(ctx, "tcp", net.JoinHostPort(addresses[0].String(), port))
	if err != nil {
		return nil, fmt.Errorf("validate upstream TLS: %w", err)
	}
	secure := conn.(*tls.Conn)
	deadline, _ := ctx.Deadline()
	if err := secure.SetDeadline(deadline); err != nil {
		_ = secure.Close()
		return nil, fmt.Errorf("bound upstream lifetime: %w", err)
	}
	return secure, nil
}

func relayLDAP(ctx context.Context, front, upstream net.Conn, result *connectionResult) {
	type responseResult struct {
		bytes int64
		err   error
	}
	done := make(chan responseResult, 1)
	go func() {
		buffer := make([]byte, 32*1024)
		n, err := io.CopyBuffer(front, io.LimitReader(upstream, maxLDAPBytes), buffer)
		clear(buffer)
		// Unblock the client reader when the upstream closes or reaches its cap.
		_ = front.Close()
		done <- responseResult{n, err}
	}()
	readClientLDAP(ctx, front, upstream, result)
	_ = upstream.Close()
	response := <-done
	result.UpstreamBytesReceived = response.bytes
	if response.bytes == maxLDAPBytes {
		result.UpstreamErrorCategory = "byte_limit"
	} else if response.err != nil && result.UpstreamErrorCategory == "" {
		result.UpstreamErrorCategory = errorCategory(response.err, ctx)
	}
}
