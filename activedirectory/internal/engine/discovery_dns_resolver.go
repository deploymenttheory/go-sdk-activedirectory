package engine

import (
	"context"
	"errors"
	"net"
)

// A fresh standard-library resolver preserves the platform's configured DNS
// interfaces. Forcing PreferGo on Windows excludes DNS-only private adapters
// without a gateway in Go1.27.4; no AD locator, realm or join identity is inferred.
func internalDiscoverySystemResolver() *net.Resolver {
	return &net.Resolver{StrictErrors: true}
}

type internalDiscoverySRVReply struct {
	canonical string
	records   []*net.SRV
}

type internalDiscoveryDNSReply[T any] struct {
	value T
	err   error
}

// Windows DnsQuery can continue after cancellation. Bound the caller's wait
// independently, retain completed partial replies, and discard late OS results.
// The buffered result belongs only to this query; it never writes SDK output.
func internalDiscoveryLookup[T any](ctx context.Context, operation func() (T, error)) (T, error) {
	var zero T
	if cause := InternalConnectionContextCause(ctx); cause != nil {
		return zero, cause
	}
	replies := make(chan internalDiscoveryDNSReply[T], 1)
	go func() { value, err := operation(); replies <- internalDiscoveryDNSReply[T]{value: value, err: err} }()
	select {
	case reply := <-replies:
		return reply.value, errors.Join(reply.err, InternalConnectionContextCause(ctx))
	case <-ctx.Done():
		return zero, InternalConnectionContextCause(ctx)
	}
}
