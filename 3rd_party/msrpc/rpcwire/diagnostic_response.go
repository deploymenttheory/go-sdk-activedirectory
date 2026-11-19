package rpcwire

import (
	"context"

	"github.com/deploymenttheory/go-sdk-activedirectory/3rd_party/msrpc/drsrwire"
)

// replicationInfo composes the actual protected stream and bounded diagnostic
// decoder. It remains unreachable without the pending authenticated adapter.
func (s *protectedStream) replicationInfo(ctx context.Context, kind uint32, request []byte) (drsrwire.Reply, error) {
	stub, err := s.exchange(ctx, 19, request)
	if err != nil {
		return drsrwire.Reply{}, err
	}
	defer clear(stub)
	reply, err := drsrwire.DecodeReplicationInfo(ctx, kind, stub)
	if err != nil {
		return reply, s.retire(err)
	}
	return reply, nil
}
