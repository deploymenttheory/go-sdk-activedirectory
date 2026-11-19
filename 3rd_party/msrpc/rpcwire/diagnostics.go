package rpcwire

import (
	"context"
	"errors"

	"github.com/deploymenttheory/go-sdk-activedirectory/3rd_party/msrpc/drsrwire"
	"github.com/deploymenttheory/go-sdk-activedirectory/3rd_party/msrpc/epmwire"
)

// EndpointReply records separately the map and optional handle-free statuses.
// Port is an authenticated mapping for the original selected host only.
type EndpointReply struct {
	Port       uint16
	MapStatus  uint32
	FreeStatus uint32
}

func (c *Client) MapDRSPort(ctx context.Context) (reply EndpointReply, err error) {
	if c.stage != EndpointMapping {
		return reply, ErrUnsupportedOperation
	}
	stub, err := c.Call(ctx, 3, epmwire.MapRequest())
	if err != nil {
		return reply, err
	}
	defer clear(stub)
	mapped, err := epmwire.DecodeMap(ctx, stub)
	if err != nil {
		return reply, c.stream.retire(err)
	}
	reply.Port, reply.MapStatus = mapped.Port, mapped.Status
	if mapped.Handle == [20]byte{} {
		return reply, nil
	}
	stub, err = c.Call(ctx, 4, epmwire.FreeRequest(mapped.Handle))
	if err != nil {
		return reply, err
	}
	defer clear(stub)
	reply.FreeStatus, err = epmwire.DecodeFree(ctx, stub)
	if err != nil {
		return reply, c.stream.retire(err)
	}
	return reply, nil
}

// BindDiagnostics obtains a DRS handle on this same authenticated association.
// A returned status is an actual DRS result, never a translated network error.
func (c *Client) BindDiagnostics(ctx context.Context) (drsrwire.BindReply, error) {
	if c.stage != DirectoryReplication {
		return drsrwire.BindReply{}, ErrUnsupportedOperation
	}
	stub, err := c.Call(ctx, 0, drsrwire.BindRequest())
	if err != nil {
		return drsrwire.BindReply{}, err
	}
	defer clear(stub)
	reply, err := drsrwire.DecodeBind(ctx, stub)
	if err != nil {
		return reply, c.stream.retire(err)
	}
	return reply, nil
}

// ReadReplicationInfo retains a valid copied prefix when bounded NDR decoding
// detects malformed later records. Such a response retires the association.
func (c *Client) ReadReplicationInfo(ctx context.Context, handle drsrwire.ContextHandle, kind uint32, objectDN *string) (drsrwire.Reply, error) {
	if c.stage != DirectoryReplication {
		return drsrwire.Reply{}, ErrUnsupportedOperation
	}
	request, err := drsrwire.ReplicationInfoRequest(ctx, handle, kind, objectDN)
	if err != nil {
		return drsrwire.Reply{}, err
	}
	stub, err := c.Call(ctx, 19, request)
	if err != nil {
		return drsrwire.Reply{}, err
	}
	defer clear(stub)
	reply, err := drsrwire.DecodeReplicationInfo(ctx, kind, stub)
	if err != nil {
		return reply, c.stream.retire(err)
	}
	return reply, nil
}

func (c *Client) UnbindDiagnostics(ctx context.Context, handle drsrwire.ContextHandle) (uint32, error) {
	if c.stage != DirectoryReplication || handle == [20]byte{} {
		return 0, ErrUnsupportedOperation
	}
	stub, err := c.Call(ctx, 1, drsrwire.UnbindRequest(handle))
	if err != nil {
		return 0, err
	}
	defer clear(stub)
	status, err := drsrwire.DecodeUnbind(ctx, stub)
	if err != nil {
		return 0, c.stream.retire(err)
	}
	return status, nil
}

// Retire discards the association after an adapter-level identity or semantic
// failure. It never starts another authentication exchange or endpoint attempt.
func (c *Client) Retire(cause error) error {
	if cause == nil {
		cause = ErrClosed
	}
	return c.stream.retire(errors.Join(ErrClosed, cause))
}
