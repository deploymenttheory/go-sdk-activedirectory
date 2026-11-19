package drsrwire

import (
	"context"
	"encoding/binary"
	"errors"
	"fmt"
)

var ErrUnsupportedServer = errors.New("DRS server did not advertise replication diagnostic support")

// ContextHandle contains opaque copied NDR context-handle bytes. It is valid
// only on the authenticated association that returned it.
type ContextHandle [20]byte

// BindReply exposes only decoded facts and an exact DRS return status. The
// server's epoch is informational; a non-DC client never adopts or retries it.
type BindReply struct {
	Handle           ContextHandle
	Flags            uint32
	ReplicationEpoch uint32
	Status           uint32
}

// BindRequest identifies a non-DC diagnostic caller and advertises only the
// ignored BASE and required POST_BETA3 bits. No replication/password capability
// or session-key-export facility is offered by this read-only client.
func BindRequest() []byte {
	out := make([]byte, 84)
	binary.LittleEndian.PutUint32(out, 1)
	copy(out[4:], []byte{0x1a, 0x20, 0x4d, 0xe2, 0xd6, 0x4f, 0xd1, 0x11, 0xa3, 0xda, 0, 0, 0xf8, 0x75, 0xae, 0x0d})
	binary.LittleEndian.PutUint32(out[20:], 21)
	binary.LittleEndian.PutUint32(out[24:], 52)
	binary.LittleEndian.PutUint32(out[28:], 52)
	binary.LittleEndian.PutUint32(out[32:], 0x00080001)
	return out
}

func DecodeBind(ctx context.Context, stub []byte) (reply BindReply, err error) {
	if len(stub) > 10040 {
		return reply, ErrNDRLimit
	}
	c := &cursor{ctx: ctx, data: stub}
	present := c.u32() != 0
	var extension []byte
	if present {
		maximum, length := c.u32(), c.u32()
		if c.err != nil {
			return reply, c.err
		}
		if length > 10000 {
			return reply, ErrNDRLimit
		}
		if length < 1 || maximum != length {
			return reply, ErrMalformedNDR
		}
		extension = c.take(int(length), 1)
	}
	copy(reply.Handle[:], c.take(20, 4))
	status := c.u32()
	if c.err != nil {
		return BindReply{}, c.err
	}
	if c.offset != len(stub) {
		return BindReply{}, ErrMalformedNDR
	}
	reply.Status = status
	if status != 0 {
		return BindReply{Status: status}, nil
	}
	if len(extension) < 4 || reply.Handle == [20]byte{} {
		return BindReply{}, ErrMalformedNDR
	}
	reply.Flags = binary.LittleEndian.Uint32(extension)
	if len(extension) >= 28 {
		reply.ReplicationEpoch = binary.LittleEndian.Uint32(extension[24:])
	}
	if reply.Flags&0x00004000 == 0 {
		return reply, ErrUnsupportedServer
	}
	return reply, nil
}

func UnbindRequest(handle ContextHandle) []byte { return append([]byte(nil), handle[:]...) }

func DecodeUnbind(ctx context.Context, stub []byte) (status uint32, err error) {
	if cause := context.Cause(ctx); cause != nil {
		return 0, fmt.Errorf("decode DRS unbind: %w", cause)
	}
	if len(stub) != 24 {
		return 0, ErrMalformedNDR
	}
	return binary.LittleEndian.Uint32(stub[20:]), nil
}
