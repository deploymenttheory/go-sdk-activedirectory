// Package epmwire implements the bounded NDR32 endpoint-map subset used by the
// isolated replication transport. Returned addresses are never routing inputs.
package epmwire

import (
	"bytes"
	"context"
	"encoding/binary"
	"errors"
	"fmt"
)

var (
	ErrMalformed  = errors.New("malformed RPC endpoint-map response")
	ErrNoEndpoint = errors.New("RPC endpoint mapper returned no matching TCP endpoint")
)

// MapReply keeps the actual server status separate from local decoding failures.
// Handle is copied for a bounded lookup-handle-free on the same association.
type MapReply struct {
	Handle [20]byte
	Port   uint16
	Status uint32
}

var (
	drsUUID = [16]byte{0x35, 0x42, 0x51, 0xe3, 0x06, 0x4b, 0xd1, 0x11, 0xab, 4, 0, 0xc0, 0x4f, 0xc2, 0xdc, 0xd2}
	ndrUUID = [16]byte{4, 0x5d, 0x88, 0x8a, 0xeb, 0x1c, 0xc9, 0x11, 0x9f, 0xe8, 8, 0, 0x2b, 0x10, 0x48, 0x60}
)

func tower(port uint16) []byte {
	out := make([]byte, 75)
	binary.LittleEndian.PutUint16(out, 5)
	offset := 2
	for i, id := range [][16]byte{drsUUID, ndrUUID} {
		binary.LittleEndian.PutUint16(out[offset:], 19)
		out[offset+2] = 0x0d
		copy(out[offset+3:], id[:])
		binary.LittleEndian.PutUint16(out[offset+19:], [2]uint16{4, 2}[i])
		binary.LittleEndian.PutUint16(out[offset+21:], 2)
		offset += 25
	}
	for i, protocol := range []byte{0x0b, 7, 9} {
		binary.LittleEndian.PutUint16(out[offset:], 1)
		out[offset+2] = protocol
		size := 2
		if i == 2 {
			size = 4
		}
		binary.LittleEndian.PutUint16(out[offset+3:], uint16(size))
		if protocol == 7 {
			binary.BigEndian.PutUint16(out[offset+5:], port)
		}
		offset += 5 + size
	}
	return out
}

// MapRequest asks only for the DRS v4/NDR32 connection-oriented TCP interface.
// It uses a null object and lookup handle and requests exactly one tower.
func MapRequest() []byte {
	out := make([]byte, 116)
	binary.LittleEndian.PutUint32(out[4:], 5)
	binary.LittleEndian.PutUint32(out[8:], 75)
	binary.LittleEndian.PutUint32(out[12:], 75)
	copy(out[16:], tower(0))
	binary.LittleEndian.PutUint32(out[112:], 1)
	return out
}

// DecodeMap accepts one complete authenticated ept_map response. It validates
// every tower floor but returns only its bounded port: the selected host stays
// pinned by the caller, including when an advertised IP differs.
func DecodeMap(ctx context.Context, stub []byte) (reply MapReply, err error) {
	if cause := context.Cause(ctx); cause != nil {
		return reply, fmt.Errorf("decode RPC endpoint map: %w", cause)
	}
	if len(stub) < 40 || len(stub) > 4096 {
		return reply, ErrMalformed
	}
	copy(reply.Handle[:], stub[:20])
	count, maximum, offset, actual := u32(stub[20:]), u32(stub[24:]), u32(stub[28:]), u32(stub[32:])
	if count > 1 || maximum != 1 || offset != 0 || actual != count {
		return MapReply{}, ErrMalformed
	}
	end := 36
	if count == 1 {
		if len(stub) < 48 || u32(stub[36:]) == 0 {
			return MapReply{}, ErrMalformed
		}
		maximum, length := u32(stub[40:]), u32(stub[44:])
		if maximum != 75 || length != 75 || len(stub) != 128 {
			return MapReply{}, ErrMalformed
		}
		value := stub[48:123]
		port := binary.BigEndian.Uint16(value[64:66])
		expected := tower(port)
		// The final IPv4 address is structurally valid opaque metadata. Never
		// return or follow it; all earlier floors must match exactly.
		if !bytes.Equal(value[:71], expected[:71]) {
			return MapReply{}, ErrMalformed
		}
		reply.Port = port
		end = 124
	}
	if end+4 != len(stub) {
		return MapReply{}, ErrMalformed
	}
	reply.Status = u32(stub[end:])
	if reply.Status != 0 {
		return MapReply{Status: reply.Status}, nil
	}
	if count == 0 || reply.Port == 0 {
		return reply, ErrNoEndpoint
	}
	return reply, nil
}

// FreeRequest copies an issued lookup handle; no new association is created.
func FreeRequest(handle [20]byte) []byte { return append([]byte(nil), handle[:]...) }

func DecodeFree(ctx context.Context, stub []byte) (status uint32, err error) {
	if cause := context.Cause(ctx); cause != nil {
		return 0, fmt.Errorf("decode RPC lookup-handle free: %w", cause)
	}
	if len(stub) != 24 {
		return 0, ErrMalformed
	}
	return u32(stub[20:]), nil
}

func u32(b []byte) uint32 { return binary.LittleEndian.Uint32(b) }
