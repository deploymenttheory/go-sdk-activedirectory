// Package rpcwire owns the bounded, serialized TCP RPC association used by the
// isolated diagnostic prototype. It does not register providers or dial fallbacks.
package rpcwire

import (
	"encoding/binary"
	"errors"
)

const (
	HeaderSize          = 16
	RequestSize         = 24
	SecurityTrailerSize = 8
	ObjectUUIDSize      = 16
)

type PacketType uint8

const (
	PacketTypeRequest  PacketType = 0
	PacketTypeResponse PacketType = 2
	PacketTypeFault    PacketType = 3
	PacketTypeBind     PacketType = 11
	PacketTypeBindAck  PacketType = 12
	PacketTypeBindNak  PacketType = 13
	PacketTypeAuth3    PacketType = 16
)

type PacketFlag uint8

const (
	PacketFlagFirstFrag         PacketFlag = 1
	PacketFlagLastFrag          PacketFlag = 2
	PacketFlagSupportHeaderSign PacketFlag = 4
	PacketFlagObjectUUID        PacketFlag = 128
)

func (f PacketFlag) IsSet(value PacketFlag) bool { return f&value != 0 }

type (
	AuthType  uint8
	AuthLevel uint8
)

const (
	AuthTypeKerberos    AuthType  = 16
	AuthLevelPktPrivacy AuthLevel = 6
)

var (
	ErrMalformedFragment = errors.New("malformed RPC fragment")
	ErrPacketTooLong     = errors.New("RPC packet or complete stub exceeds limit")
	ErrBufferTooSmall    = errors.New("RPC fragment buffer is invalid")
	ErrNoSecurityContext = errors.New("RPC record security context is invalid")
	ErrClosed            = errors.New("RPC association is closed")
)

type Header struct {
	RPCVersion, RPCVersionMinor uint8
	PacketType                  PacketType
	PacketFlags                 PacketFlag
	PacketDRep                  [4]byte
	FragLength, AuthLength      uint16
	CallID                      uint32
}

func defaultDataRepresentation() [4]byte { return [4]byte{16, 0, 0, 0} }

func decodeHeader(frame []byte) (h Header, err error) {
	if len(frame) < HeaderSize {
		return h, ErrMalformedFragment
	}
	h.RPCVersion, h.RPCVersionMinor = frame[0], frame[1]
	h.PacketType, h.PacketFlags = PacketType(frame[2]), PacketFlag(frame[3])
	copy(h.PacketDRep[:], frame[4:8])
	h.FragLength, h.AuthLength = binary.LittleEndian.Uint16(frame[8:]), binary.LittleEndian.Uint16(frame[10:])
	h.CallID = binary.LittleEndian.Uint32(frame[12:])
	return h, nil
}

func (h Header) validateFragment(available int) error {
	if h.RPCVersion != 5 || h.RPCVersionMinor != 0 || h.PacketDRep != defaultDataRepresentation() {
		return ErrMalformedFragment
	}
	length := int(h.FragLength)
	if length < HeaderSize || length > available {
		return ErrMalformedFragment
	}
	if h.AuthLength != 0 && int(h.AuthLength)+SecurityTrailerSize > length-HeaderSize {
		return ErrMalformedFragment
	}
	return nil
}

func (h Header) validatePDU(available int) error {
	if err := h.validateFragment(available); err != nil {
		return err
	}
	var minimum int
	switch h.PacketType {
	case PacketTypeRequest, PacketTypeResponse:
		minimum = 24
		if h.PacketFlags.IsSet(PacketFlagObjectUUID) {
			minimum += 16
		}
	case PacketTypeFault:
		minimum = 32
	case PacketTypeBind:
		minimum = 28
	case PacketTypeBindAck:
		minimum = 26
	case PacketTypeBindNak:
		minimum = 18
	case PacketTypeAuth3:
		minimum = 20
	default:
		return ErrMalformedFragment
	}
	remaining := int(h.FragLength) - minimum
	if h.AuthLength != 0 {
		remaining -= SecurityTrailerSize + int(h.AuthLength)
	}
	if remaining < 0 {
		return ErrMalformedFragment
	}
	return nil
}
