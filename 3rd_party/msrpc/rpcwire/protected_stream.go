package rpcwire

import (
	"context"
	"encoding/binary"
	"errors"
	"fmt"
	"math"
	"time"
)

const (
	maxProtectedStub      = 16 << 20
	maxProtectedFragments = 1 << 16
)

// rpcRecordCipher is owned by a single already authenticated association. The
// stream does not perform Kerberos authentication or manufacture protection facts.
type rpcRecordCipher interface {
	WrapEx(context.Context, uint64, [][]byte, [][]byte) ([]byte, error)
	UnwrapEx(context.Context, uint64, [][]byte, [][]byte, []byte) (bool, error)
	Size(context.Context, bool) int
	Destroy()
}

// protectedStream deliberately omits multiplexing, transport reuse and retries.
// A failed record poisons its connection and both directional keys immediately.
type protectedStream struct {
	gate                          chan struct{}
	transport                     *transport
	send, receive                 rpcRecordCipher
	sendSequence, receiveSequence uint64
	callID                        uint32
	presentationID                uint16
	securityID                    uint32
}

// FaultError contains the actual status from a verified protected RPC fault.
// Transport failures and unprotected bind negotiation never create this type.
type FaultError struct{ Status uint32 }

func (e *FaultError) Error() string {
	return fmt.Sprintf("authenticated RPC fault status %d", e.Status)
}

type rpcFaultError = FaultError

func newProtectedStream(raw RawConn, send, receive rpcRecordCipher, maxFragment int, presentation uint16, security uint32) (*protectedStream, error) {
	if raw == nil || send == nil || receive == nil || maxFragment < 128 || maxFragment > math.MaxUint16 {
		return nil, ErrBufferTooSmall
	}
	settings := NewTransport()
	settings.MaxRecvFrag, settings.MaxXmitFrag = maxFragment, maxFragment
	settings.Timeout = 30 * time.Second
	return &protectedStream{
		gate: make(chan struct{}, 1), transport: &transport{settings: &settings, cc: NewBufferedConn(raw, maxFragment)},
		send: send, receive: receive, presentationID: presentation, securityID: security,
	}, nil
}

func (s *protectedStream) retire(err error) error {
	err = s.transport.retire(err)
	s.send.Destroy()
	s.receive.Destroy()
	return err
}

// exchange is reachable only from the future authenticated adapter, not the SDK
// dispatcher. A synthetic pre-established record context can exercise this seam.
func (s *protectedStream) exchange(ctx context.Context, opnum uint16, stub []byte) ([]byte, error) {
	return s.exchangeWithTail(ctx, opnum, stub, 0)
}

// exchangeWithTail keeps a verification trailer wholly in the final request
// fragment. The tail is protocol data, never authentication padding.
func (s *protectedStream) exchangeWithTail(ctx context.Context, opnum uint16, stub []byte, minimumTail int) ([]byte, error) {
	select {
	case s.gate <- struct{}{}:
	case <-ctx.Done():
		return nil, fmt.Errorf("wait for RPC operation: %w", context.Cause(ctx))
	}
	defer func() { <-s.gate }()
	if err := context.Cause(ctx); err != nil {
		return nil, fmt.Errorf("begin RPC operation: %w", err)
	}
	if err := s.transport.HasErr(); err != nil {
		return nil, err
	}
	if len(stub) > maxProtectedStub || s.callID == math.MaxUint32 {
		return nil, s.retire(ErrPacketTooLong)
	}
	if s.transport.settings.Timeout > 0 {
		var cancel context.CancelFunc
		ctx, cancel = context.WithTimeout(ctx, s.transport.settings.Timeout)
		defer cancel()
	}
	s.callID++
	remaining := stub
	first := true
	for fragments := 0; first || len(remaining) > 0; fragments++ {
		if fragments >= maxProtectedFragments {
			return nil, s.retire(ErrPacketTooLong)
		}
		signatureSize := s.send.Size(ctx, true)
		capacity := (s.transport.settings.MaxXmitFrag - RequestSize - SecurityTrailerSize - signatureSize) &^ 15
		if capacity < 1 || signatureSize < 16 || signatureSize > 512 || minimumTail > capacity || minimumTail > len(stub) || minimumTail < 0 {
			return nil, s.retire(ErrBufferTooSmall)
		}
		count := min(len(remaining), capacity)
		if len(remaining) > capacity && len(remaining)-count < minimumTail {
			count = len(remaining) - minimumTail
		}
		last := count == len(remaining)
		if err := s.writeRequest(ctx, opnum, remaining[:count], first, last); err != nil {
			return nil, s.retire(err)
		}
		remaining = remaining[count:]
		first = false
	}
	var result []byte
	first = true
	for fragments := 0; ; fragments++ {
		if fragments >= maxProtectedFragments {
			return result, s.retire(ErrPacketTooLong)
		}
		frame := make([]byte, s.transport.settings.MaxRecvFrag)
		hdr, err := s.transport.ReadBuffer(ctx, frame)
		if err != nil {
			return result, s.retire(err)
		}
		frame = frame[:hdr.FragLength]
		part, last, err := s.readResponse(ctx, hdr, frame, first)
		if err != nil {
			return result, s.retire(err)
		}
		if len(part) > maxProtectedStub-len(result) {
			return result, s.retire(ErrPacketTooLong)
		}
		if len(part) == 0 && !last {
			return result, s.retire(ErrMalformedFragment)
		}
		result = append(result, part...)
		clear(part)
		if last {
			return result, nil
		}
		first = false
	}
}

func (s *protectedStream) writeRequest(ctx context.Context, opnum uint16, stub []byte, first, last bool) error {
	if s.sendSequence == math.MaxUint64 {
		return ErrNoSecurityContext
	}
	pad := (-len(stub)) & 15
	stubLength, signatureLength := len(stub), s.send.Size(ctx, true)
	if stubLength > math.MaxUint16 || signatureLength < 16 || signatureLength > 512 {
		return ErrPacketTooLong
	}
	length := RequestSize + stubLength + pad + SecurityTrailerSize + signatureLength
	if length < 0 || length > math.MaxUint16 || length > s.transport.settings.MaxXmitFrag {
		return ErrPacketTooLong
	}
	frame := make([]byte, length)
	defer clear(frame)
	frame[0], frame[2], frame[4] = 5, byte(PacketTypeRequest), 0x10
	if first {
		frame[3] |= byte(PacketFlagFirstFrag)
	}
	if last {
		frame[3] |= byte(PacketFlagLastFrag)
	}
	binary.LittleEndian.PutUint16(frame[8:], uint16(length))
	binary.LittleEndian.PutUint16(frame[10:], uint16(signatureLength))
	binary.LittleEndian.PutUint32(frame[12:], s.callID)
	// MS-RPCE 2.2.2.6 requires acceptance of a zero allocation hint. Use zero
	// consistently so it cannot misdescribe the remaining fragmented stub.
	binary.LittleEndian.PutUint16(frame[20:], s.presentationID)
	binary.LittleEndian.PutUint16(frame[22:], opnum)
	copy(frame[RequestSize:], stub)
	end := RequestSize + len(stub) + pad
	trailer := frame[end : end+SecurityTrailerSize]
	trailer[0], trailer[1], trailer[2] = byte(AuthTypeKerberos), byte(AuthLevelPktPrivacy), byte(pad)
	binary.LittleEndian.PutUint32(trailer[4:], s.securityID)
	body := frame[RequestSize:end]
	token, err := s.send.WrapEx(ctx, s.sendSequence, [][]byte{frame[:RequestSize], body, trailer}, [][]byte{body})
	if err != nil {
		return err
	}
	if len(token) != s.send.Size(ctx, true) {
		return ErrNoSecurityContext
	}
	copy(frame[end+SecurityTrailerSize:], token)
	header, err := decodeHeader(frame[:HeaderSize])
	if err != nil {
		return err
	}
	if err := s.transport.WriteBuffer(ctx, header, frame); err != nil {
		return err
	}
	s.sendSequence++
	return nil
}

func (s *protectedStream) readResponse(ctx context.Context, hdr Header, frame []byte, first bool) ([]byte, bool, error) {
	if err := hdr.validatePDU(len(frame)); err != nil {
		return nil, false, err
	}
	if hdr.CallID != s.callID || hdr.PacketFlags.IsSet(PacketFlagFirstFrag) != first || hdr.PacketFlags.IsSet(PacketFlagObjectUUID) {
		return nil, false, ErrMalformedFragment
	}
	headerSize := RequestSize
	if hdr.PacketType == PacketTypeFault {
		headerSize = 32
	} else if hdr.PacketType != PacketTypeResponse {
		return nil, false, ErrMalformedFragment
	}
	if hdr.AuthLength < 16 || s.receiveSequence == math.MaxUint64 {
		return nil, false, ErrNoSecurityContext
	}
	end := len(frame) - int(hdr.AuthLength) - SecurityTrailerSize
	if end < headerSize || (end-headerSize)&15 != 0 {
		return nil, false, ErrMalformedFragment
	}
	trailer := frame[end : end+SecurityTrailerSize]
	pad := int(trailer[2])
	if trailer[0] != byte(AuthTypeKerberos) || trailer[1] != byte(AuthLevelPktPrivacy) || trailer[3] != 0 ||
		binary.LittleEndian.Uint32(trailer[4:]) != s.securityID || pad > 15 || pad > end-headerSize ||
		binary.LittleEndian.Uint16(frame[20:]) != s.presentationID {
		return nil, false, ErrNoSecurityContext
	}
	body := frame[headerSize:end]
	ok, err := s.receive.UnwrapEx(ctx, s.receiveSequence, [][]byte{frame[:headerSize], body, trailer}, [][]byte{body}, frame[end+SecurityTrailerSize:])
	if err != nil || !ok {
		return nil, false, errors.Join(ErrNoSecurityContext, err)
	}
	s.receiveSequence++
	last := hdr.PacketFlags.IsSet(PacketFlagLastFrag)
	if hdr.PacketType == PacketTypeFault {
		if !first || !last {
			return nil, false, ErrMalformedFragment
		}
		return nil, false, &rpcFaultError{Status: binary.LittleEndian.Uint32(frame[24:])}
	}
	return body[:len(body)-pad], last, nil
}
