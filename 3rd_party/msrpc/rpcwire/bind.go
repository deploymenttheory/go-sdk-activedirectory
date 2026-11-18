package rpcwire

import (
	"bytes"
	"context"
	"encoding/binary"
	"errors"
	"fmt"
	"strings"
	"sync/atomic"
	"time"

	"github.com/deploymenttheory/go-sdk-activedirectory/3rd_party/msrpc/rpcdce"
)

type Stage uint8

const (
	EndpointMapping Stage = iota + 1
	DirectoryReplication
)

var ErrUnsupportedOperation = errors.New("unsupported RPC diagnostic operation")

type Client struct {
	stream         *protectedStream
	stage          Stage
	syntax         [20]byte
	realm, service string
	expiresAt      time.Time
	encryptionType int32
	protectedReply atomic.Bool
}

// BindRejection preserves unprotected RPC presentation negotiation values.
// Even a verified AP-REP does not authenticate the bind-ack body; these values
// must never be promoted to an authenticated server status.
type BindRejection struct{ Result, Reason uint16 }

func (e *BindRejection) Error() string {
	return fmt.Sprintf("unprotected RPC presentation rejection result%d reason%d", e.Result, e.Reason)
}

type bindRejection = BindRejection

func transferSyntax() [20]byte {
	return [20]byte{0x04, 0x5d, 0x88, 0x8a, 0xeb, 0x1c, 0xc9, 0x11, 0x9f, 0xe8, 0x08, 0x00, 0x2b, 0x10, 0x48, 0x60, 2, 0, 0, 0}
}

func interfaceSyntax(stage Stage) ([20]byte, error) {
	switch stage {
	case EndpointMapping:
		return [20]byte{0x08, 0x83, 0xaf, 0xe1, 0x1f, 0x5d, 0xc9, 0x11, 0x91, 0xa4, 0x08, 0, 0x2b, 0x14, 0xa0, 0xfa, 3, 0, 0, 0}, nil
	case DirectoryReplication:
		return [20]byte{0x35, 0x42, 0x51, 0xe3, 0x06, 0x4b, 0xd1, 0x11, 0xab, 0x04, 0, 0xc0, 0x4f, 0xc2, 0xdc, 0xd2, 4, 0, 0, 0}, nil
	default:
		return [20]byte{}, ErrUnsupportedOperation
	}
}

// Bind owns the supplied direct connection on entry. It performs a Kerberos-only
// three-leg bind for one pinned stage and requires NDR32 plus header signing.
// Final RPC protection is confirmed only by a subsequent authenticated response.
func Bind(ctx context.Context, raw RawConn, actor *rpcdce.Client, stage Stage, timeout time.Duration) (client *Client, err error) {
	if actor != nil {
		defer actor.Destroy()
	}
	if raw != nil {
		raw = &ownedRawConn{RawConn: raw}
		defer func() {
			if err != nil {
				err = errors.Join(err, raw.Close())
			}
		}()
	}
	if raw == nil || actor == nil {
		return nil, ErrNoSecurityContext
	}
	syntax, err := interfaceSyntax(stage)
	if err != nil {
		return nil, err
	}
	realm, principal := actor.TicketIdentity()
	if realm == "" || timeout <= 0 || stage == EndpointMapping && !strings.HasPrefix(principal, "RPC/") ||
		stage == DirectoryReplication && !strings.HasPrefix(principal, "ldap/") {
		return nil, rpcdce.ErrIdentity
	}
	ctx, cancel := context.WithTimeout(ctx, timeout)
	defer cancel()
	token, err := actor.Begin(ctx)
	if err != nil {
		return nil, err
	}
	settings := NewTransport()
	settings.MaxXmitFrag, settings.MaxRecvFrag = 65535, 65535
	settings.Timeout = timeout
	tr := &transport{settings: &settings, cc: NewBufferedConn(raw, 65535)}
	bind, err := bindPacket(syntax, token)
	if err != nil {
		return nil, err
	}
	header, err := decodeHeader(bind)
	if err != nil {
		return nil, err
	}
	if err = tr.WriteBuffer(ctx, header, bind); err != nil {
		return nil, err
	}
	frame := make([]byte, 65535)
	header, err = tr.ReadBuffer(ctx, frame)
	if err != nil {
		return nil, err
	}
	frame = frame[:header.FragLength]
	ack, err := readBindAck(header, frame)
	if err != nil {
		return nil, err
	}
	third, records, err := actor.Accept(ctx, ack.token)
	if err != nil {
		return nil, err
	}
	defer func() {
		if err != nil {
			records.Destroy()
		}
	}()
	if ack.result != 0 {
		return nil, &BindRejection{Result: ack.result, Reason: ack.reason}
	}
	auth, err := authPacket(third)
	if err != nil {
		return nil, err
	}
	header, err = decodeHeader(auth)
	if err != nil {
		return nil, err
	}
	if err = tr.WriteBuffer(ctx, header, auth); err != nil {
		return nil, err
	}
	stream, err := newProtectedStream(raw, records.Send, records.Receive, int(ack.receive), 0, 1)
	if err != nil {
		return nil, err
	}
	stream.transport.settings.MaxXmitFrag = int(ack.transmit)
	stream.transport.settings.Timeout = timeout
	stream.callID = 2
	stream.sendSequence, stream.receiveSequence = records.SendSequence, records.ReceiveSequence
	return &Client{stream: stream, stage: stage, syntax: syntax, realm: realm, service: principal, expiresAt: records.ExpiresAt, encryptionType: records.EncryptionType}, nil
}

func controlPacket(ptype PacketType, call uint32, pdu, token []byte) ([]byte, error) {
	pad := (-len(pdu)) & 3
	tokenLength := len(token)
	if tokenLength < 1 || tokenLength > 65535 || len(pdu) > 65535 {
		return nil, ErrPacketTooLong
	}
	length := HeaderSize + len(pdu) + pad + SecurityTrailerSize + tokenLength
	if length > 65535 {
		return nil, ErrPacketTooLong
	}
	frame := make([]byte, length)
	frame[0], frame[2], frame[3], frame[4] = 5, byte(ptype), 3, 16
	if ptype == PacketTypeBind || ptype == PacketTypeAuth3 {
		frame[3] |= byte(PacketFlagSupportHeaderSign)
	}
	binary.LittleEndian.PutUint16(frame[8:], uint16(length))
	binary.LittleEndian.PutUint16(frame[10:], uint16(tokenLength))
	binary.LittleEndian.PutUint32(frame[12:], call)
	copy(frame[16:], pdu)
	end := 16 + len(pdu) + pad
	frame[end], frame[end+1], frame[end+2] = 16, 6, byte(pad)
	binary.LittleEndian.PutUint32(frame[end+4:], 1)
	copy(frame[end+8:], token)
	return frame, nil
}

func bindPacket(syntax [20]byte, token []byte) ([]byte, error) {
	pdu := make([]byte, 56)
	binary.LittleEndian.PutUint16(pdu, 4096)
	binary.LittleEndian.PutUint16(pdu[2:], 4096)
	pdu[8], pdu[14] = 1, 1
	copy(pdu[16:], syntax[:])
	transfer := transferSyntax()
	copy(pdu[36:], transfer[:])
	return controlPacket(PacketTypeBind, 1, pdu, token)
}

func authPacket(token []byte) ([]byte, error) {
	return controlPacket(PacketTypeAuth3, 2, make([]byte, 4), token)
}

type bindAck struct {
	transmit, receive, result, reason uint16
	token                             []byte
}

func readBindAck(header Header, frame []byte) (ack bindAck, err error) {
	if header.PacketType != PacketTypeBindAck || header.CallID != 1 || header.PacketFlags != PacketFlagFirstFrag|PacketFlagLastFrag|PacketFlagSupportHeaderSign ||
		header.AuthLength == 0 {
		return ack, ErrNoSecurityContext
	}
	end := len(frame) - int(header.AuthLength) - 8
	if end < 26 {
		return ack, ErrMalformedFragment
	}
	trailer := frame[end : end+8]
	if trailer[0] != 16 || trailer[1] != 6 || trailer[3] != 0 || trailer[2] > 15 || int(trailer[2]) > end-26 || binary.LittleEndian.Uint32(trailer[4:]) != 1 {
		return ack, ErrNoSecurityContext
	}
	bodyEnd := end - int(trailer[2])
	serverTransmit, serverReceive := binary.LittleEndian.Uint16(frame[16:]), binary.LittleEndian.Uint16(frame[18:])
	if serverTransmit < 128 || serverReceive < 128 {
		return ack, ErrMalformedFragment
	}
	secondaryLength := int(binary.LittleEndian.Uint16(frame[24:]))
	if secondaryLength > 1024 || secondaryLength > bodyEnd-26 {
		return ack, ErrMalformedFragment
	}
	resultStart := (26 + secondaryLength + 3) &^ 3
	if resultStart > bodyEnd-4 || frame[resultStart] != 1 || resultStart+28 != bodyEnd {
		return ack, ErrMalformedFragment
	}
	ack.result, ack.reason = binary.LittleEndian.Uint16(frame[resultStart+4:]), binary.LittleEndian.Uint16(frame[resultStart+6:])
	if ack.result == 0 && ack.reason != 0 {
		return ack, ErrMalformedFragment
	}
	transfer := transferSyntax()
	if ack.result == 0 && !bytes.Equal(frame[resultStart+8:resultStart+28], transfer[:]) {
		return ack, ErrMalformedFragment
	}
	ack.transmit, ack.receive = min(serverReceive, 4096), min(serverTransmit, 4096)
	ack.token = append([]byte(nil), frame[end+8:]...)
	return ack, nil
}

// Call permits only the selected stage's diagnostic or context-cleanup methods.
// There is no generic operation/provider dispatch and no automatic retry.
func (c *Client) Call(ctx context.Context, opnum uint16, request []byte) ([]byte, error) {
	if c.stage == EndpointMapping && opnum != 3 && opnum != 4 || c.stage == DirectoryReplication && opnum != 0 && opnum != 1 && opnum != 19 {
		return nil, ErrUnsupportedOperation
	}
	if cause := context.Cause(ctx); cause != nil {
		return nil, fmt.Errorf("invoke RPC diagnostic operation: %w", cause)
	}
	if !time.Now().Before(c.expiresAt) {
		return nil, c.stream.retire(rpcdce.ErrExpired)
	}
	ctx, cancel := context.WithDeadlineCause(ctx, c.expiresAt, rpcdce.ErrExpired)
	defer cancel()
	verified, err := addVerification(request, c.syntax)
	if err != nil {
		return nil, err
	}
	defer clear(verified)
	response, callErr := c.stream.exchangeWithTail(ctx, opnum, verified, 60)
	var fault *FaultError
	if callErr == nil || errors.As(callErr, &fault) {
		c.protectedReply.Store(true)
	}
	return response, callErr
}

func (c *Client) Close() error { _ = c.stream.retire(ErrClosed); return c.stream.transport.closeErr }
