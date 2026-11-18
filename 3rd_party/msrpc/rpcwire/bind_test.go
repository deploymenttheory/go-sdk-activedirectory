package rpcwire

import (
	"bytes"
	"context"
	"encoding/binary"
	"errors"
	"net"
	"testing"
	"time"

	"github.com/jcmturner/gofork/encoding/asn1"

	"github.com/deploymenttheory/go-sdk-activedirectory/3rd_party/gokrb5/v8/asn1tools"
	krbclient "github.com/deploymenttheory/go-sdk-activedirectory/3rd_party/gokrb5/v8/client"
	krbcrypto "github.com/deploymenttheory/go-sdk-activedirectory/3rd_party/gokrb5/v8/crypto"
	"github.com/deploymenttheory/go-sdk-activedirectory/3rd_party/gokrb5/v8/iana/keyusage"
	"github.com/deploymenttheory/go-sdk-activedirectory/3rd_party/gokrb5/v8/messages"
	"github.com/deploymenttheory/go-sdk-activedirectory/3rd_party/gokrb5/v8/types"
	"github.com/deploymenttheory/go-sdk-activedirectory/3rd_party/msrpc/rpcdce"
	record "github.com/deploymenttheory/go-sdk-activedirectory/3rd_party/msrpc/ssp/krb5/crypto"
)

func qualificationBindActor(t *testing.T) (*rpcdce.Client, types.EncryptionKey) {
	return qualificationBindActorFor(t, "ldap/dc.example.test")
}

func qualificationBindActorFor(t *testing.T, service string) (*rpcdce.Client, types.EncryptionKey) {
	t.Helper()
	key := types.EncryptionKey{KeyType: 18, KeyValue: bytes.Repeat([]byte{0x71}, 32)}
	principal := types.NewPrincipalName(2, service)
	actor, err := rpcdce.NewClient(context.Background(), "EXAMPLE.TEST", principal, "EXAMPLE.TEST", types.NewPrincipalName(1, "client"),
		krbclient.ServiceTicket{
			Ticket: messages.Ticket{TktVNO: 5, Realm: "EXAMPLE.TEST", SName: principal, EncPart: types.EncryptedData{EType: 18, Cipher: []byte("public opaque synthetic ticket")}},
			Key:    key, StartTime: time.Now().Add(-time.Minute), EndTime: time.Now().Add(time.Hour),
		})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(actor.Destroy)
	return actor, key
}

func qualificationAPReply(key types.EncryptionKey, part messages.EncAPRepPart) ([]byte, error) {
	plain, err := asn1.Marshal(part)
	if err != nil {
		return nil, err
	}
	plain = asn1tools.AddASNAppTag(plain, 27)
	defer clear(plain)
	ed, err := krbcrypto.GetEncryptedData(plain, key, keyusage.AP_REP_ENCPART, 0)
	if err != nil {
		return nil, err
	}
	wire, err := asn1.Marshal(messages.APRep{PVNO: 5, MsgType: 15, EncPart: ed})
	if err != nil {
		return nil, err
	}
	return asn1tools.AddASNAppTag(wire, 15), nil
}

func qualificationBoundCipher(key types.EncryptionKey, initiator bool) (rpcRecordCipher, error) {
	et, err := krbcrypto.GetEtype(key.KeyType)
	if err != nil {
		return nil, err
	}
	cipher, err := record.NewCipher(context.Background(), record.CipherSetting{Type: et, Key: key, IsLocal: initiator, IsSubKey: true, DCEStyle: true})
	if err != nil {
		return nil, err
	}
	return cipher.(rpcRecordCipher), nil
}

func qualificationBindPeer(ctx context.Context, raw net.Conn, key types.EncryptionKey, mode string) error {
	defer raw.Close()
	settings := NewTransport()
	settings.MaxRecvFrag, settings.MaxXmitFrag = 65535, 65535
	tr := &transport{settings: &settings, cc: NewBufferedConn(raw, 65535)}
	frame := make([]byte, 65535)
	header, err := tr.ReadBuffer(ctx, frame)
	if err != nil {
		return err
	}
	if header.PacketType != PacketTypeBind || header.CallID != 1 || frame[30] != 1 {
		return ErrMalformedFragment
	}
	var req messages.APReq
	if err := req.Unmarshal(frame[int(header.FragLength)-int(header.AuthLength) : header.FragLength]); err != nil {
		return err
	}
	if err := req.DecryptAuthenticator(key); err != nil {
		return err
	}
	serverKey := types.EncryptionKey{KeyType: 18, KeyValue: bytes.Repeat([]byte{0x42}, 32)}
	part := messages.EncAPRepPart{CTime: req.Authenticator.CTime, Cusec: req.Authenticator.Cusec, Subkey: serverKey, SequenceNumber: 42}
	if mode == "wrong-time" {
		part.CTime = part.CTime.Add(time.Second)
	}
	token, err := qualificationAPReply(key, part)
	if err != nil {
		return err
	}
	pdu := make([]byte, 40)
	binary.LittleEndian.PutUint16(pdu, 4096)
	binary.LittleEndian.PutUint16(pdu[2:], 4096)
	pdu[12] = 1
	transfer := transferSyntax()
	copy(pdu[20:], transfer[:])
	if mode == "rejected-context" {
		binary.LittleEndian.PutUint16(pdu[16:], 2)
		binary.LittleEndian.PutUint16(pdu[18:], 1)
	}
	ack, err := controlPacket(PacketTypeBindAck, 1, pdu, token)
	if err != nil {
		return err
	}
	ack[3] |= byte(PacketFlagSupportHeaderSign)
	switch mode {
	case "no-header-sign":
		ack[3] &^= byte(PacketFlagSupportHeaderSign)
	case "wrong-call":
		binary.LittleEndian.PutUint32(ack[12:], 2)
	case "wrong-transfer":
		ack[36] ^= 1
	case "wrong-security-context":
		binary.LittleEndian.PutUint32(ack[60:], 2)
	}
	if _, err := raw.Write(ack); err != nil {
		return err
	}
	header, err = tr.ReadBuffer(ctx, frame)
	if mode != "valid" {
		if err == nil {
			return errors.New("rejected handshake sent another packet")
		}
		return nil
	}
	if err != nil {
		return err
	}
	if header.PacketType != PacketTypeAuth3 || header.CallID != 2 {
		return ErrMalformedFragment
	}
	var final messages.APRep
	if err := final.Unmarshal(frame[int(header.FragLength)-int(header.AuthLength) : header.FragLength]); err != nil {
		return err
	}
	plain, err := krbcrypto.DecryptEncPart(final.EncPart, key, keyusage.AP_REP_ENCPART)
	if err != nil {
		return err
	}
	defer clear(plain)
	var finalPart messages.EncAPRepPart
	if err := finalPart.Unmarshal(plain); err != nil {
		return err
	}
	if finalPart.SequenceNumber != 42 || len(finalPart.Subkey.KeyValue) != 0 {
		return rpcdce.ErrAuthentication
	}
	// No application request is accepted until all three actual RPC/auth legs.
	header, err = tr.ReadBuffer(ctx, frame)
	if err != nil {
		return err
	}
	frame = frame[:header.FragLength]
	if header.CallID != 3 || header.PacketType != PacketTypeRequest || binary.LittleEndian.Uint16(frame[22:]) != 19 {
		return ErrMalformedFragment
	}
	end := len(frame) - int(header.AuthLength) - 8
	trailer, body := frame[end:end+8], frame[24:end]
	peerReceive, err := qualificationBoundCipher(serverKey, true)
	if err != nil {
		return err
	}
	defer peerReceive.Destroy()
	ok, err := peerReceive.UnwrapEx(ctx, uint64(req.Authenticator.SeqNumber), [][]byte{frame[:24], body, trailer}, [][]byte{body}, frame[end+8:])
	if err != nil || !ok {
		return errors.Join(ErrNoSecurityContext, err)
	}
	unpadded := body[:len(body)-int(trailer[2])]
	if len(unpadded) != 80 || string(unpadded[:20]) != "read-only diagnostic" {
		return ErrMalformedFragment
	}
	vt := unpadded[20:]
	if !bytes.Equal(vt[:8], []byte{0x8a, 0xe3, 0x13, 0x71, 2, 0xf4, 0x36, 0x71}) || binary.LittleEndian.Uint16(vt[8:]) != 0x8001 ||
		binary.LittleEndian.Uint32(vt[12:]) != 1 || binary.LittleEndian.Uint16(vt[16:]) != 0xc002 {
		return ErrMalformedFragment
	}
	actualSyntax, _ := interfaceSyntax(DirectoryReplication)
	if !bytes.Equal(vt[20:40], actualSyntax[:]) || !bytes.Equal(vt[40:], transfer[:]) {
		return ErrMalformedFragment
	}
	peerSend, err := qualificationBoundCipher(serverKey, false)
	if err != nil {
		return err
	}
	defer peerSend.Destroy()
	replyBody := []byte("confirmed reply")
	padding := (-len(replyBody)) & 15
	end = 24 + len(replyBody) + padding
	reply := make([]byte, end+8+peerSend.Size(ctx, true))
	reply[0], reply[2], reply[3], reply[4] = 5, 2, 3, 16
	binary.LittleEndian.PutUint16(reply[8:], uint16(len(reply)))
	binary.LittleEndian.PutUint16(reply[10:], uint16(peerSend.Size(ctx, true)))
	binary.LittleEndian.PutUint32(reply[12:], 3)
	copy(reply[24:], replyBody)
	trailer = reply[end : end+8]
	trailer[0], trailer[1], trailer[2] = 16, 6, byte(padding)
	binary.LittleEndian.PutUint32(trailer[4:], 1)
	body = reply[24:end]
	token, err = peerSend.WrapEx(ctx, 42, [][]byte{reply[:24], body, trailer}, [][]byte{body})
	if err != nil {
		return err
	}
	copy(reply[end+8:], token)
	_, err = raw.Write(reply)
	return err
}

func TestQualificationActualRPCBindAuth3AndProtectedCall(t *testing.T) {
	for _, mode := range []string{"valid", "no-header-sign", "wrong-call", "wrong-transfer", "wrong-security-context", "wrong-time", "rejected-context"} {
		t.Run(mode, func(t *testing.T) {
			ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
			defer cancel()
			client, server := net.Pipe()
			t.Cleanup(func() { _ = client.Close(); _ = server.Close() })
			actor, key := qualificationBindActor(t)
			done := make(chan error, 1)
			go func() { done <- qualificationBindPeer(ctx, server, key, mode) }()
			session, err := Bind(ctx, client, actor, DirectoryReplication, time.Second)
			if mode == "valid" {
				if err != nil {
					t.Fatal(err)
				}
				if _, err := session.Call(ctx, 3, nil); !errors.Is(err, ErrUnsupportedOperation) {
					t.Fatal("unsupported non-diagnostic operation allowed")
				}
				response, err := session.Call(ctx, 19, []byte("read-only diagnostic"))
				if err != nil || string(response) != "confirmed reply" {
					t.Fatalf("actual protected post-auth call failed: %v", err)
				}
				if err := session.Close(); err != nil {
					t.Fatalf("normal close failed: %v", err)
				}
			} else {
				if err == nil || session != nil {
					t.Fatal("invalid RPC/auth negotiation produced a session")
				}
				var rejection *bindRejection
				if mode == "rejected-context" && (!errors.As(err, &rejection) || rejection.Result != 2 || rejection.Reason != 1) {
					t.Fatalf("authenticated bind status lost: %v", err)
				}
			}
			select {
			case err := <-done:
				if err != nil {
					t.Fatal(err)
				}
			case <-ctx.Done():
				t.Fatal("RPC peer did not retire")
			}
		})
	}
}
