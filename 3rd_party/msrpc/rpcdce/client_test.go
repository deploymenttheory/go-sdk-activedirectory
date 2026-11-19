package rpcdce

import (
	"bytes"
	"context"
	"encoding/binary"
	"errors"
	"testing"
	"time"

	krbclient "github.com/deploymenttheory/go-sdk-activedirectory/3rd_party/gokrb5/v8/client"
	krbcrypto "github.com/deploymenttheory/go-sdk-activedirectory/3rd_party/gokrb5/v8/crypto"
	"github.com/deploymenttheory/go-sdk-activedirectory/3rd_party/gokrb5/v8/iana/keyusage"
	"github.com/deploymenttheory/go-sdk-activedirectory/3rd_party/gokrb5/v8/messages"
	"github.com/deploymenttheory/go-sdk-activedirectory/3rd_party/gokrb5/v8/types"
	record "github.com/deploymenttheory/go-sdk-activedirectory/3rd_party/msrpc/ssp/krb5/crypto"
)

func qualificationClient(t *testing.T) (*Client, types.EncryptionKey) {
	t.Helper()
	key := types.EncryptionKey{KeyType: 18, KeyValue: bytes.Repeat([]byte{0x71}, 32)}
	service := types.NewPrincipalName(2, "ldap/dc.example.test")
	selected := krbclient.ServiceTicket{
		Ticket: messages.Ticket{
			TktVNO: 5, Realm: "EXAMPLE.TEST", SName: service,
			EncPart: types.EncryptedData{EType: 18, Cipher: []byte("synthetic opaque ticket, not a KDC response")},
		}, Key: key,
		StartTime: time.Now().Add(-time.Minute), EndTime: time.Now().Add(time.Hour),
	}
	c, err := NewClient(context.Background(), "EXAMPLE.TEST", service, "EXAMPLE.TEST", types.NewPrincipalName(1, "client"), selected)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(c.Destroy)
	return c, key
}

func TestQualificationDCEAuthenticatorAndFinalLeg(t *testing.T) {
	ctx := context.Background()
	c, key := qualificationClient(t)
	wire, err := c.Begin(ctx)
	if err != nil {
		t.Fatal(err)
	}
	if wire[0] != 0x6e {
		t.Fatal("DCE AP-REQ was GSS-wrapped or incorrectly tagged")
	}
	var req messages.APReq
	if err := req.Unmarshal(wire); err != nil {
		t.Fatal(err)
	}
	if err := req.DecryptAuthenticator(key); err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(req.Authenticator.Cksum.Checksum[4:20], make([]byte, 16)) || binary.LittleEndian.Uint32(req.Authenticator.Cksum.Checksum[20:]) != 0x103e {
		t.Fatal("DCE/mutual/privacy flags or unrequested channel binding changed")
	}
	if req.Authenticator.SeqNumber != int64(c.sendSequence) || len(req.Authenticator.SubKey.KeyValue) != 32 {
		t.Fatal("authenticator state not retained")
	}
	serverKey := types.EncryptionKey{KeyType: 18, KeyValue: bytes.Repeat([]byte{0x42}, 32)}
	serverReply, err := marshalAPReply(key, messages.EncAPRepPart{CTime: c.authTime, Cusec: c.authUsec, Subkey: serverKey, SequenceNumber: 42})
	if err != nil {
		t.Fatal(err)
	}
	third, records, err := c.Accept(ctx, serverReply)
	if err != nil {
		t.Fatal(err)
	}
	defer records.Destroy()
	if records.EncryptionType != 18 || !records.AcceptorSubkey || records.ReceiveSequence != 42 || records.SendSequence != uint64(req.Authenticator.SeqNumber) {
		t.Fatal("authenticated profile/sequence facts lost")
	}
	var final messages.APRep
	if err := final.Unmarshal(third); err != nil {
		t.Fatal(err)
	}
	plain, err := krbcrypto.DecryptEncPart(final.EncPart, key, keyusage.AP_REP_ENCPART)
	if err != nil {
		t.Fatal(err)
	}
	defer clear(plain)
	var part messages.EncAPRepPart
	if err := part.Unmarshal(plain); err != nil {
		t.Fatal(err)
	}
	if part.SequenceNumber != 42 || len(part.Subkey.KeyValue) != 0 {
		t.Fatal("DCE third leg did not echo acceptor sequence without replacing key")
	}
	if len(c.key.KeyValue) != 0 || len(c.initiatorKey.KeyValue) != 0 {
		t.Fatal("completed actor retained handshake keys")
	}
	if _, err := records.Send.WrapEx(ctx, records.SendSequence, nil, nil); err != nil {
		t.Fatalf("transferred record key was prematurely retired: %v", err)
	}
}

func TestQualificationDCEReplyRefusalRetiresHandshake(t *testing.T) {
	for _, mode := range []string{"time", "usec", "sequence", "profile", "key-size", "typed-empty-key", "trailing-envelope", "bad-mac", "canceled"} {
		t.Run(mode, func(t *testing.T) {
			c, key := qualificationClient(t)
			if _, err := c.Begin(context.Background()); err != nil {
				t.Fatal(err)
			}
			part := messages.EncAPRepPart{CTime: c.authTime, Cusec: c.authUsec, SequenceNumber: 7, Subkey: types.EncryptionKey{KeyType: 18, KeyValue: make([]byte, 32)}}
			switch mode {
			case "time":
				part.CTime = part.CTime.Add(time.Second)
			case "usec":
				part.Cusec = (part.Cusec + 1) % 1000000
			case "sequence":
				part.SequenceNumber = -1
			case "profile":
				part.Subkey.KeyType = 20
			case "key-size":
				part.Subkey.KeyValue = make([]byte, 31)
			case "typed-empty-key":
				part.Subkey.KeyValue = nil
			}
			wire, err := marshalAPReply(key, part)
			if err != nil {
				t.Fatal(err)
			}
			if mode == "trailing-envelope" {
				wire = append(wire, 0)
			}
			if mode == "bad-mac" {
				wire[len(wire)-1] ^= 1
			}
			ctx := context.Background()
			cause := errors.New("owned AP cancellation")
			if mode == "canceled" {
				var cancel context.CancelCauseFunc
				ctx, cancel = context.WithCancelCause(ctx)
				cancel(cause)
			}
			third, records, err := c.Accept(ctx, wire)
			if err == nil || records != nil || third != nil {
				t.Fatal("invalid mutual reply produced usable records")
			}
			if mode == "canceled" && !errors.Is(err, cause) {
				t.Fatal("caller cause lost")
			}
			if len(c.key.KeyValue) != 0 || len(c.initiatorKey.KeyValue) != 0 || c.phase != 3 {
				t.Fatal("failed handshake retained usable key material")
			}
		})
	}
}

func TestQualificationDCEUnsupportedProfileIsNotDowngraded(t *testing.T) {
	for _, profile := range []int32{19, 20} {
		service := types.NewPrincipalName(2, "ldap/dc.example.test")
		_, err := NewClient(context.Background(), "EXAMPLE.TEST", service, "EXAMPLE.TEST", types.NewPrincipalName(1, "client"),
			krbclient.ServiceTicket{Ticket: messages.Ticket{TktVNO: 5, Realm: "EXAMPLE.TEST", SName: service}, Key: types.EncryptionKey{KeyType: profile}})
		if !errors.Is(err, record.ErrUnsupportedProfile) {
			t.Fatalf("profile%d was not explicitly refused: %v", profile, err)
		}
	}
}
