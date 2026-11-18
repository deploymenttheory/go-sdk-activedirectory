package gssapi

import (
	"bytes"
	"encoding/binary"
	"testing"
	"time"

	"github.com/jcmturner/gofork/encoding/asn1"

	"github.com/deploymenttheory/go-sdk-activedirectory/3rd_party/gokrb5/v8/asn1tools"
	"github.com/deploymenttheory/go-sdk-activedirectory/3rd_party/gokrb5/v8/crypto"
	krbgss "github.com/deploymenttheory/go-sdk-activedirectory/3rd_party/gokrb5/v8/gssapi"
	"github.com/deploymenttheory/go-sdk-activedirectory/3rd_party/gokrb5/v8/iana/keyusage"
	"github.com/deploymenttheory/go-sdk-activedirectory/3rd_party/gokrb5/v8/messages"
	"github.com/deploymenttheory/go-sdk-activedirectory/3rd_party/gokrb5/v8/types"
)

func contextTestClient(t *testing.T, acceptorKey bool) *Client {
	t.Helper()
	client := &Client{ekey: types.EncryptionKey{KeyType: 17, KeyValue: bytes.Repeat([]byte{0x41}, 16)}}
	authenticator, err := types.NewAuthenticator("AD.SDK.TEST", types.PrincipalName{})
	if err != nil {
		t.Fatal(err)
	}
	authenticator.SubKey = types.EncryptionKey{KeyType: 17, KeyValue: bytes.Repeat([]byte{0x42}, 16)}
	if err := client.retainAuthenticator(authenticator); err != nil {
		t.Fatal(err)
	}
	part := messages.EncAPRepPart{CTime: client.authenticatorTime, Cusec: client.authenticatorUsec, SequenceNumber: 712}
	if acceptorKey {
		part.Subkey = types.EncryptionKey{KeyType: 17, KeyValue: bytes.Repeat([]byte{0x43}, 16)}
	}
	_, more, err := client.InitSecContext("ldap/dc.ad.sdk.test", contextTestAPRepToken(t, client.ekey, part))
	if err != nil || more {
		t.Fatalf("valid authenticated AP-REP: more=%v err=%v", more, err)
	}
	return client
}

func contextTestAPRepToken(t *testing.T, key types.EncryptionKey, part messages.EncAPRepPart) []byte {
	t.Helper()
	plain, err := asn1.Marshal(part)
	if err != nil {
		t.Fatal(err)
	}
	plain = asn1tools.AddASNAppTag(plain, 27)
	encrypted, err := crypto.GetEncryptedData(plain, key, keyusage.AP_REP_ENCPART, 0)
	if err != nil {
		t.Fatal(err)
	}
	reply := messages.APRep{PVNO: 5, MsgType: 15, EncPart: encrypted}
	encodedReply, err := asn1.Marshal(reply)
	if err != nil {
		t.Fatal(err)
	}
	encodedReply = asn1tools.AddASNAppTag(encodedReply, 15)
	oid, err := asn1.Marshal(krbgss.OIDKRB5.OID())
	if err != nil {
		t.Fatal(err)
	}
	inner := append(append(oid, 2, 0), encodedReply...)
	result, err := asn1.Marshal(asn1.RawValue{Class: asn1.ClassApplication, Tag: 0, IsCompound: true, Bytes: inner})
	if err != nil {
		t.Fatal(err)
	}
	return result
}

func contextTestServerOffer(t *testing.T, client *Client, offer []byte, rotation uint16) []byte {
	t.Helper()
	key := client.contextKey()
	et, err := crypto.GetEtype(key.KeyType)
	if err != nil {
		t.Fatal(err)
	}
	var flags byte = 1
	if len(client.Subkey.KeyValue) > 0 {
		flags |= 4
	}
	token := &krbgss.WrapToken{Flags: flags, EC: uint16(et.GetHMACBitLength() / 8), SndSeqNum: client.receiveSequence, Payload: offer}
	if err := token.SetCheckSum(key, keyusage.GSSAPI_ACCEPTOR_SEAL); err != nil {
		t.Fatal(err)
	}
	wire, err := token.Marshal()
	if err != nil {
		t.Fatal(err)
	}
	if rotation != 0 {
		body := bytes.Clone(wire[16:])
		r := int(rotation) % len(body)
		copy(wire[16:], body[len(body)-r:])
		copy(wire[16+r:], body[:len(body)-r])
		binary.BigEndian.PutUint16(wire[6:8], rotation)
	}
	return wire
}

// Security-layer negotiation exercises actual encrypted AP-REP state before
// any per-message token can be accepted.
func TestKerberosRejectsUnofferedSecurityLayer(t *testing.T) {
	for _, rotation := range []uint16{0, 12, 65535} {
		client := contextTestClient(t, true)
		client.SASLSecurity = 4
		if _, err := client.NegotiateSaslAuth(contextTestServerOffer(t, client, []byte{7, 0, 255, 255}, rotation), ""); err != nil {
			t.Fatalf("valid offered seal layer rejected: %v", err)
		}
		refusal := contextTestClient(t, true)
		refusal.SASLSecurity = 4
		if _, err := refusal.NegotiateSaslAuth(contextTestServerOffer(t, refusal, []byte{1, 0, 0, 0}, rotation), ""); err == nil {
			t.Fatal("selected unoffered sealing")
		}
	}
}

func TestKerberosNegotiatesRFCNoLayerByte(t *testing.T) {
	client := contextTestClient(t, true)
	response, err := client.NegotiateSaslAuth(contextTestServerOffer(t, client, []byte{1, 0, 0, 0}, 12), "")
	if err != nil {
		t.Fatal(err)
	}
	var token krbgss.WrapToken
	if err := token.Unmarshal(response, false); err != nil {
		t.Fatal(err)
	}
	if len(token.Payload) != 4 || !bytes.Equal(token.Payload, []byte{1, 0, 0, 0}) {
		t.Fatalf("no-layer selection=%v", token.Payload)
	}
}

func TestKerberosRetainsAuthenticatedSequencesAndKeyOrigin(t *testing.T) {
	for _, acceptorKey := range []bool{false, true} {
		client := contextTestClient(t, acceptorKey)
		client.SASLSecurity = 4
		initialSend, initialReceive := client.sendSequence, client.receiveSequence
		key := bytes.Clone(client.contextKey().KeyValue)
		response, err := client.NegotiateSaslAuth(contextTestServerOffer(t, client, []byte{7, 0, 128, 0}, 0), "")
		if err != nil {
			t.Fatal(err)
		}
		var token krbgss.WrapToken
		if err := token.Unmarshal(response, false); err != nil {
			t.Fatal(err)
		}
		context, err := client.SASLContext()
		if err != nil {
			t.Fatal(err)
		}
		if token.SndSeqNum != initialSend || context.SendSequence != initialSend+1 || context.ReceiveSequence != initialReceive+1 ||
			context.PeerMaxTokenSize != 32768 || context.LocalMaxTokenSize != 65535 || context.AcceptorSubkey != acceptorKey || !bytes.Equal(context.KeyValue, key) {
			t.Fatal("context lost authenticated sequence, key origin or negotiated limits")
		}
		if err := client.DeleteSecContext(); err != nil {
			t.Fatal(err)
		}
		if !bytes.Equal(context.KeyValue, key) {
			t.Fatal("export did not own copied key")
		}
		clear(context.KeyValue)
		if _, err := client.SASLContext(); err == nil {
			t.Fatal("deleted context remained exportable")
		}
	}
}

func TestKerberosRejectsUnboundAPRepAndMissingContext(t *testing.T) {
	for _, change := range []string{"ctime", "cusec"} {
		client := &Client{ekey: types.EncryptionKey{KeyType: 17, KeyValue: bytes.Repeat([]byte{0x41}, 16)}}
		if err := client.retainAuthenticator(types.Authenticator{CTime: time.Unix(1800000000, 0), Cusec: 1234, SeqNumber: 971}); err != nil {
			t.Fatal(err)
		}
		part := messages.EncAPRepPart{CTime: client.authenticatorTime, Cusec: client.authenticatorUsec, SequenceNumber: 712}
		if change == "ctime" {
			part.CTime = part.CTime.Add(time.Second)
		} else {
			part.Cusec++
		}
		if _, _, err := client.InitSecContext("ldap/dc.ad.sdk.test", contextTestAPRepToken(t, client.ekey, part)); err == nil {
			t.Fatal("accepted cryptographically valid AP-REP bound to another authenticator")
		}
		if _, err := client.SASLContext(); err == nil {
			t.Fatal("failed AP-REP exported context")
		}
	}
	client := &Client{Subkey: types.EncryptionKey{KeyType: 17, KeyValue: bytes.Repeat([]byte{0x44}, 16)}}
	if _, err := client.NegotiateSaslAuth(nil, ""); err == nil {
		t.Fatal("SASL negotiated without mutual authentication")
	}
}

func TestKerberosRefusesInvalidNegotiationLimits(t *testing.T) {
	for _, test := range []struct {
		mode  int
		offer []byte
	}{
		{4, []byte{4, 0, 0, 0}}, {0, []byte{1, 0, 1, 0}}, {3, []byte{7, 0, 255, 255}}, {4, []byte{2, 0, 255, 255}}, {0, []byte{6, 0, 255, 255}},
	} {
		client := contextTestClient(t, true)
		client.SASLSecurity = test.mode
		if _, err := client.NegotiateSaslAuth(contextTestServerOffer(t, client, test.offer, 0), ""); err == nil {
			t.Fatal("invalid negotiation accepted")
		}
		if _, err := client.SASLContext(); err == nil {
			t.Fatal("refused negotiation exported context")
		}
	}
}
