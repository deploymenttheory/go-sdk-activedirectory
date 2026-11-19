package messages

import (
	"bytes"
	"encoding/asn1"
	"encoding/json"
	"fmt"
	"strings"
	"testing"
	"time"

	"github.com/deploymenttheory/go-sdk-activedirectory/3rd_party/gokrb5/v8/iana/flags"
	"github.com/deploymenttheory/go-sdk-activedirectory/3rd_party/gokrb5/v8/types"
)

func forwardingCredentialFixture(profile int32) (KRBCred, types.EncryptionKey) {
	size := 16
	if profile == 18 || profile == 20 {
		size = 32
	}
	key := types.EncryptionKey{KeyType: profile, KeyValue: bytes.Repeat([]byte{0x31}, size)}
	forwardedKey := types.EncryptionKey{KeyType: profile, KeyValue: bytes.Repeat([]byte{0x42}, size)}
	ticketFlags := types.NewKrbFlags()
	types.SetFlag(&ticketFlags, flags.Forwardable)
	types.SetFlag(&ticketFlags, flags.Forwarded)
	now := time.Now().UTC().Truncate(time.Second)
	service := types.NewPrincipalName(2, "krbtgt/EXAMPLE.TEST")
	return KRBCred{
		PVNO: 5, MsgType: 22,
		Tickets: []Ticket{{TktVNO: 5, Realm: "EXAMPLE.TEST", SName: service, EncPart: types.EncryptedData{EType: profile, Cipher: []byte("opaque-ticket")}}},
		DecryptedEncPart: EncKrbCredPart{
			Timestamp: now, Usec: 123, Nouce: 451,
			TicketInfo: []KrbCredInfo{{
				Key: forwardedKey, PRealm: "EXAMPLE.TEST", PName: types.NewPrincipalName(1, "fixture-user"), Flags: ticketFlags,
				AuthTime: now.Add(-time.Minute), StartTime: now, EndTime: now.Add(time.Hour), SRealm: "EXAMPLE.TEST", SName: service,
			}},
		},
	}, key
}

func TestForwardingCredentialEncryptsFourAESProfilesWithServiceKey(t *testing.T) {
	for _, profile := range []int32{17, 18, 19, 20} {
		t.Run(fmt.Sprint(profile), func(t *testing.T) {
			credential, serviceKey := forwardingCredentialFixture(profile)
			if err := credential.EncryptEncPart(serviceKey); err != nil {
				t.Fatal(err)
			}
			raw, err := credential.Marshal()
			if err != nil {
				t.Fatal(err)
			}
			if bytes.Contains(raw, serviceKey.KeyValue) {
				t.Fatal("credential exposed an unencrypted key")
			}
			var decoded KRBCred
			if err := decoded.Unmarshal(raw); err != nil {
				t.Fatal(err)
			}
			wrongKey := types.EncryptionKey{KeyType: profile, KeyValue: bytes.Repeat([]byte{0x32}, len(serviceKey.KeyValue))}
			if err := decoded.DecryptEncPart(wrongKey); err == nil {
				t.Fatal("initiator subkey or wrong service key decrypted credential")
			}
			if err := decoded.DecryptEncPart(serviceKey); err != nil {
				t.Fatal(err)
			}
			part := decoded.DecryptedEncPart
			if len(part.TicketInfo) != 1 || part.Nouce != 451 || part.Usec != 123 || !part.Timestamp.Equal(credential.DecryptedEncPart.Timestamp) {
				t.Fatal("credential metadata did not round trip")
			}
			info := part.TicketInfo[0]
			if !bytes.Equal(info.Key.KeyValue, credential.DecryptedEncPart.TicketInfo[0].Key.KeyValue) ||
				!types.IsFlagSet(&info.Flags, flags.Forwarded) || info.SRealm != "EXAMPLE.TEST" {
				t.Fatal("forwarded credential identity/key/flags changed")
			}
			decoded.EncPart.Cipher[len(decoded.EncPart.Cipher)-1] ^= 1
			if err := decoded.DecryptEncPart(serviceKey); err == nil {
				t.Fatal("tampered credential was accepted")
			}
		})
	}
}

func TestForwardingCredentialRejectsTrailingAndWrongProtocolEnvelope(t *testing.T) {
	credential, key := forwardingCredentialFixture(18)
	if err := credential.EncryptEncPart(key); err != nil {
		t.Fatal(err)
	}
	for _, version := range []int{4, 6} {
		credential.PVNO = version
		if _, err := credential.Marshal(); err == nil {
			t.Fatal("invalid credential version marshalled")
		}
	}
	credential.PVNO = 5
	raw, err := credential.Marshal()
	if err != nil {
		t.Fatal(err)
	}
	var decoded KRBCred
	if err := decoded.Unmarshal(append(raw, 0)); err == nil {
		t.Fatal("trailing credential data accepted")
	}
}

func TestForwardingCredentialFormattingDoesNotExposeKeys(t *testing.T) {
	credential, _ := forwardingCredentialFixture(18)
	for _, value := range []any{credential, credential.DecryptedEncPart, credential.DecryptedEncPart.TicketInfo[0], struct{ Value any }{credential}} {
		for _, format := range []string{"%v", "%+v", "%#v", "%d", "%x", "%s", "%q"} {
			if output := fmt.Sprintf(format, value); strings.Contains(output, "fixture-user") || strings.Contains(output, "66 66 66") ||
				strings.Contains(output, "42424242") || strings.Contains(output, "BBBBBBBB") || strings.Contains(output, "0x42, 0x42") {
				t.Fatal("credential formatting exposed identity or key material")
			}
		}
		encoded, err := json.Marshal(value)
		if err != nil || bytes.Contains(encoded, []byte("QkJCQkJC")) || bytes.Contains(encoded, []byte("fixture-user")) {
			t.Fatal("credential serialization exposed identity or key material")
		}
	}
}

// Use the standard-library DER envelope reader, not this library's permissive
// RawValue field decoder: a self-roundtrip cannot establish RFC wire tags.
func TestForwardingCredentialDERFieldsMatchRFC4120(t *testing.T) {
	credential, key := forwardingCredentialFixture(18)
	if err := credential.EncryptEncPart(key); err != nil {
		t.Fatal(err)
	}
	encoded, err := credential.Marshal()
	if err != nil {
		t.Fatal(err)
	}
	var application, sequence asn1.RawValue
	if rest, err := asn1.Unmarshal(encoded, &application); err != nil || len(rest) != 0 || application.Class != asn1.ClassApplication || application.Tag != 22 {
		t.Fatal("KRB-CRED application envelope is not RFC4120 application22")
	}
	if rest, err := asn1.Unmarshal(application.Bytes, &sequence); err != nil || len(rest) != 0 || sequence.Class != asn1.ClassUniversal || sequence.Tag != asn1.TagSequence {
		t.Fatal("KRB-CRED application envelope omitted its sequence")
	}
	remaining := sequence.Bytes
	var tickets asn1.RawValue
	for tag := range 4 {
		var field asn1.RawValue
		var err error
		remaining, err = asn1.Unmarshal(remaining, &field)
		if err != nil || field.Class != asn1.ClassContextSpecific || field.Tag != tag || !field.IsCompound {
			t.Fatalf("KRB-CRED field%d has class=%d tag=%d; expected explicit context%d", tag, field.Class, field.Tag, tag)
		}
		if tag == 2 {
			tickets = field
		}
	}
	if len(remaining) != 0 {
		t.Fatal("KRB-CRED contains extra unaccounted fields")
	}
	for _, octet := range []*byte{&tickets.FullBytes[0], &tickets.Bytes[0]} {
		original := *octet
		*octet ^= 1 // [2] becomes [3], or SEQUENCE becomes SET, at unchanged length.
		var malformed KRBCred
		if err := malformed.Unmarshal(encoded); err == nil {
			t.Fatal("credential decoder accepted wrong explicit tag or inner sequence schema")
		}
		*octet = original
	}
}
