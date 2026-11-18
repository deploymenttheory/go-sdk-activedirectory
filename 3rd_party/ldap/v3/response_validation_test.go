package ldap

import (
	"bytes"
	"errors"
	"testing"

	ber "github.com/go-asn1-ber/asn1-ber"
)

func validationTestEnvelope(tag ber.Tag, status int64, fields ...*ber.Packet) *ber.Packet {
	operation := ber.Encode(ber.ClassApplication, ber.TypeConstructed, tag, nil, "")
	operation.AppendChild(ber.NewInteger(ber.ClassUniversal, ber.TypePrimitive, ber.TagEnumerated, status, ""))
	operation.AppendChild(ber.NewString(ber.ClassUniversal, ber.TypePrimitive, ber.TagOctetString, "", ""))
	operation.AppendChild(ber.NewString(ber.ClassUniversal, ber.TypePrimitive, ber.TagOctetString, "", ""))
	for _, field := range fields {
		operation.AppendChild(field)
	}
	packet := ber.NewSequence("")
	packet.AppendChild(ber.NewInteger(ber.ClassUniversal, ber.TypePrimitive, ber.TagInteger, 1, ""))
	packet.AppendChild(operation)
	return packet
}

func TestLDAPResponseValidationKeepsOptionalBindExtendedReferralAndBinaryControls(t *testing.T) {
	referral := ber.Encode(ber.ClassContext, ber.TypeConstructed, 3, nil, "")
	referral.AppendChild(ber.NewString(ber.ClassUniversal, ber.TypePrimitive, ber.TagOctetString, "ldap://owned.ad.sdk.test/DC=ad,DC=sdk,DC=test", ""))
	cases := map[string]*ber.Packet{
		"bind-sasl-in-progress": validationTestEnvelope(ApplicationBindResponse, 14,
			ber.NewString(ber.ClassContext, ber.TypePrimitive, 7, string([]byte{0, 0xff, 0x80}), "")),
		"bind-referral-and-sasl": validationTestEnvelope(ApplicationBindResponse, 10, referral,
			ber.NewString(ber.ClassContext, ber.TypePrimitive, 7, "", "")),
		"extended-value-only": validationTestEnvelope(ApplicationExtendedResponse, 0,
			ber.NewString(ber.ClassContext, ber.TypePrimitive, 11, string([]byte{0, 0xff}), "")),
		"extended-name-and-value": validationTestEnvelope(ApplicationExtendedResponse, 0,
			ber.NewString(ber.ClassContext, ber.TypePrimitive, 10, "1.3.6.1.4.1.4203.1.11.3", ""),
			ber.NewString(ber.ClassContext, ber.TypePrimitive, 11, "", "")),
		"modify-referral": validationTestEnvelope(ApplicationModifyResponse, 10, referral),
	}
	for name, packet := range cases {
		t.Run(name, func(t *testing.T) {
			controls := ber.Encode(ber.ClassContext, ber.TypeConstructed, 0, nil, "")
			controls.AppendChild(NewControlString("1.2.3.4", true, string([]byte{0, 0xff, 0x80})).Encode())
			packet.AppendChild(controls)
			decoded, err := readLDAPResponse(bytes.NewReader(packet.Bytes()))
			if err != nil {
				t.Fatal(err)
			}
			before := append([]byte(nil), decoded.Bytes()...)
			if _, err := validateLDAPResponseEnvelope(decoded); err != nil {
				t.Fatalf("valid optional LDAP fields rejected: %v", err)
			}
			if !bytes.Equal(before, decoded.Bytes()) {
				t.Fatal("response validation mutated opaque control or bind bytes")
			}
		})
	}
}

func TestLDAPResponseValidationRejectsUnexpectedOptionalFields(t *testing.T) {
	for _, packet := range []*ber.Packet{
		validationTestEnvelope(ApplicationModifyResponse, 0, ber.NewString(ber.ClassContext, ber.TypePrimitive, 7, "", "")),
		validationTestEnvelope(ApplicationBindResponse, 0, ber.NewString(ber.ClassContext, ber.TypeConstructed, 7, "", "")),
		validationTestEnvelope(ApplicationExtendedResponse, 0,
			ber.NewString(ber.ClassContext, ber.TypePrimitive, 11, "", ""), ber.NewString(ber.ClassContext, ber.TypePrimitive, 10, "1.2.3", "")),
		validationTestEnvelope(ApplicationExtendedResponse, 0, ber.NewString(ber.ClassContext, ber.TypePrimitive, 10, "invalid OID", "")),
	} {
		decoded, err := readLDAPResponse(bytes.NewReader(packet.Bytes()))
		if err != nil {
			t.Fatal(err)
		}
		if _, err := validateLDAPResponseEnvelope(decoded); !errors.Is(err, ErrMalformedPacket) {
			t.Fatalf("malformed optional fields became a valid result: %v", err)
		}
	}
}

func FuzzLDAPResponseValidation(f *testing.F) {
	f.Add(validationTestEnvelope(ApplicationModifyResponse, 0).Bytes())
	f.Add(validationTestEnvelope(ApplicationBindResponse, 14,
		ber.NewString(ber.ClassContext, ber.TypePrimitive, 7, string([]byte{0, 0xff}), "")).Bytes())
	f.Add(validationTestEnvelope(ApplicationExtendedResponse, 0,
		ber.NewString(ber.ClassContext, ber.TypePrimitive, 11, string([]byte{0, 0xff}), "")).Bytes())
	f.Add([]byte{0x30, 0x84, 1, 0, 0, 1})
	f.Fuzz(func(t *testing.T, wire []byte) {
		if len(wire) > 1<<20 {
			t.Skip("fuzz inputs are bounded separately from the 16 MiB production frame limit")
		}
		packet, err := readLDAPResponse(bytes.NewReader(wire))
		if err != nil {
			return
		}
		if _, err := validateLDAPResponseEnvelope(packet); err != nil {
			return
		}
		if err := addLDAPDescriptions(packet); err != nil {
			t.Fatalf("validated response cannot be described: %v", err)
		}
	})
}
