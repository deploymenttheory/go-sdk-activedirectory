package ldap

import (
	"fmt"
	"math"
	"testing"

	ber "github.com/go-asn1-ber/asn1-ber"
)

func vendorResultEnvelope() *ber.Packet {
	packet := ber.Encode(ber.ClassUniversal, ber.TypeConstructed, ber.TagSequence, nil, "LDAP message")
	packet.AppendChild(ber.NewInteger(ber.ClassUniversal, ber.TypePrimitive, ber.TagInteger, int64(1), "Message ID"))
	result := ber.Encode(ber.ClassApplication, ber.TypeConstructed, ApplicationModifyResponse, nil, "Modify response")
	result.AppendChild(ber.NewInteger(ber.ClassUniversal, ber.TypePrimitive, ber.TagEnumerated, int64(0), "Success"))
	result.AppendChild(ber.NewString(ber.ClassUniversal, ber.TypePrimitive, ber.TagOctetString, "", "Matched DN"))
	result.AppendChild(ber.NewString(ber.ClassUniversal, ber.TypePrimitive, ber.TagOctetString, "", "Diagnostic"))
	packet.AppendChild(result)
	return packet
}

func vendorRefreshBER(packet *ber.Packet) {
	if len(packet.Children) == 0 {
		return
	}
	packet.Data.Reset()
	for _, child := range packet.Children {
		vendorRefreshBER(child)
		_, _ = packet.Data.Write(child.Bytes())
	}
}

func TestVendoredLDAPSuccessRequiresValidResultFields(t *testing.T) {
	for name, mutate := range map[string]func(*ber.Packet){
		"valid": func(*ber.Packet) {},
		"integer matched DN": func(result *ber.Packet) {
			result.Children[1] = ber.NewInteger(ber.ClassUniversal, ber.TypePrimitive, ber.TagInteger, int64(0), "Invalid DN")
		},
		"integer diagnostic": func(result *ber.Packet) {
			result.Children[2] = ber.NewInteger(ber.ClassUniversal, ber.TypePrimitive, ber.TagInteger, int64(0), "Invalid diagnostic")
		},
		"context matched DN":  func(result *ber.Packet) { result.Children[1].ClassType = ber.ClassContext },
		"high diagnostic tag": func(result *ber.Packet) { result.Children[2].Tag += 256 },
		"high result tag":     func(result *ber.Packet) { result.Children[0].Tag += 256 },
	} {
		t.Run(name, func(t *testing.T) {
			packet := vendorResultEnvelope()
			mutate(packet.Children[1])
			vendorRefreshBER(packet)
			decoded, err := ber.DecodePacketErr(packet.Bytes())
			if err != nil {
				t.Fatal(err)
			}
			err = GetLDAPError(decoded)
			if name == "valid" {
				if err != nil {
					t.Fatal(err)
				}
			} else if err == nil {
				t.Fatal("a success code bypassed malformed result fields")
			}
		})
	}
}

func TestVendoredPagingSizeDoesNotWrap(t *testing.T) {
	for _, size := range []int64{-1, 0, math.MaxUint32, int64(math.MaxUint32) + 1} {
		t.Run(fmt.Sprint(size), func(t *testing.T) {
			control := ber.Encode(ber.ClassUniversal, ber.TypeConstructed, ber.TagSequence, nil, "Paging control")
			control.AppendChild(ber.NewString(ber.ClassUniversal, ber.TypePrimitive, ber.TagOctetString, ControlTypePaging, "OID"))
			sequence := ber.Encode(ber.ClassUniversal, ber.TypeConstructed, ber.TagSequence, nil, "Paging value")
			sequence.AppendChild(ber.NewInteger(ber.ClassUniversal, ber.TypePrimitive, ber.TagInteger, size, "Estimated size"))
			sequence.AppendChild(ber.NewString(ber.ClassUniversal, ber.TypePrimitive, ber.TagOctetString, "", "Cookie"))
			control.AppendChild(ber.NewString(ber.ClassUniversal, ber.TypePrimitive, ber.TagOctetString, string(sequence.Bytes()), "Encoded value"))
			decoded, err := ber.DecodePacketErr(control.Bytes())
			if err != nil {
				t.Fatal(err)
			}
			result, err := DecodeControl(decoded)
			if size < 0 || size > math.MaxUint32 {
				if err == nil {
					t.Fatalf("paging size %d was silently narrowed: %+v", size, result)
				}
			} else if err != nil {
				t.Fatal(err)
			}
		})
	}
}

func TestVendoredSearchRejectsInvalidLimitsBeforeEncoding(t *testing.T) {
	for name, mutate := range map[string]func(*SearchRequest){
		"negative scope": func(request *SearchRequest) { request.Scope = -1 },
		"unknown scope":  func(request *SearchRequest) { request.Scope = ScopeChildren + 1 },
		"negative alias policy": func(request *SearchRequest) {
			request.DerefAliases = -1
		},
		"negative size": func(request *SearchRequest) { request.SizeLimit = -1 },
		"negative time": func(request *SearchRequest) { request.TimeLimit = -1 },
	} {
		t.Run(name, func(t *testing.T) {
			request := NewSearchRequest("", ScopeBaseObject, NeverDerefAliases, 0, 0, false, "(objectClass=*)", nil, nil)
			mutate(request)
			envelope := ber.Encode(ber.ClassUniversal, ber.TypeConstructed, ber.TagSequence, nil, "LDAP message")
			if err := request.appendTo(envelope); err == nil || len(envelope.Children) != 0 {
				t.Fatalf("invalid request reached encoding: children=%d, error=%v", len(envelope.Children), err)
			}
		})
	}
}
