package ldap

import (
	"bytes"
	"errors"
	"io"
	"net"
	"testing"
	"time"

	ber "github.com/go-asn1-ber/asn1-ber"
)

func boundedTestSequence(data []byte) []byte {
	packet := ber.Encode(ber.ClassUniversal, ber.TypeConstructed, ber.TagSequence, nil, "")
	packet.Data.Write(data)
	return packet.Bytes()
}

func TestLDAPBERBudgetRetainsValidFramesAndRejectsAllocationDepthAndNodeExcess(t *testing.T) {
	valid := boundedTestSequence([]byte{2, 1, 1, 0x65, 7, 10, 1, 0, 4, 0, 4, 0})
	if _, err := readLDAPResponse(bytes.NewReader(valid)); err != nil {
		t.Fatal("valid LDAP response rejected:", err)
	}
	nested := []byte{4, 0}
	for range maxLDAPResponseDepth {
		nested = boundedTestSequence(nested)
	}
	cases := map[string][]byte{
		"advertised-oversize": {0x30, 0x84, 1, 0, 0, 1},
		"indefinite":          {0x30, 0x80, 0, 0},
		"too-many-lengths":    {0x30, 0x85},
		"depth":               nested,
		"nodes":               boundedTestSequence(bytes.Repeat([]byte{4, 0}, maxLDAPResponseElements)),
		"empty-integer":       boundedTestSequence([]byte{2, 0}),
		"long-result":         boundedTestSequence([]byte{10, 9, 0, 0, 0, 0, 0, 0, 0, 0, 0}),
		"empty-boolean":       boundedTestSequence([]byte{1, 0}),
		"long-boolean":        boundedTestSequence([]byte{1, 2, 0, 0}),
	}
	for name, wire := range cases {
		t.Run(name, func(t *testing.T) {
			if _, err := readLDAPResponse(bytes.NewReader(wire)); !errors.Is(err, ErrMalformedPacket) {
				t.Fatalf("untrusted BER budget bypassed: %v", err)
			}
		})
	}
	for _, wire := range [][]byte{{0x30}, {0x30, 3, 1}} {
		if _, err := readLDAPResponse(bytes.NewReader(wire)); err == nil {
			t.Fatal("truncated BER became complete")
		}
	}
}

func TestLDAPControlInnerBERUsesSameBudget(t *testing.T) {
	valid := (&ControlPaging{PagingSize: 5, Cookie: []byte{0, 0xff}}).Encode()
	control, err := DecodeControl(valid)
	if err != nil || control.(*ControlPaging).PagingSize != 5 || !bytes.Equal(control.(*ControlPaging).Cookie, []byte{0, 0xff}) {
		t.Fatalf("valid paging control changed: %v %v", control, err)
	}
	nested := []byte{4, 0}
	for range maxLDAPResponseDepth {
		nested = boundedTestSequence(nested)
	}
	packet := ber.Encode(ber.ClassUniversal, ber.TypeConstructed, ber.TagSequence, nil, "")
	packet.AppendChild(ber.NewString(ber.ClassUniversal, ber.TypePrimitive, ber.TagOctetString, ControlTypePaging, ""))
	value := ber.Encode(ber.ClassUniversal, ber.TypePrimitive, ber.TagOctetString, nil, "")
	value.Data.Write(nested)
	packet.AppendChild(value)
	// Decode the actual wire shape so primitive OCTET STRING has its usual Value.
	decoded, err := ber.DecodePacketErr(packet.Bytes())
	if err != nil {
		t.Fatal(err)
	}
	if _, err := DecodeControl(decoded); !errors.Is(err, ErrMalformedPacket) {
		t.Fatalf("encoded control bypassed BER depth budget: %v", err)
	}
}

type shortLDAPRequestConn struct{ net.Conn }

func (c shortLDAPRequestConn) Write([]byte) (int, error) { return 1, nil }

func TestLDAPShortRequestWriteRetiresConnection(t *testing.T) {
	client, server := net.Pipe()
	defer server.Close()
	connection := NewConn(shortLDAPRequestConn{client}, false)
	connection.SetTimeout(time.Second)
	connection.Start()
	defer connection.Close()
	if _, err := connection.SimpleBind(NewSimpleBindRequest("owned", "owned", nil)); !errors.Is(err, io.ErrShortWrite) {
		t.Fatalf("short request write was not reported: %v", err)
	}
	if err := connection.Close(); err != nil {
		t.Fatal(err)
	}
	if !errors.Is(connection.GetLastError(), io.ErrShortWrite) || !connection.IsClosing() {
		t.Fatalf("failed request stream remained reusable: %v", connection.GetLastError())
	}
}
