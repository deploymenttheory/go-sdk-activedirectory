package gssapi

import (
	"testing"

	"github.com/jcmturner/gofork/encoding/asn1"

	"github.com/deploymenttheory/go-sdk-activedirectory/3rd_party/gokrb5/v8/messages"
)

func TestMutualAuthenticationRejectsTrailingMechanismBytes(t *testing.T) {
	client := contextTestClient(t, false)
	// A completed context cannot accept another authenticator response; using
	// the valid fixture response here tests only its bounded mechanism decoder.
	valid := contextTestAPRepToken(t, client.ekey, messages.EncAPRepPart{CTime: client.authenticatorTime, Cusec: client.authenticatorUsec, SequenceNumber: 712})
	var outer asn1.RawValue
	if _, err := asn1.Unmarshal(valid, &outer); err != nil {
		t.Fatal(err)
	}
	innerGarbage := outer
	innerGarbage.FullBytes = nil
	innerGarbage.Bytes = append(append([]byte(nil), outer.Bytes...), 0)
	encoded, err := asn1.Marshal(innerGarbage)
	if err != nil {
		t.Fatal(err)
	}
	for _, wire := range [][]byte{append(append([]byte(nil), valid...), 0), encoded} {
		var token krb5Token
		if err := token.Unmarshal(wire); err == nil {
			t.Fatal("mechanism token accepted trailing bytes")
		}
	}
}
