package gssapi

import (
	"bytes"
	"encoding/binary"
	"math"
	"testing"
	"time"

	krbgss "github.com/deploymenttheory/go-sdk-activedirectory/3rd_party/gokrb5/v8/gssapi"
	"github.com/deploymenttheory/go-sdk-activedirectory/3rd_party/gokrb5/v8/types"
)

func TestDelegationChecksumRequiresExplicitBoundedCredential(t *testing.T) {
	for _, size := range []int{0, 1, math.MaxUint16, math.MaxUint16 + 1} {
		for _, requested := range []bool{false, true} {
			client := &Client{delegationRequested: requested}
			credential := bytes.Repeat([]byte{0x6a}, size)
			binding := [16]byte{0x31, 0x80}
			checksum, err := client.delegationChecksum([]uint32{krbgss.ContextFlagMutual}, &binding, credential)
			wantError := requested != (size != 0) || size > math.MaxUint16
			if (err != nil) != wantError {
				t.Fatalf("requested=%t size=%d error=%v", requested, size, err)
			}
			if wantError {
				if checksum != nil {
					t.Fatal("refused forwarding emitted a partial checksum")
				}
				continue
			}
			if binary.LittleEndian.Uint32(checksum[:4]) != 16 || !bytes.Equal(checksum[4:20], binding[:]) {
				t.Fatal("forwarding changed the certificate binding")
			}
			if !requested {
				if len(checksum) != 24 || binary.LittleEndian.Uint32(checksum[20:24]) != krbgss.ContextFlagMutual {
					t.Fatal("ordinary authentication emitted forwarding material or intent")
				}
				continue
			}
			if len(checksum) != size+28 || binary.LittleEndian.Uint32(checksum[20:24]) != krbgss.ContextFlagMutual|krbgss.ContextFlagDeleg ||
				binary.LittleEndian.Uint16(checksum[24:26]) != 1 || int(binary.LittleEndian.Uint16(checksum[26:28])) != size ||
				!bytes.Equal(checksum[28:], credential) {
				t.Fatal("forwarding changed the authenticated GSS envelope")
			}
		}
	}
}

func TestDelegationPolicyCannotChangeAnActiveContext(t *testing.T) {
	for _, client := range []*Client{{ekey: types.EncryptionKey{KeyValue: []byte{1}}}, {mutualAuthenticated: true}, {saslNegotiated: true}} {
		if err := client.SetDelegation(true); err == nil {
			t.Fatal("active context accepted new delegation policy")
		}
	}
	client := &Client{}
	if err := client.SetDelegation(true); err != nil {
		t.Fatal(err)
	}
	if _, err := client.AuthenticationContext(); err == nil {
		t.Fatal("configuration alone manufactured delegation observations")
	}
}

func TestContextProtocolFailureRetiresDerivedKeysAndDelegationFacts(t *testing.T) {
	key, subkey, initiator := []byte{1, 2}, []byte{3, 4}, []byte{5, 6}
	client := &Client{
		ekey: types.EncryptionKey{KeyValue: key}, Subkey: types.EncryptionKey{KeyValue: subkey},
		initiatorSubkey: types.EncryptionKey{KeyValue: initiator}, delegationRequested: true,
		delegationSent: true, delegationExpiresAt: time.Now().Add(time.Hour),
		mutualAuthenticated: true, saslNegotiated: true, contextExpiresAt: time.Now().Add(time.Hour),
	}
	if _, _, err := client.InitSecContextWithOptions("ldap/dc.example.test", []byte{0x60, 0xff}, nil); err == nil {
		t.Fatal("malformed mechanism continuation was accepted")
	}
	if !bytes.Equal(key, make([]byte, len(key))) || !bytes.Equal(subkey, make([]byte, len(subkey))) || !bytes.Equal(initiator, make([]byte, len(initiator))) ||
		client.delegationSent || !client.delegationExpiresAt.IsZero() || !client.contextExpiresAt.IsZero() || !client.delegationRequested {
		t.Fatal("failed mechanism retained keys/facts or weakened the explicit forwarding policy")
	}
	if _, err := client.AuthenticationContext(); err == nil {
		t.Fatal("failed mechanism remained observable as established")
	}
}
