package gssapi

import (
	"bytes"
	"fmt"
	"testing"
	"time"

	"github.com/deploymenttheory/go-sdk-activedirectory/3rd_party/gokrb5/v8/crypto"
	"github.com/deploymenttheory/go-sdk-activedirectory/3rd_party/gokrb5/v8/messages"
	"github.com/deploymenttheory/go-sdk-activedirectory/3rd_party/gokrb5/v8/types"
)

func TestAPRepSubkeyRequiresAdvertisedProfileAndExactAESKey(t *testing.T) {
	for _, profile := range []int32{17, 18, 19, 20} {
		et, err := crypto.GetEtype(profile)
		if err != nil {
			t.Fatal(err)
		}
		for _, delta := range []int{-1, 0, 1} {
			t.Run(fmt.Sprintf("profile=%d/size-delta=%d", profile, delta), func(t *testing.T) {
				client := &Client{ekey: types.EncryptionKey{KeyType: profile, KeyValue: bytes.Repeat([]byte{0x41}, et.GetKeyByteSize())}}
				authenticator := types.Authenticator{CTime: time.Now().UTC().Truncate(time.Second), Cusec: 124, SeqNumber: 17, SubKey: client.ekey}
				if err := client.retainAuthenticator(authenticator); err != nil {
					t.Fatal(err)
				}
				part := messages.EncAPRepPart{CTime: authenticator.CTime, Cusec: authenticator.Cusec, SequenceNumber: 83,
					Subkey: types.EncryptionKey{KeyType: profile, KeyValue: bytes.Repeat([]byte{0x42}, et.GetKeyByteSize()+delta)}}
				err := client.acceptAPRepPart(part)
				if delta == 0 {
					if err != nil || !client.mutualAuthenticated {
						t.Fatalf("exact AES subkey rejected: %v", err)
					}
					return
				}
				if err == nil || client.mutualAuthenticated || len(client.Subkey.KeyValue) != 0 {
					t.Fatal("invalid subkey retained or mutual authentication asserted")
				}
			})
		}
	}
	for _, profile := range []int32{0, 3, 16, 18, 19, 20, 23, -1} {
		client := contextTestClient(t, false)
		client.mutualAuthenticated = false
		part := messages.EncAPRepPart{CTime: client.authenticatorTime, Cusec: client.authenticatorUsec, SequenceNumber: 83,
			Subkey: types.EncryptionKey{KeyType: profile, KeyValue: bytes.Repeat([]byte{0x42}, 16)}}
		if err := client.acceptAPRepPart(part); err == nil || client.mutualAuthenticated {
			t.Fatalf("accepted unsolicited profile=%d", profile)
		}
	}
}

func TestSASLContextUsesFrozenAuthenticatedLayer(t *testing.T) {
	client := contextTestClient(t, true)
	client.SASLSecurity = 4
	if _, err := client.NegotiateSaslAuth(contextTestServerOffer(t, client, []byte{7, 0, 255, 255}, 0), ""); err != nil {
		t.Fatal(err)
	}
	client.SASLSecurity = 0
	context, err := client.SASLContext()
	if err != nil || context.SASLSecurity != 4 {
		t.Fatalf("mutable request changed authenticated exported layer: %v", err)
	}
	clear(context.KeyValue)
}
