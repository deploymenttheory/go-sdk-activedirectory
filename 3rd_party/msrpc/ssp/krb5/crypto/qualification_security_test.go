package crypto

import (
	"bytes"
	"context"
	"fmt"
	"testing"

	krbcrypto "github.com/deploymenttheory/go-sdk-activedirectory/3rd_party/gokrb5/v8/crypto"
	"github.com/deploymenttheory/go-sdk-activedirectory/3rd_party/gokrb5/v8/types"
)

func qualificationCipher(t *testing.T) Cipher {
	t.Helper()
	et, err := krbcrypto.GetEtype(18)
	if err != nil {
		t.Fatal(err)
	}
	cipher, err := NewCipher(context.Background(), CipherSetting{
		Key:  types.EncryptionKey{KeyType: 18, KeyValue: bytes.Repeat([]byte{0x71}, 32)},
		Type: et, IsLocal: false, IsSubKey: true, DCEStyle: true,
	})
	if err != nil {
		t.Fatal(err)
	}
	return cipher
}

func TestQualificationShortRPCSignatureMustNotPanic(t *testing.T) {
	for n := range 16 {
		t.Run(fmt.Sprint(n), func(t *testing.T) {
			defer func() {
				if recovered := recover(); recovered != nil {
					t.Errorf("untrusted signature length %d panicked: %v", n, recovered)
				}
			}()
			ok, err := qualificationCipher(t).UnwrapEx(context.Background(), 7, nil, nil, make([]byte, n))
			if err == nil || ok {
				t.Fatal("short signature was accepted")
			}
		})
	}
}

func TestQualificationRPCSequenceAndOuterHeader(t *testing.T) {
	ctx := context.Background()
	payload := []byte("authenticated replication diagnostic reply")
	ciphertext := bytes.Clone(payload)
	signature, err := qualificationCipher(t).WrapEx(ctx, 7, [][]byte{ciphertext}, [][]byte{ciphertext})
	if err != nil {
		t.Fatal(err)
	}
	for _, tc := range []struct {
		name   string
		seq    uint64
		mutate func([]byte)
		wantOK bool
	}{
		{"valid", 7, nil, true},
		{"reordered", 8, nil, false},
		{"wrong-token-id", 7, func(b []byte) { b[0] ^= 1 }, false},
		{"wrong-sender-role", 7, func(b []byte) { b[2] ^= CFXFlagSendByAcceptor }, false},
		{"unsealed-flag", 7, func(b []byte) { b[2] ^= CFXFlagSealed }, false},
		{"wrong-key-origin", 7, func(b []byte) { b[2] ^= CFXFlagAcceptorSubKey }, false},
	} {
		t.Run(tc.name, func(t *testing.T) {
			body, token := bytes.Clone(ciphertext), bytes.Clone(signature)
			if tc.mutate != nil {
				tc.mutate(token)
			}
			ok, err := qualificationCipher(t).UnwrapEx(ctx, tc.seq, [][]byte{body}, [][]byte{body}, token)
			if tc.wantOK {
				if err != nil || !ok || !bytes.Equal(body, payload) {
					t.Fatalf("valid control failed: ok=%v err=%v", ok, err)
				}
			} else if err == nil && ok {
				t.Fatal("authenticated RPC record with unexpected sequence/header was accepted")
			}
		})
	}
}
