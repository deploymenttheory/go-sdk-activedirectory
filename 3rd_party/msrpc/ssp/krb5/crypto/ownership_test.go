package crypto

import (
	"bytes"
	"context"
	"testing"

	krbcrypto "github.com/deploymenttheory/go-sdk-activedirectory/3rd_party/gokrb5/v8/crypto"
	"github.com/deploymenttheory/go-sdk-activedirectory/3rd_party/gokrb5/v8/crypto/etype"
	"github.com/deploymenttheory/go-sdk-activedirectory/3rd_party/gokrb5/v8/types"
)

type qualificationCallerEType struct{ etype.EType }

func (qualificationCallerEType) GetKeyByteSize() int { return 0 }

func TestQualificationRecordUsesCanonicalProfileNotCallerImplementation(t *testing.T) {
	et, err := krbcrypto.GetEtype(18)
	if err != nil {
		t.Fatal(err)
	}
	cipher, err := NewCipher(
		context.Background(),
		CipherSetting{Type: qualificationCallerEType{et}, Key: types.EncryptionKey{KeyType: 18, KeyValue: bytes.Repeat([]byte{0x71}, 32)}, IsLocal: true, DCEStyle: true},
	)
	if err != nil {
		t.Fatalf("caller implementation changed the canonical profile: %v", err)
	}
	defer cipher.Destroy()
	body := make([]byte, 16)
	if _, err = cipher.WrapEx(context.Background(), 0, [][]byte{[]byte("header"), body, []byte("trailer")}, [][]byte{body}); err != nil {
		t.Fatal(err)
	}
}
