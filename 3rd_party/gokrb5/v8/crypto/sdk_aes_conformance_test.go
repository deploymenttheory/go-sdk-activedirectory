package crypto_test

import (
	"bytes"
	"encoding/hex"
	"testing"

	"github.com/jcmturner/gofork/encoding/asn1"

	krbcrypto "github.com/deploymenttheory/go-sdk-activedirectory/3rd_party/gokrb5/v8/crypto"
	"github.com/deploymenttheory/go-sdk-activedirectory/3rd_party/gokrb5/v8/crypto/common"
	"github.com/deploymenttheory/go-sdk-activedirectory/3rd_party/gokrb5/v8/iana/patype"
	"github.com/deploymenttheory/go-sdk-activedirectory/3rd_party/gokrb5/v8/types"
)

func TestSDKFourAESProfilesRetainKeyAndMACSizes(t *testing.T) {
	for _, profile := range []struct {
		id       int32
		keyBytes int
		macBytes int
	}{{17, 16, 12}, {18, 32, 12}, {19, 16, 16}, {20, 32, 24}} {
		e, err := krbcrypto.GetEtype(profile.id)
		if err != nil {
			t.Fatal(err)
		}
		if e.GetKeyByteSize() != profile.keyBytes || e.GetKeySeedBitLength() != profile.keyBytes*8 ||
			e.GetHMACBitLength() != profile.macBytes*8 {
			t.Fatalf("profile %d conflates its base key and MAC sizes", profile.id)
		}
		key := bytes.Repeat([]byte{0x55}, profile.keyBytes)
		message := []byte("owned Kerberos profile conformance")
		_, encrypted, err := e.EncryptMessage(key, message, 24)
		if err != nil {
			t.Fatalf("profile %d encrypt: %v", profile.id, err)
		}
		plain, err := e.DecryptMessage(key, encrypted, 24)
		if err != nil || !bytes.Equal(plain, message) {
			t.Fatalf("profile %d decrypt: %v", profile.id, err)
		}
		checksum, err := e.GetChecksumHash(key, message, 25)
		if err != nil || len(checksum) != profile.macBytes || !e.VerifyChecksum(key, message, checksum, 25) {
			t.Fatalf("profile %d failed its complete checksum contract: %v", profile.id, err)
		}
		corrupted := append([]byte(nil), encrypted...)
		corrupted[len(corrupted)-1] ^= 1
		if plain, err := e.DecryptMessage(key, corrupted, 24); err == nil || plain != nil {
			t.Fatalf("profile %d released data with a modified integrity tag", profile.id)
		}
		if plain, err := e.DecryptMessage(key[:len(key)-1], encrypted, 24); err == nil || plain != nil {
			t.Fatalf("profile %d accepted the wrong protocol key size", profile.id)
		}
		for length := 0; length < e.GetConfounderByteSize()+profile.macBytes; length++ {
			short := make([]byte, length)
			if plain, err := e.DecryptMessage(key, short, 24); err == nil || plain != nil {
				t.Fatalf("profile %d accepted truncated ciphertext length %d", profile.id, length)
			}
			if e.VerifyIntegrity(key, short, nil, 24) {
				t.Fatalf("profile %d accepted truncated integrity data", profile.id)
			}
		}
	}
}

func TestSDKRFC8009SeparatesAES256BaseAndMACKeys(t *testing.T) {
	e, err := krbcrypto.GetEtype(20)
	if err != nil {
		t.Fatal(err)
	}
	key, _ := hex.DecodeString("6d404d37faf79f9df0d33568d320669800eb4836472ea8a026d16b7182460c52")
	for _, vector := range []struct {
		label    []byte
		expected string
	}{
		{common.GetUsageKc(2), "ef5718be86cc84963d8bbb5031e9f5c4ba41f28faf69e73d"},
		{common.GetUsageKe(2), "56ab22bee63d82d7bc5227f6773f8ea7a5eb1c825160c38312980c442e5c7e49"},
		{common.GetUsageKi(2), "69b16514e3cd8e56b82010d5c73012b622c4d00ffc23ed1f"},
	} {
		got, err := e.DeriveKey(key, vector.label)
		if err != nil || hex.EncodeToString(got) != vector.expected {
			t.Fatalf("RFC8009 key derivation mismatch: %v", err)
		}
	}
	if got, err := e.DeriveKey(key, nil); err != nil || len(got) != 32 {
		t.Fatalf("empty arbitrary label panicked or changed the base key size: %v", err)
	}
}

func TestSDKRFC8009PRFVectors(t *testing.T) {
	// RFC8009 AppendixA: exact PRF outputs for the octet string "test".
	for _, vector := range []struct {
		id       int32
		key      string
		expected string
	}{
		{
			19, "3705d96080c17728a0e800eab6e0d23c",
			"9d188616f63852fe86915bb840b4a886ff3e6bb0f819b49b893393d393854295",
		},
		{
			20, "6d404d37faf79f9df0d33568d320669800eb4836472ea8a026d16b7182460c52",
			"9801f69a368c2bf675e59521e177d9a07f67efe1cfde8d3c8d6f6a0256e3b17d" +
				"b3c1b62ad1b8553360d17367eb1514d2",
		},
	} {
		e, err := krbcrypto.GetEtype(vector.id)
		if err != nil {
			t.Fatal(err)
		}
		key, _ := hex.DecodeString(vector.key)
		output, err := e.DeriveRandom(key, []byte("test"))
		if err != nil || hex.EncodeToString(output) != vector.expected {
			t.Fatalf("RFC8009 PRF profile%d is truncated or incorrect: %x, %v", vector.id, output, err)
		}
	}
}

// Untrusted KDC hints cannot select another algorithm or cause an empty-slice panic.
func TestSDKPasswordDerivationRejectsMalformedOrUnrequestedHints(t *testing.T) {
	for _, dataType := range []int32{patype.PA_ETYPE_INFO, patype.PA_ETYPE_INFO2} {
		for _, body := range [][]byte{{0x30, 0x00}, {0x30, 0x01, 0x00}} {
			_, _, err := krbcrypto.GetKeyFromPassword("test", types.PrincipalName{}, "EXAMPLE.TEST", 20, types.PADataSequence{{PADataType: dataType, PADataValue: body}})
			if err == nil {
				t.Fatalf("type %d accepted malformed or empty hint", dataType)
			}
		}
	}
	for _, entries := range []types.ETypeInfo2{
		{{EType: 23, Salt: "unexpected"}},
		{{EType: 20, Salt: "test", S2KParams: []byte{1}}},
	} {
		body, err := asn1.Marshal(entries)
		if err != nil {
			t.Fatal(err)
		}
		_, _, err = krbcrypto.GetKeyFromPassword("test", types.PrincipalName{}, "EXAMPLE.TEST", 20, types.PADataSequence{{PADataType: patype.PA_ETYPE_INFO2, PADataValue: body}})
		if err == nil {
			t.Fatal("accepted unrequested algorithm or malformed S2K parameters")
		}
	}
	entries := types.ETypeInfo2{{EType: 23, Salt: "wrong"}, {EType: 20, Salt: "chosen", S2KParams: []byte{0, 0, 0, 1}}}
	body, err := asn1.Marshal(entries)
	if err != nil {
		t.Fatal(err)
	}
	key, et, err := krbcrypto.GetKeyFromPassword("test", types.PrincipalName{}, "EXAMPLE.TEST", 20, types.PADataSequence{{PADataType: patype.PA_ETYPE_INFO2, PADataValue: body}})
	if err != nil {
		t.Fatal(err)
	}
	expected, err := et.StringToKey("test", "chosen", "00000001")
	if err != nil {
		t.Fatal(err)
	}
	if key.KeyType != 20 || et.GetETypeID() != 20 || !bytes.Equal(expected, key.KeyValue) {
		t.Fatal("did not retain requested enctype and its matching salt")
	}
}

func TestSDKPasswordDerivationRejectsUnboundedIterationCounts(t *testing.T) {
	for _, id := range []int32{17, 18, 19, 20} {
		et, err := krbcrypto.GetEtype(id)
		if err != nil {
			t.Fatal(err)
		}
		for _, count := range []string{"00000000", "00100001", "ffffffff"} {
			key, err := et.StringToKey("test", "salt", count)
			if err == nil || key != nil {
				t.Fatalf("profile %d accepted unsupported iteration count %s", id, count)
			}
		}
		key, err := et.StringToKey("test", "salt", "00000001")
		if err != nil || len(key) != et.GetKeyByteSize() {
			t.Fatalf("profile %d rejected supported iteration count", id)
		}
		if et.VerifyChecksum(nil, nil, nil, 0) {
			t.Fatalf("profile %d accepted empty checksum/key", id)
		}
	}
}

// Keeping upstream legacy codecs does not permit malformed inputs to panic.
// These tests do not authorize the SDK to negotiate either legacy algorithm.
func TestSDKRetainedLegacyCodecsRejectTruncatedInputs(t *testing.T) {
	for _, id := range []int32{16, 23} {
		et, err := krbcrypto.GetEtype(id)
		if err != nil {
			t.Fatal(err)
		}
		key := bytes.Repeat([]byte{0x55}, et.GetKeyByteSize())
		for n := 0; n < et.GetConfounderByteSize()+et.GetHMACBitLength()/8; n++ {
			if plain, err := et.DecryptMessage(key, make([]byte, n), 24); err == nil || len(plain) != 0 {
				t.Fatalf("legacy profile %d accepted truncated input %d", id, n)
			}
			if et.VerifyIntegrity(key, make([]byte, n), nil, 24) {
				t.Fatal("verified truncated legacy message")
			}
		}
		if _, _, err := et.EncryptData(key, nil); id == 16 && err == nil {
			t.Fatal("DES3 accepted empty data")
		}
	}
}
