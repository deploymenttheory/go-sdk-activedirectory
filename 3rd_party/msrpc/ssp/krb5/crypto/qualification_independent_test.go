package crypto

import (
	"bytes"
	"context"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"log/slog"
	"os"
	"strings"
	"testing"

	krbcrypto "github.com/deploymenttheory/go-sdk-activedirectory/3rd_party/gokrb5/v8/crypto"
	"github.com/deploymenttheory/go-sdk-activedirectory/3rd_party/gokrb5/v8/types"
)

func TestQualificationIndependentPythonRecords(t *testing.T) {
	data, err := os.ReadFile("testdata/rpc-python-records.json")
	if err != nil {
		t.Fatal(err)
	}
	var fixture struct {
		Cases []struct {
			Etype                                                   int32
			Acceptor                                                bool
			Sequence                                                uint64
			Key, Header, Plain, Trailer, Signature, Ciphertext, MIC string
		}
	}
	if err := json.Unmarshal(data, &fixture); err != nil {
		t.Fatal(err)
	}
	if len(fixture.Cases) != 4 {
		t.Fatal("missing independent record cases")
	}
	decode := func(s string) []byte {
		b, err := hex.DecodeString(s)
		if err != nil {
			t.Fatal(err)
		}
		return b
	}
	for _, tc := range fixture.Cases {
		t.Run(fmt.Sprintf("etype%d-acceptor%t", tc.Etype, tc.Acceptor), func(t *testing.T) {
			et, err := krbcrypto.GetEtype(tc.Etype)
			if err != nil {
				t.Fatal(err)
			}
			key := decode(tc.Key)
			setting := CipherSetting{Key: types.EncryptionKey{KeyType: tc.Etype, KeyValue: key}, Type: et, IsLocal: !tc.Acceptor, IsSubKey: true, DCEStyle: true}
			cipher, err := NewCipher(context.Background(), setting)
			if err != nil {
				t.Fatal(err)
			}
			clear(key) // constructor must own a copy
			body, header, trailer, token := decode(tc.Ciphertext), decode(tc.Header), decode(tc.Trailer), decode(tc.Signature)
			originalToken := bytes.Clone(token)
			ok, err := cipher.UnwrapEx(context.Background(), tc.Sequence, [][]byte{header, body, trailer}, [][]byte{body}, token)
			if err != nil || !ok || !bytes.Equal(body, decode(tc.Plain)) {
				t.Fatalf("independent record failed: ok=%t err=%v", ok, err)
			}
			if !bytes.Equal(token, originalToken) {
				t.Fatal("caller token was mutated")
			}
			mic, err := cipher.MakeSignature(context.Background(), tc.Sequence, [][]byte{header, body, trailer})
			if err != nil || !bytes.Equal(mic, decode(tc.MIC)) {
				t.Fatalf("independent MIC differs: err=%v", err)
			}
			for _, target := range []string{"signature", "ciphertext", "signed-header", "trailer"} {
				t.Run("tampered-"+target, func(t *testing.T) {
					body, header, trailer, token := decode(tc.Ciphertext), decode(tc.Header), decode(tc.Trailer), decode(tc.Signature)
					switch target {
					case "signature":
						token[len(token)-1] ^= 1
					case "ciphertext":
						body[len(body)/2] ^= 1
					case "signed-header":
						header[12] ^= 1
					case "trailer":
						trailer[0] ^= 1
					}
					before := bytes.Clone(body)
					ok, err := cipher.UnwrapEx(context.Background(), tc.Sequence, [][]byte{header, body, trailer}, [][]byte{body}, token)
					if err == nil || ok {
						t.Fatal("tampered record accepted")
					}
					if !bytes.Equal(body, before) {
						t.Fatal("unauthenticated plaintext published")
					}
				})
			}
			concrete := cipher.(*AESCTSHMACSHA1)
			owned := concrete.setting.Key.KeyValue
			concrete.Destroy()
			if !bytes.Equal(owned, make([]byte, len(owned))) {
				t.Fatal("record key not cleared")
			}
			if _, err := cipher.MakeSignature(context.Background(), 0, nil); !errors.Is(err, ErrRetiredContext) {
				t.Fatalf("retired key usable: %v", err)
			}
		})
	}
}

func TestQualificationRecordInputsAndSecretOwnership(t *testing.T) {
	et, err := krbcrypto.GetEtype(18)
	if err != nil {
		t.Fatal(err)
	}
	for _, setting := range []CipherSetting{
		{},
		{Type: et},
		{Type: et, Key: types.EncryptionKey{KeyType: 17, KeyValue: make([]byte, 32)}},
		{Type: et, Key: types.EncryptionKey{KeyType: 18, KeyValue: make([]byte, 31)}},
	} {
		if cipher, err := NewCipher(context.Background(), setting); err == nil || cipher != nil {
			t.Fatal("invalid record setting accepted")
		}
	}
	key := make([]byte, 32)
	copy(key, bytes.Repeat([]byte("SYNTHETIC-SECRET!"), 2))
	setting := CipherSetting{Type: et, Key: types.EncryptionKey{KeyType: 18, KeyValue: key}, IsLocal: true, IsSubKey: true, DCEStyle: true}
	cipher, err := NewCipher(context.Background(), setting)
	if err != nil {
		t.Fatal(err)
	}
	for _, verb := range []string{"%v", "%+v", "%#v", "%s", "%d", "%x", "%q"} {
		for _, value := range []any{setting, &setting, struct{ Setting CipherSetting }{setting}, cipher} {
			if output := fmt.Sprintf(verb, value); strings.Contains(output, "SYNTHETIC") || strings.Contains(output, "83 89 78") {
				t.Fatalf("secret formatting leaked with verb%s", verb)
			}
		}
	}
	for _, value := range []any{setting, cipher} {
		encoded, err := json.Marshal(value)
		if err != nil || bytes.Contains(encoded, []byte("SYNTHETIC")) {
			t.Fatal("secret JSON leak")
		}
		var log bytes.Buffer
		slog.New(slog.NewJSONHandler(&log, nil)).Info("record", "key", value)
		if bytes.Contains(log.Bytes(), []byte("SYNTHETIC")) {
			t.Fatal("structured secret leak")
		}
	}
	for _, test := range []struct {
		sign, seal [][]byte
		want       error
	}{
		{[][]byte{make([]byte, maxRecordBytes+1)}, nil, ErrMessageTooLarge},
		{nil, [][]byte{[]byte("unsigned ciphertext")}, ErrInvalidToken},
	} {
		if _, err := cipher.WrapEx(context.Background(), 0, test.sign, test.seal); !errors.Is(err, test.want) {
			t.Fatalf("buffer contract: %v", err)
		}
	}
	ctx, cancel := context.WithCancelCause(context.Background())
	cause := errors.New("owned record cancellation")
	cancel(cause)
	if _, err := cipher.WrapEx(ctx, 0, nil, nil); !errors.Is(err, cause) {
		t.Fatal("record lost caller cancellation cause")
	}
}

func TestQualificationRefusesUnimplementedRFC8009WithoutFallback(t *testing.T) {
	for _, profile := range []int32{19, 20} {
		et, err := krbcrypto.GetEtype(profile)
		if err != nil {
			t.Fatal(err)
		}
		cipher, err := NewCipher(context.Background(), CipherSetting{Type: et, Key: types.EncryptionKey{KeyType: profile, KeyValue: make([]byte, et.GetKeyByteSize())}})
		if cipher != nil || !errors.Is(err, ErrUnsupportedProfile) {
			t.Fatalf("profile%d selected unqualified record semantics: %v", profile, err)
		}
	}
}
