package ldap

import (
	"bytes"
	"errors"
	"fmt"
	"io"
	"math"
	"testing"

	"github.com/deploymenttheory/go-sdk-activedirectory/3rd_party/gokrb5/v8/crypto"
	"github.com/deploymenttheory/go-sdk-activedirectory/3rd_party/gokrb5/v8/types"
	ldapgss "github.com/deploymenttheory/go-sdk-activedirectory/3rd_party/ldap/v3/gssapi"
)

type singleOctetReader struct{ io.Reader }

func (r singleOctetReader) Read(p []byte) (int, error) {
	if len(p) > 1 {
		p = p[:1]
	}
	return r.Reader.Read(p)
}

func adversarialSASLKey(t *testing.T, profile int32) types.EncryptionKey {
	t.Helper()
	et, err := crypto.GetEtype(profile)
	if err != nil {
		t.Fatal(err)
	}
	return types.EncryptionKey{KeyType: profile, KeyValue: bytes.Repeat([]byte{0x41}, et.GetKeyByteSize())}
}

func adversarialSASLToken(t *testing.T, key types.EncryptionKey, mode SASLSecurityMode, payload []byte, seq uint64) []byte {
	t.Helper()
	if payload == nil {
		payload = []byte{}
	}
	var wire []byte
	var err error
	if mode == SASLSecuritySeal {
		wire, err = peerSealWrite(key, payload, seq)
	} else {
		wire, err = peerSignWrite(key, payload, seq)
	}
	if err != nil {
		t.Fatal(err)
	}
	return wire
}

func adversarialSASLConnection(t *testing.T, key types.EncryptionKey, mode SASLSecurityMode, stream []byte) (*krbSASLConn, *kerberosCaptureConn) {
	t.Helper()
	transport := &kerberosCaptureConn{fakeReadConn: fakeReadConn{r: singleOctetReader{bytes.NewReader(stream)}}}
	connection, err := newKrbSASLConnWithContext(transport, ldapgss.SASLSecurityContext{
		KeyType: key.KeyType, KeyValue: key.KeyValue, SASLSecurity: int(mode), AcceptorSubkey: true,
		PeerMaxTokenSize: 65535, LocalMaxTokenSize: 65535,
	}, mode)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = connection.Close() })
	return connection, transport
}

func TestSASLAllAESProfilesRejectCorruptTruncatedAndReorderedFrames(t *testing.T) {
	for _, profile := range []int32{17, 18, 19, 20} {
		for _, mode := range []SASLSecurityMode{SASLSecuritySign, SASLSecuritySeal} {
			for _, scenario := range []string{
				"token-id", "direction", "protection", "key-origin", "filler", "sequence", "ec", "mac", "short-prefix", "short-body", "zero-size", "oversize",
			} {
				t.Run(fmt.Sprintf("profile=%d/mode=%d/%s", profile, mode, scenario), func(t *testing.T) {
					key := adversarialSASLKey(t, profile)
					wire := adversarialSASLToken(t, key, mode, []byte("authenticated fixture"), 0)
					switch scenario {
					case "token-id":
						wire[0] ^= 1
					case "direction":
						wire[2] ^= 1
					case "protection":
						wire[2] ^= 2
					case "key-origin":
						wire[2] ^= 4
					case "filler":
						wire[3] ^= 1
					case "sequence":
						wire[15] = 1
					case "ec":
						wire[4], wire[5] = 255, 255
					case "mac":
						wire[len(wire)-1] ^= 1
					}
					stream := frameWith4ByteLen(wire)
					switch scenario {
					case "short-prefix":
						stream = stream[:3]
					case "short-body":
						stream = stream[:len(stream)-1]
					case "zero-size":
						stream = []byte{0, 0, 0, 0}
					case "oversize":
						stream = []byte{0, 1, 0, 0}
					}
					connection, transport := adversarialSASLConnection(t, key, mode, stream)
					buffer := make([]byte, 64)
					if n, err := connection.Read(buffer); err == nil || n != 0 {
						t.Fatal("invalid protected token produced plaintext")
					}
					if !transport.closed.Load() || !bytes.Equal(connection.subkey.KeyValue, make([]byte, len(key.KeyValue))) {
						t.Fatal("terminal failure did not close the stream and clear its copied key")
					}
					if n, err := connection.Write([]byte("must-not-submit")); err == nil || n != 0 || transport.written.Len() != 0 {
						t.Fatal("poisoned connection submitted another operation")
					}
					if _, err := connection.Read(buffer); err == nil {
						t.Fatal("poisoned connection resumed reading")
					}
				})
			}
		}
	}
}

func TestSASLAllAESProfilesRejectReplayAfterAcceptedFragment(t *testing.T) {
	for _, profile := range []int32{17, 18, 19, 20} {
		for _, mode := range []SASLSecurityMode{SASLSecuritySign, SASLSecuritySeal} {
			t.Run(fmt.Sprintf("profile=%d/mode=%d", profile, mode), func(t *testing.T) {
				key := adversarialSASLKey(t, profile)
				frame := frameWith4ByteLen(adversarialSASLToken(t, key, mode, []byte("accepted"), 0))
				connection, _ := adversarialSASLConnection(t, key, mode, append(bytes.Clone(frame), frame...))
				buffer := make([]byte, 64)
				if n, err := connection.Read(buffer); err != nil || string(buffer[:n]) != "accepted" {
					t.Fatalf("valid control rejected: %v", err)
				}
				if n, err := connection.Read(buffer); err == nil || n != 0 {
					t.Fatal("replayed token was accepted")
				}
			})
		}
	}
}

func TestSASLEmptyTokensPreserveProgressAndEnforceBudget(t *testing.T) {
	for _, mode := range []SASLSecurityMode{SASLSecuritySign, SASLSecuritySeal} {
		key := adversarialSASLKey(t, 20)
		var stream []byte
		for seq := range uint64(3) {
			stream = append(stream, frameWith4ByteLen(adversarialSASLToken(t, key, mode, nil, seq))...)
		}
		stream = append(stream, frameWith4ByteLen(adversarialSASLToken(t, key, mode, []byte("next"), 3))...)
		connection, _ := adversarialSASLConnection(t, key, mode, stream)
		buffer := make([]byte, 64)
		if n, err := connection.Read(buffer); err != nil || string(buffer[:n]) != "next" {
			t.Fatalf("valid empty tokens stalled protected reads: %v", err)
		}
		stream = nil
		for seq := range uint64(16) {
			stream = append(stream, frameWith4ByteLen(adversarialSASLToken(t, key, mode, nil, seq))...)
		}
		limited, _ := adversarialSASLConnection(t, key, mode, stream)
		if _, err := limited.Read(buffer); !errors.Is(err, io.ErrNoProgress) {
			t.Fatalf("empty authenticated traffic evaded progress bounds: %v", err)
		}
	}
}

func TestSASLSequenceExhaustionCannotReuseZero(t *testing.T) {
	key := adversarialSASLKey(t, 17)
	for _, direction := range []string{"send", "receive"} {
		connection, transport := adversarialSASLConnection(t, key, SASLSecuritySeal, nil)
		var err error
		if direction == "send" {
			connection.wSeqNum = math.MaxUint64
			_, err = connection.Write([]byte("must-not-wrap"))
		} else {
			connection.rSeqNum = math.MaxUint64
			_, err = connection.Read(make([]byte, 1))
		}
		if err == nil || !transport.closed.Load() || transport.written.Len() != 0 {
			t.Fatalf("%s sequence exhaustion left a reusable context", direction)
		}
	}
}

func TestSASLConsumedAndRetiredPlaintextBuffersAreCleared(t *testing.T) {
	key := adversarialSASLKey(t, 18)
	frame := frameWith4ByteLen(adversarialSASLToken(t, key, SASLSecuritySeal, []byte("private plaintext"), 0))
	connection, _ := adversarialSASLConnection(t, key, SASLSecuritySeal, frame)
	buffer := make([]byte, 1)
	if _, err := connection.Read(buffer); err != nil {
		t.Fatal(err)
	}
	retained := connection.rBuf.buf
	if retained[0] != 0 || buffer[0] != 'p' {
		t.Fatal("consumed plaintext was not copied then cleared")
	}
	if err := connection.Close(); err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(retained, make([]byte, len(retained))) {
		t.Fatal("retirement retained unread plaintext")
	}
}
