package ldap

import (
	"bytes"
	"encoding/binary"
	"errors"
	"io"
	"net"
	"sync/atomic"
	"testing"

	"github.com/deploymenttheory/go-sdk-activedirectory/3rd_party/gokrb5/v8/crypto"
	krbgss "github.com/deploymenttheory/go-sdk-activedirectory/3rd_party/gokrb5/v8/gssapi"
	"github.com/deploymenttheory/go-sdk-activedirectory/3rd_party/gokrb5/v8/iana/keyusage"
	"github.com/deploymenttheory/go-sdk-activedirectory/3rd_party/gokrb5/v8/types"
	ldapgss "github.com/deploymenttheory/go-sdk-activedirectory/3rd_party/ldap/v3/gssapi"
)

// The old constructor shape is retained only for existing synthetic-token tests.
// Production must obtain sequence and limit values from the authenticated GSS context.
func newKrbSASLConn(conn net.Conn, keyType int32, keyValue []byte, mode SASLSecurityMode) *krbSASLConn {
	result, err := newKrbSASLConnWithContext(conn, ldapgss.SASLSecurityContext{
		KeyType: keyType, KeyValue: keyValue, AcceptorSubkey: true,
		SendSequence: 2, ReceiveSequence: 0, PeerMaxTokenSize: 65535, LocalMaxTokenSize: 65535,
	}, mode)
	if err != nil {
		panic(err)
	}
	return result
}

type kerberosCaptureConn struct {
	fakeReadConn
	written bytes.Buffer
	short   bool
	closed  atomic.Bool
}

func (c *kerberosCaptureConn) Write(p []byte) (int, error) {
	if c.closed.Load() {
		return 0, net.ErrClosed
	}
	if c.short {
		return len(p) / 2, nil
	}
	return c.written.Write(p)
}

func (c *kerberosCaptureConn) Close() error { c.closed.Store(true); return nil }

func TestKerberosFragmentsToNegotiatedTokenLimit(t *testing.T) {
	for _, mode := range []SASLSecurityMode{SASLSecuritySign, SASLSecuritySeal} {
		for _, keyType := range []int32{17, 18, 19, 20} {
			et, err := crypto.GetEtype(keyType)
			if err != nil {
				t.Fatal(err)
			}
			key := bytes.Repeat([]byte{0x41}, et.GetKeyByteSize())
			const limit = 100
			transport := &kerberosCaptureConn{fakeReadConn: fakeReadConn{r: bytes.NewReader(nil)}}
			connection, err := newKrbSASLConnWithContext(transport, ldapgss.SASLSecurityContext{
				KeyType: keyType, KeyValue: key, AcceptorSubkey: true, SendSequence: 981, ReceiveSequence: 407,
				PeerMaxTokenSize: limit, LocalMaxTokenSize: 65535,
			}, mode)
			if err != nil {
				t.Fatal(err)
			}
			payload := bytes.Repeat([]byte("owned-data"), 37)
			if n, err := connection.Write(payload); err != nil || n != len(payload) {
				t.Fatalf("write mode=%d etype=%d n=%d err=%v", mode, keyType, n, err)
			}
			var decoded []byte
			sequence := uint64(981)
			frames := 0
			for transport.written.Len() > 0 {
				var size [4]byte
				if _, err := io.ReadFull(&transport.written, size[:]); err != nil {
					t.Fatal(err)
				}
				tokenSize := binary.BigEndian.Uint32(size[:])
				if tokenSize > limit {
					t.Fatal("exceeded peer negotiated output-message limit")
				}
				token := make([]byte, tokenSize)
				if _, err := io.ReadFull(&transport.written, token); err != nil {
					t.Fatal(err)
				}
				if binary.BigEndian.Uint64(token[8:16]) != sequence {
					t.Fatal("lost initial GSS send sequence or per-frame increment")
				}
				sequence++
				frames++
				if mode == SASLSecuritySeal {
					plain, err := et.DecryptMessage(key, token[16:], keyusage.GSSAPI_INITIATOR_SEAL)
					if err != nil {
						t.Fatal(err)
					}
					decoded = append(decoded, plain[:len(plain)-16]...)
				} else {
					var wrapped krbgss.WrapToken
					if err := wrapped.Unmarshal(token, false); err != nil {
						t.Fatal(err)
					}
					if _, err := wrapped.Verify(types.EncryptionKey{KeyType: keyType, KeyValue: key}, keyusage.GSSAPI_INITIATOR_SEAL); err != nil {
						t.Fatal(err)
					}
					decoded = append(decoded, wrapped.Payload...)
				}
			}
			if frames < 2 || !bytes.Equal(decoded, payload) {
				t.Fatal("fragmented LDAP byte stream changed")
			}
			ownedKey := connection.subkey.KeyValue
			if err := connection.Close(); err != nil {
				t.Fatal(err)
			}
			if !bytes.Equal(ownedKey, make([]byte, len(ownedKey))) || bytes.Equal(key, ownedKey) {
				t.Fatal("key retirement did not clear owned copy independently")
			}
		}
	}
}

func TestKerberosPoisonsAfterShortWriteAndOrderingFailure(t *testing.T) {
	keyType, key := newTestSubkey(t)
	transport := &kerberosCaptureConn{fakeReadConn: fakeReadConn{r: bytes.NewReader(nil)}, short: true}
	connection := newKrbSASLConn(transport, keyType, key, SASLSecuritySeal)
	if n, err := connection.Write([]byte("owned-data")); n != 0 || !errors.Is(err, io.ErrShortWrite) {
		t.Fatalf("short write: %d %v", n, err)
	}
	if !transport.closed.Load() {
		t.Fatal("short write did not retire transport")
	}
	if _, err := connection.Write([]byte("second")); !errors.Is(err, io.ErrShortWrite) {
		t.Fatal("poisoned writer reused")
	}
	if err := connection.Close(); err != nil {
		t.Fatal(err)
	}
	if err := connection.Close(); err != nil {
		t.Fatal(err)
	}

	token, err := peerSealWrite(types.EncryptionKey{KeyType: keyType, KeyValue: key}, []byte("owned-response"), 408)
	if err != nil {
		t.Fatal(err)
	}
	readTransport := &kerberosCaptureConn{fakeReadConn: fakeReadConn{r: bytes.NewReader(frameWith4ByteLen(token))}}
	reader, err := newKrbSASLConnWithContext(readTransport, ldapgss.SASLSecurityContext{
		KeyType: keyType, KeyValue: key, AcceptorSubkey: true, SendSequence: 981, ReceiveSequence: 407, PeerMaxTokenSize: 65535, LocalMaxTokenSize: 65535,
	}, SASLSecuritySeal)
	if err != nil {
		t.Fatal(err)
	}
	_, firstErr := reader.Read(make([]byte, 100))
	if firstErr == nil || !readTransport.closed.Load() {
		t.Fatal("sequence mismatch did not poison transport")
	}
	if _, err := reader.Read(make([]byte, 100)); err != firstErr {
		t.Fatal("poisoned reader reused")
	}
	if _, err := reader.Write([]byte("second")); err != firstErr || readTransport.written.Len() != 0 {
		t.Fatal("write after failed integrity/ordering")
	}
	if err := reader.Close(); err != nil {
		t.Fatal(err)
	}
}

func TestKerberosHonorsAuthenticatedReceiveSequence(t *testing.T) {
	keyType, key := newTestSubkey(t)
	token, err := peerSealWrite(types.EncryptionKey{KeyType: keyType, KeyValue: key}, []byte("owned-response"), 407)
	if err != nil {
		t.Fatal(err)
	}
	transport := &kerberosCaptureConn{fakeReadConn: fakeReadConn{r: bytes.NewReader(frameWith4ByteLen(token))}}
	connection, err := newKrbSASLConnWithContext(transport, ldapgss.SASLSecurityContext{
		KeyType: keyType, KeyValue: key, AcceptorSubkey: true, SendSequence: 981, ReceiveSequence: 407, PeerMaxTokenSize: 65535, LocalMaxTokenSize: 65535,
	}, SASLSecuritySeal)
	if err != nil {
		t.Fatal(err)
	}
	if n, err := connection.Read(make([]byte, 100)); err != nil || n != len("owned-response") || connection.rSeqNum != 408 {
		t.Fatalf("valid initial GSS sequence: n=%d err=%v", n, err)
	}
	if err := connection.Close(); err != nil {
		t.Fatal(err)
	}
}
