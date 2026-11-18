package gssapi

import (
	"encoding/binary"
	"fmt"
	"math"
	"time"
	"unicode/utf8"

	"github.com/deploymenttheory/go-sdk-activedirectory/3rd_party/gokrb5/v8/crypto"
	krbgss "github.com/deploymenttheory/go-sdk-activedirectory/3rd_party/gokrb5/v8/gssapi"
	"github.com/deploymenttheory/go-sdk-activedirectory/3rd_party/gokrb5/v8/messages"
	"github.com/deploymenttheory/go-sdk-activedirectory/3rd_party/gokrb5/v8/types"
)

// SASLSecurityContext owns the established GSS key and sequence state after the
// security-layer exchange. Callers must clear KeyValue when the connection closes.
// Sequence values come from the authenticated AP exchange, never a data token.
type SASLSecurityContext struct {
	KeyType                             int32
	KeyValue                            []byte
	AcceptorSubkey                      bool
	SendSequence, ReceiveSequence       uint64
	PeerMaxTokenSize, LocalMaxTokenSize uint32
	// SASLSecurity is the authenticated selected layer, never the mutable request.
	SASLSecurity int
}

func (client *Client) retainAuthenticator(authenticator types.Authenticator) error {
	if authenticator.SeqNumber < 0 || authenticator.SeqNumber > math.MaxUint32 {
		return fmt.Errorf("ldap: invalid initiating GSS sequence")
	}
	client.initiatorSubkey = types.EncryptionKey{KeyType: authenticator.SubKey.KeyType, KeyValue: append([]byte(nil), authenticator.SubKey.KeyValue...)}
	client.authenticatorTime = authenticator.CTime.Truncate(time.Second)
	client.authenticatorUsec = authenticator.Cusec
	client.sendSequence = uint64(authenticator.SeqNumber)
	return nil
}

func (client *Client) contextKey() types.EncryptionKey {
	if len(client.Subkey.KeyValue) != 0 {
		return client.Subkey
	}
	if len(client.initiatorSubkey.KeyValue) != 0 {
		return client.initiatorSubkey
	}
	return client.ekey
}

// SASLContext exports a copy of the authenticated state required for per-message
// protection. An incomplete handshake never yields a usable context.
func (client *Client) SASLContext() (SASLSecurityContext, error) {
	if !client.mutualAuthenticated || !client.saslNegotiated || client.negotiatedSASLSecurity == 0 {
		return SASLSecurityContext{}, fmt.Errorf("ldap: no negotiated Kerberos SASL security context")
	}
	key := client.contextKey()
	return SASLSecurityContext{
		KeyType:           key.KeyType,
		KeyValue:          append([]byte(nil), key.KeyValue...),
		AcceptorSubkey:    len(client.Subkey.KeyValue) != 0,
		SendSequence:      client.sendSequence,
		ReceiveSequence:   client.receiveSequence,
		PeerMaxTokenSize:  client.peerMaxTokenSize,
		LocalMaxTokenSize: client.localMaxTokenSize,
		SASLSecurity:      client.negotiatedSASLSecurity,
	}, nil
}

func (client *Client) acceptAPRepPart(part messages.EncAPRepPart) error {
	// RFC4120 3.2.5 binds the reply to the initiating authenticator timestamp.
	if client.mutualAuthenticated || client.authenticatorTime.IsZero() || !part.CTime.Equal(client.authenticatorTime) || part.Cusec != client.authenticatorUsec ||
		part.SequenceNumber < 0 || part.SequenceNumber > math.MaxUint32 {
		return fmt.Errorf("ldap: AP-REP does not match the initiating authenticator")
	}
	if len(part.Subkey.KeyValue) != 0 {
		// We do not advertise RFC4537 enctype negotiation. Require the
		// authenticated initiator profile instead of accepting an unsolicited
		// algorithm change, and validate its exact AES key size before retention.
		key := client.contextKey()
		if part.Subkey.KeyType < 17 || part.Subkey.KeyType > 20 || part.Subkey.KeyType != key.KeyType {
			return fmt.Errorf("ldap: AP-REP selected an unnegotiated encryption profile")
		}
		encType, err := crypto.GetEtype(part.Subkey.KeyType)
		if err != nil || len(part.Subkey.KeyValue) != encType.GetKeyByteSize() {
			return fmt.Errorf("ldap: AP-REP contains an invalid AES subkey")
		}
		client.Subkey = types.EncryptionKey{KeyType: part.Subkey.KeyType, KeyValue: append([]byte(nil), part.Subkey.KeyValue...)}
	} else if part.Subkey.KeyType != 0 {
		return fmt.Errorf("ldap: AP-REP contains an empty typed subkey")
	}
	client.receiveSequence = uint64(part.SequenceNumber)
	client.mutualAuthenticated = true
	return nil
}

func selectSASLSecurityLayer(offer []byte, mode int) ([4]byte, uint32, error) {
	var selected [4]byte
	if len(offer) != 4 || (mode != 0 && mode != 2 && mode != 4) {
		return selected, 0, fmt.Errorf("ldap: invalid SASL security layer")
	}
	layer := byte(mode)
	if layer == 0 {
		layer = 1 // RFC4752: no security layer is bit1, not zero.
	}
	peerMax := uint32(offer[1])<<16 | uint32(offer[2])<<8 | uint32(offer[3])
	if offer[0]&layer == 0 || (offer[0]&6 == 0 && peerMax != 0) || (mode != 0 && peerMax == 0) {
		return selected, 0, fmt.Errorf("ldap: server offer cannot satisfy the requested SASL security layer")
	}
	selected[0] = layer
	if mode != 0 {
		selected[2], selected[3] = 0xff, 0xff // Advertise an enforced 65535-byte token limit.
	}
	return selected, peerMax, nil
}

// unmarshalSASLHandshakeToken handles every RFC4121 rotation, including zero.
func unmarshalSASLHandshakeToken(token *krbgss.WrapToken, wire []byte) error {
	if len(wire) < krbgss.HdrLen {
		return fmt.Errorf("ldap: SASL handshake token is too short")
	}
	normalized := append([]byte(nil), wire...)
	rotation := int(binary.BigEndian.Uint16(normalized[6:8]))
	body := normalized[krbgss.HdrLen:]
	if len(body) != 0 && rotation%len(body) != 0 {
		rotation %= len(body)
		rotated := append([]byte(nil), body...)
		copy(body, rotated[rotation:])
		copy(body[len(body)-rotation:], rotated[:rotation])
	}
	normalized[6], normalized[7] = 0, 0
	return token.Unmarshal(normalized, true)
}

func validSASLAuthzID(authzid string) bool { return utf8.ValidString(authzid) }
