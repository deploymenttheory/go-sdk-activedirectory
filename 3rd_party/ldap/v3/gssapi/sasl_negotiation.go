package gssapi

import (
	"fmt"

	"github.com/deploymenttheory/go-sdk-activedirectory/3rd_party/gokrb5/v8/crypto"
	"github.com/deploymenttheory/go-sdk-activedirectory/3rd_party/gokrb5/v8/gssapi"
	"github.com/deploymenttheory/go-sdk-activedirectory/3rd_party/gokrb5/v8/iana/keyusage"
)

// NegotiateSaslAuth performs the last step of the SASL handshake.
// See RFC 4752 section 3.1.
func (client *Client) NegotiateSaslAuth(input []byte, authzid string) ([]byte, error) {
	if !client.mutualAuthenticated || client.saslNegotiated || !validSASLAuthzID(authzid) {
		return nil, fmt.Errorf("ldap: SASL negotiation requires a fresh mutually authenticated context")
	}
	token := &gssapi.WrapToken{}
	err := unmarshalSASLHandshakeToken(token, input)
	if err != nil {
		return nil, err
	}

	if token.Flags&0b11 != 1 || (token.Flags&0b100 != 0) != (len(client.Subkey.KeyValue) != 0) || token.SndSeqNum != client.receiveSequence {
		return nil, fmt.Errorf("ldap: invalid SASL security-layer token flags or sequence")
	}

	key := client.contextKey()

	_, err = token.Verify(key, keyusage.GSSAPI_ACCEPTOR_SEAL)
	if err != nil {
		return nil, err
	}

	pl := token.Payload
	if len(pl) != 4 {
		return nil, fmt.Errorf("server send bad final token for SASL GSSAPI Handshake")
	}

	// Set the SASL security layer byte and max buffer size.
	// When SASLSecurity is 0 (default), we request no security layer and
	// send a zero buffer size. Otherwise, we advertise the requested
	// security layer and a 65535-byte max buffer.
	b, peerMax, err := selectSASLSecurityLayer(pl, client.SASLSecurity)
	if err != nil {
		return nil, err
	}
	payload := append(b[:], []byte(authzid)...)

	encType, err := crypto.GetEtype(key.KeyType)
	if err != nil {
		return nil, err
	}

	var tokenFlags byte
	if len(client.Subkey.KeyValue) != 0 {
		tokenFlags = 0b100
	}
	checksumLength := encType.GetHMACBitLength() / 8
	if checksumLength <= 0 || checksumLength > 65535 {
		return nil, fmt.Errorf("ldap: invalid GSS checksum size")
	}
	token = &gssapi.WrapToken{
		Flags:     tokenFlags,
		EC:        uint16(checksumLength),
		RRC:       0,
		SndSeqNum: client.sendSequence,
		Payload:   payload,
	}

	if err := token.SetCheckSum(key, keyusage.GSSAPI_INITIATOR_SEAL); err != nil {
		return nil, err
	}

	output, err := token.Marshal()
	if err != nil {
		return nil, err
	}

	client.sendSequence++
	client.receiveSequence++
	client.peerMaxTokenSize = peerMax
	client.localMaxTokenSize = uint32(b[1])<<16 | uint32(b[2])<<8 | uint32(b[3])
	client.saslNegotiated = true
	return output, nil
}
