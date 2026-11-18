package gssapi

import (
	"bytes"
	"crypto/rand"
	"crypto/x509"
	"encoding/binary"
	"encoding/hex"
	"errors"
	"fmt"
	"time"

	"github.com/deploymenttheory/go-sdk-activedirectory/3rd_party/gokrb5/v8/client"
	"github.com/deploymenttheory/go-sdk-activedirectory/3rd_party/gokrb5/v8/config"
	"github.com/deploymenttheory/go-sdk-activedirectory/3rd_party/gokrb5/v8/credentials"
	"github.com/deploymenttheory/go-sdk-activedirectory/3rd_party/gokrb5/v8/crypto"
	"github.com/deploymenttheory/go-sdk-activedirectory/3rd_party/gokrb5/v8/gssapi"
	"github.com/deploymenttheory/go-sdk-activedirectory/3rd_party/gokrb5/v8/iana/chksumtype"
	"github.com/deploymenttheory/go-sdk-activedirectory/3rd_party/gokrb5/v8/iana/flags"
	"github.com/deploymenttheory/go-sdk-activedirectory/3rd_party/gokrb5/v8/iana/keyusage"
	"github.com/deploymenttheory/go-sdk-activedirectory/3rd_party/gokrb5/v8/keytab"
	"github.com/deploymenttheory/go-sdk-activedirectory/3rd_party/gokrb5/v8/messages"
	"github.com/deploymenttheory/go-sdk-activedirectory/3rd_party/gokrb5/v8/types"
)

var le = binary.LittleEndian

// Client implements ldap.GSSAPIClient interface.
type Client struct {
	*client.Client

	ekey                   types.EncryptionKey
	Subkey                 types.EncryptionKey
	initiatorSubkey        types.EncryptionKey
	authenticatorTime      time.Time
	authenticatorUsec      int
	sendSequence           uint64
	receiveSequence        uint64
	mutualAuthenticated    bool
	saslNegotiated         bool
	negotiatedSASLSecurity int
	contextExpiresAt       time.Time
	channelBindingSent     bool
	peerMaxTokenSize       uint32
	localMaxTokenSize      uint32

	// SASLSecurity controls the SASL security layer negotiated during the
	// GSSAPI bind. Values match ldap.SASLSecurityMode (RFC 4752 bitmask):
	//   0 = none, 2 = integrity (sign), 4 = confidentiality (seal).
	SASLSecurity int

	// channelBindingHash is the MD5 hash of the gss_channel_bindings_struct.
	// When set (non-zero), it is included in the authenticator checksum
	// per RFC 1964 §1.1.1, enabling TLS channel binding.
	channelBindingHash [16]byte
}

func NewClient(client *client.Client) (c *Client, err error) {
	return &Client{Client: client}, nil
}

// NewClientWithKeytab creates a new client from a keytab credential.
// Set the realm to empty string to use the default realm from config.
func NewClientWithKeytab(username, realm, keytabPath, krb5confPath string, settings ...func(*client.Settings)) (*Client, error) {
	krb5conf, err := config.Load(krb5confPath)
	if err != nil {
		return nil, err
	}

	keytab, err := keytab.Load(keytabPath)
	if err != nil {
		return nil, err
	}
	return NewClientWithKeytabExt(username, realm, keytab, krb5conf, settings...)
}

// NewClientWithKeytab creates a new client from a keytab credential.
// Set the realm to empty string to use the default realm from config.
func NewClientWithKeytabExt(username, realm string, keytab *keytab.Keytab, krb5conf *config.Config, settings ...func(*client.Settings)) (*Client, error) {
	client := client.NewWithKeytab(username, realm, keytab, krb5conf, settings...)

	return &Client{
		Client: client,
	}, nil
}

// NewClientWithPassword creates a new client from a password credential.
// Set the realm to empty string to use the default realm from config.
func NewClientWithPassword(username, realm, password string, krb5confPath string, settings ...func(*client.Settings)) (*Client, error) {
	krb5conf, err := config.Load(krb5confPath)
	if err != nil {
		return nil, err
	}
	return NewClientWithPasswordExt(username, realm, password, krb5conf, settings...)
}

// NewClientWithPassword creates a new client from a password credential.
// Set the realm to empty string to use the default realm from config.
func NewClientWithPasswordExt(username, realm, password string, krb5conf *config.Config, settings ...func(*client.Settings)) (*Client, error) {
	client := client.NewWithPassword(username, realm, password, krb5conf, settings...)

	return &Client{
		Client: client,
	}, nil
}

// NewClientFromCCache creates a new client from a populated client cache.
func NewClientFromCCache(ccachePath, krb5confPath string, settings ...func(*client.Settings)) (*Client, error) {
	krb5conf, err := config.Load(krb5confPath)
	if err != nil {
		return nil, err
	}

	ccache, err := credentials.LoadCCache(ccachePath)
	if err != nil {
		return nil, err
	}
	return NewClientFromCCacheExt(ccache, krb5conf, settings...)
}

// NewClientFromCCache creates a new client from a populated client cache.
func NewClientFromCCacheExt(ccache *credentials.CCache, krb5conf *config.Config, settings ...func(*client.Settings)) (*Client, error) {
	client, err := client.NewFromCCache(ccache, krb5conf, settings...)
	if err != nil {
		return nil, err
	}

	return &Client{
		Client: client,
	}, nil
}

// SetSASLSecurity sets the SASL security layer to negotiate during the
// GSSAPI bind. Values match ldap.SASLSecurityMode (RFC 4752 bitmask):
// 0 = none, 2 = integrity, 4 = confidentiality.
func (c *Client) SetSASLSecurity(mode int) {
	c.SASLSecurity = mode
}

// SetChannelBinding computes and sets the channel binding hash from the
// TLS server certificate for RFC 5929 "tls-server-end-point" binding.
func (c *Client) SetChannelBinding(cert *x509.Certificate) error {
	certHash := CertificateHash(cert)
	if certHash == nil {
		return fmt.Errorf("unsupported certificate signature algorithm for channel binding")
	}
	hash, err := ComputeChannelBindingHash(certHash)
	if err != nil {
		return err
	}
	c.channelBindingHash = hash
	return nil
}

// NewClientWithKeytabAndChannelBinding creates a Kerberos client with
// TLS channel binding from a keytab. cert is the TLS server certificate.
func NewClientWithKeytabAndChannelBinding(username, realm, keytabPath, krb5confPath string, cert *x509.Certificate, settings ...func(*client.Settings)) (*Client, error) {
	c, err := NewClientWithKeytab(username, realm, keytabPath, krb5confPath, settings...)
	if err != nil {
		return nil, err
	}
	if err := c.SetChannelBinding(cert); err != nil {
		return nil, err
	}
	return c, nil
}

// NewClientWithPasswordAndChannelBinding creates a Kerberos client with
// TLS channel binding from a password. cert is the TLS server certificate.
func NewClientWithPasswordAndChannelBinding(username, realm, password, krb5confPath string, cert *x509.Certificate, settings ...func(*client.Settings)) (*Client, error) {
	c, err := NewClientWithPassword(username, realm, password, krb5confPath, settings...)
	if err != nil {
		return nil, err
	}
	if err := c.SetChannelBinding(cert); err != nil {
		return nil, err
	}
	return c, nil
}

// NewClientFromCCacheAndChannelBinding creates a Kerberos client with
// TLS channel binding from a credential cache. cert is the TLS server certificate.
func NewClientFromCCacheAndChannelBinding(ccachePath, krb5confPath string, cert *x509.Certificate, settings ...func(*client.Settings)) (*Client, error) {
	c, err := NewClientFromCCache(ccachePath, krb5confPath, settings...)
	if err != nil {
		return nil, err
	}
	if err := c.SetChannelBinding(cert); err != nil {
		return nil, err
	}
	return c, nil
}

// Close deletes any established secure context and closes the client.
func (client *Client) Close() error {
	_ = client.DeleteSecContext()
	client.Destroy()
	return nil
}

// DeleteSecContext destroys any established secure context.
func (client *Client) DeleteSecContext() error {
	clear(client.ekey.KeyValue)
	clear(client.Subkey.KeyValue)
	clear(client.initiatorSubkey.KeyValue)
	client.ekey = types.EncryptionKey{}
	client.Subkey = types.EncryptionKey{}
	client.initiatorSubkey = types.EncryptionKey{}
	client.authenticatorTime = time.Time{}
	client.authenticatorUsec = 0
	client.sendSequence, client.receiveSequence = 0, 0
	client.mutualAuthenticated, client.saslNegotiated = false, false
	client.negotiatedSASLSecurity = 0
	client.contextExpiresAt = time.Time{}
	client.channelBindingSent = false
	client.peerMaxTokenSize, client.localMaxTokenSize = 0, 0
	return nil
}

// SASLKey returns the Kerberos session subkey parameters for SASL wrapping.
// This satisfies the saslKeyProvider interface used by the GSSAPI bind flow
// to install Kerberos SASL wrapping on the connection.
func (client *Client) SASLKey() (keyType int32, keyValue []byte) {
	key := client.contextKey()
	return key.KeyType, append([]byte(nil), key.KeyValue...)
}

// InitSecContext initiates the establishment of a security context for
// GSS-API between the client and server.
// See RFC 4752 section 3.1.
func (client *Client) InitSecContext(target string, input []byte) ([]byte, bool, error) {
	return client.InitSecContextWithOptions(target, input, []int{})
}

// newAuthenticatorChecksum builds an RFC 1964 Section 1.1.1 authenticator checksum.
// channelBinding is the optional MD5 hash of the gss_channel_bindings_struct;
// when non-nil it is placed in bytes 4-19 (the Bnd field).
func newAuthenticatorChecksum(flags []uint32, channelBinding *[16]byte) []byte {
	a := make([]byte, 24)
	le.PutUint32(a[:4], 16) // Bnd length
	if channelBinding != nil {
		copy(a[4:20], channelBinding[:])
	}
	for _, flag := range flags {
		le.PutUint32(a[20:24], le.Uint32(a[20:24])|flag)
	}
	return a
}

// InitSecContextWithOptions initiates the establishment of a security context for
// GSS-API between the client and server.
// See RFC 4752 section 3.1.
func (client *Client) InitSecContextWithOptions(target string, input []byte, APOptions []int) ([]byte, bool, error) {
	gssapiFlags := []uint32{gssapi.ContextFlagInteg, gssapi.ContextFlagConf, gssapi.ContextFlagMutual, gssapi.ContextFlagReplay, gssapi.ContextFlagSequence}

	switch input {
	case nil:
		_ = client.DeleteSecContext()
		selected, err := client.GetServiceTicketWithValidity(target)
		if err != nil {
			return nil, false, err
		}
		tkt, ekey := selected.Ticket, selected.Key
		defer clear(ekey.KeyValue)
		client.contextExpiresAt = selected.EndTime
		client.ekey = types.EncryptionKey{KeyType: ekey.KeyType, KeyValue: append([]byte(nil), ekey.KeyValue...)}

		authenticator, err := types.NewAuthenticator(client.Credentials.Domain(), client.Credentials.CName())
		if err != nil {
			return nil, false, err
		}
		var cbPtr *[16]byte
		if client.channelBindingHash != [16]byte{} {
			cbPtr = &client.channelBindingHash
		}
		authenticator.Cksum = types.Checksum{
			CksumType: chksumtype.GSSAPI,
			Checksum:  newAuthenticatorChecksum(gssapiFlags, cbPtr),
		}

		etype, err := crypto.GetEtype(ekey.KeyType)
		if err != nil {
			return nil, false, err
		}
		subkey := make([]byte, etype.GetKeyByteSize())
		if _, err = rand.Read(subkey); err != nil {
			return nil, false, err
		}
		authenticator.SubKey = types.EncryptionKey{
			KeyType:  ekey.KeyType,
			KeyValue: subkey,
		}
		if err := client.retainAuthenticator(authenticator); err != nil {
			return nil, false, err
		}

		apReq, err := messages.NewAPReq(tkt, ekey, authenticator)
		if err != nil {
			return nil, false, err
		}

		for _, opt := range APOptions {
			types.SetFlag(&apReq.APOptions, opt)
		}
		types.SetFlag(&apReq.APOptions, flags.APOptionMutualRequired)

		token := krb5Token{
			Oid:     gssapi.OIDKRB5.OID(),
			TokenId: tokenIdKrb5APReq,
			APReq:   apReq,
		}

		output, err := token.Marshal()
		if err != nil {
			return nil, false, err
		}
		client.channelBindingSent = cbPtr != nil

		return output, true, nil

	default:
		var token krb5Token

		err := token.Unmarshal(input)
		if err != nil {
			return nil, false, err
		}

		var completed bool

		if token.TokenId == tokenIdKrb5APRep {
			completed = true

			encpart, err := crypto.DecryptEncPart(token.APRep.EncPart, client.ekey, keyusage.AP_REP_ENCPART)
			if err != nil {
				return nil, false, err
			}

			part := &messages.EncAPRepPart{}

			if err = part.Unmarshal(encpart); err != nil {
				return nil, false, err
			}
			if err := client.acceptAPRepPart(*part); err != nil {
				return nil, false, err
			}
		}

		if token.TokenId == tokenIdKrb5Error {
			return nil, true, token.KRBError
		}

		return make([]byte, 0), !completed, nil
	}
}

func getGssWrapTokenId() *[2]byte {
	return &[2]byte{0x05, 0x04}
}

func UnmarshalWrapToken(wt *gssapi.WrapToken, b []byte, expectFromAcceptor bool) error {
	// Check if we can read a whole header
	if len(b) < 16 {
		return errors.New("bytes shorter than header length")
	}
	// Is the Token ID correct?
	if !bytes.Equal(getGssWrapTokenId()[:], b[0:2]) {
		return fmt.Errorf("wrong Token ID. Expected %s, was %s",
			hex.EncodeToString(getGssWrapTokenId()[:]),
			hex.EncodeToString(b[0:2]))
	}
	// Check the acceptor flag
	flags := b[2]
	isFromAcceptor := flags&0x01 == 1
	if isFromAcceptor && !expectFromAcceptor {
		return errors.New("unexpected acceptor flag is set: not expecting a token from the acceptor")
	}
	if !isFromAcceptor && expectFromAcceptor {
		return errors.New("expected acceptor flag is not set: expecting a token from the acceptor, not the initiator")
	}
	// Check the filler byte
	if b[3] != gssapi.FillerByte {
		return fmt.Errorf("unexpected filler byte: expecting 0xFF, was %s ", hex.EncodeToString(b[3:4]))
	}
	checksumL := binary.BigEndian.Uint16(b[4:6])
	// Sanity check on the checksum length
	if int(checksumL) > len(b)-gssapi.HdrLen {
		return fmt.Errorf("inconsistent checksum length: %d bytes to parse, checksum length is %d", len(b), checksumL)
	}

	// Compute the offset in int. checksumL is a uint16 read from the wire, so
	// 16 + checksumL overflows the uint16 range once checksumL exceeds 65519,
	// wrapping to a small value and turning the slices below into out-of-range
	// accesses that panic the bind goroutine.
	payloadStart := gssapi.HdrLen + int(checksumL)

	wt.Flags = flags
	wt.EC = checksumL
	wt.RRC = binary.BigEndian.Uint16(b[6:8])
	wt.SndSeqNum = binary.BigEndian.Uint64(b[8:16])
	wt.CheckSum = b[16:payloadStart]
	wt.Payload = b[payloadStart:]

	return nil
}
