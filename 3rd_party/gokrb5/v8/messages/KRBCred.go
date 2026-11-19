package messages

import (
	"fmt"
	"time"

	"github.com/jcmturner/gofork/encoding/asn1"

	"github.com/deploymenttheory/go-sdk-activedirectory/3rd_party/gokrb5/v8/asn1tools"
	"github.com/deploymenttheory/go-sdk-activedirectory/3rd_party/gokrb5/v8/crypto"
	"github.com/deploymenttheory/go-sdk-activedirectory/3rd_party/gokrb5/v8/iana/asnAppTag"
	"github.com/deploymenttheory/go-sdk-activedirectory/3rd_party/gokrb5/v8/iana/keyusage"
	"github.com/deploymenttheory/go-sdk-activedirectory/3rd_party/gokrb5/v8/iana/msgtype"
	"github.com/deploymenttheory/go-sdk-activedirectory/3rd_party/gokrb5/v8/krberror"
	"github.com/deploymenttheory/go-sdk-activedirectory/3rd_party/gokrb5/v8/types"
)

type marshalKRBCred struct {
	PVNO    int                 `asn1:"explicit,tag:0"`
	MsgType int                 `asn1:"explicit,tag:1"`
	Tickets asn1.RawValue       `asn1:"explicit,tag:2"`
	EncPart types.EncryptedData `asn1:"explicit,tag:3"`
}

// KRBCred implements RFC 4120 KRB_CRED: https://tools.ietf.org/html/rfc4120#section-5.8.1.
type KRBCred struct {
	PVNO             int
	MsgType          int
	Tickets          []Ticket
	EncPart          types.EncryptedData
	DecryptedEncPart EncKrbCredPart
}

// EncKrbCredPart is the encrypted part of KRB_CRED.
type EncKrbCredPart struct {
	TicketInfo []KrbCredInfo     `asn1:"explicit,tag:0"`
	Nouce      int               `asn1:"optional,explicit,tag:1"`
	Timestamp  time.Time         `asn1:"generalized,optional,explicit,tag:2"`
	Usec       int               `asn1:"optional,explicit,tag:3"`
	SAddress   types.HostAddress `asn1:"optional,explicit,tag:4"`
	RAddress   types.HostAddress `asn1:"optional,explicit,tag:5"`
}

// KrbCredInfo is the KRB_CRED_INFO part of KRB_CRED.
type KrbCredInfo struct {
	Key       types.EncryptionKey `asn1:"explicit,tag:0"`
	PRealm    string              `asn1:"generalstring,optional,explicit,tag:1"`
	PName     types.PrincipalName `asn1:"optional,explicit,tag:2"`
	Flags     asn1.BitString      `asn1:"optional,explicit,tag:3"`
	AuthTime  time.Time           `asn1:"generalized,optional,explicit,tag:4"`
	StartTime time.Time           `asn1:"generalized,optional,explicit,tag:5"`
	EndTime   time.Time           `asn1:"generalized,optional,explicit,tag:6"`
	RenewTill time.Time           `asn1:"generalized,optional,explicit,tag:7"`
	SRealm    string              `asn1:"optional,explicit,generalstring,tag:8"`
	SName     types.PrincipalName `asn1:"optional,explicit,tag:9"`
	CAddr     types.HostAddresses `asn1:"optional,explicit,tag:10"`
}

// Unmarshal bytes b into the KRBCred struct.
func (k *KRBCred) Unmarshal(b []byte) error {
	var m marshalKRBCred
	rest, err := asn1.UnmarshalWithParams(b, &m, fmt.Sprintf("application,explicit,tag:%v", asnAppTag.KRBCred))
	if err != nil {
		return processUnmarshalReplyError(b, err)
	}
	if len(rest) != 0 || m.PVNO != 5 {
		return fmt.Errorf("invalid or trailing KRB_CRED protocol envelope")
	}
	expectedMsgType := msgtype.KRB_CRED
	if m.MsgType != expectedMsgType {
		return krberror.NewErrorf(krberror.KRBMsgError, "message ID does not indicate a KRB_CRED. Expected: %v; Actual: %v", expectedMsgType, m.MsgType)
	}
	k.PVNO = m.PVNO
	k.MsgType = m.MsgType
	k.EncPart = m.EncPart
	if len(m.Tickets.Bytes) > 0 {
		k.Tickets, err = unmarshalTicketsSequence(m.Tickets)
		if err != nil {
			return krberror.Errorf(err, krberror.EncodingError, "error unmarshaling tickets within KRB_CRED")
		}
	}
	return nil
}

// DecryptEncPart decrypts the encrypted part of a KRB_CRED.
func (k *KRBCred) DecryptEncPart(key types.EncryptionKey) error {
	b, err := crypto.DecryptEncPart(k.EncPart, key, keyusage.KRB_CRED_ENCPART)
	if err != nil {
		return krberror.Errorf(err, krberror.DecryptingError, "error decrypting KRB_CRED EncPart")
	}
	defer clear(b)
	var denc EncKrbCredPart
	err = denc.Unmarshal(b)
	if err != nil {
		return krberror.Errorf(err, krberror.EncodingError, "error unmarshaling encrypted part of KRB_CRED")
	}
	k.DecryptedEncPart = denc
	return nil
}

// Unmarshal bytes b into the encrypted part of KRB_CRED.
func (k *EncKrbCredPart) Unmarshal(b []byte) error {
	rest, err := asn1.UnmarshalWithParams(b, k, fmt.Sprintf("application,explicit,tag:%v", asnAppTag.EncKrbCredPart))
	if err != nil {
		return krberror.Errorf(err, krberror.EncodingError, "error unmarshaling EncKrbCredPart")
	}
	if len(rest) != 0 {
		return fmt.Errorf("trailing EncKrbCredPart data")
	}
	// ASN.1 byte fields can alias decrypted input. Own every retained byte slice
	// before DecryptEncPart clears that temporary plaintext.
	for i := range k.TicketInfo {
		info := &k.TicketInfo[i]
		info.Key.KeyValue = append([]byte(nil), info.Key.KeyValue...)
		info.Flags.Bytes = append([]byte(nil), info.Flags.Bytes...)
		for j := range info.CAddr {
			info.CAddr[j].Address = append([]byte(nil), info.CAddr[j].Address...)
		}
	}
	k.SAddress.Address = append([]byte(nil), k.SAddress.Address...)
	k.RAddress.Address = append([]byte(nil), k.RAddress.Address...)
	return nil
}

// Marshal encodes the complete RFC4120 KRB_CRED envelope. It excludes the
// plaintext DecryptedEncPart; EncryptEncPart must establish the encrypted form.
func (k *KRBCred) Marshal() ([]byte, error) {
	if k.PVNO != 5 || k.MsgType != msgtype.KRB_CRED || len(k.Tickets) == 0 || k.EncPart.EType == 0 || len(k.EncPart.Cipher) == 0 {
		return nil, fmt.Errorf("invalid KRB_CRED protocol envelope")
	}
	tickets, err := MarshalTicketSequence(k.Tickets)
	if err != nil {
		return nil, err
	}
	encoded, err := asn1.Marshal(marshalKRBCred{PVNO: k.PVNO, MsgType: k.MsgType, Tickets: tickets, EncPart: k.EncPart})
	if err != nil {
		return nil, err
	}
	return asn1tools.AddASNAppTag(encoded, asnAppTag.KRBCred), nil
}

// EncryptEncPart encrypts owned encoded plaintext with key usage 14. GSSAPI
// forwarding must pass the service-ticket session key, never the initiator
// subkey (RFC4121 section 4.1.1). The caller retains ownership of the input keys.
func (k *KRBCred) EncryptEncPart(key types.EncryptionKey) error {
	if k.PVNO != 5 || k.MsgType != msgtype.KRB_CRED || len(k.Tickets) == 0 || len(k.Tickets) != len(k.DecryptedEncPart.TicketInfo) {
		return fmt.Errorf("invalid KRB_CRED ticket and credential-info mapping")
	}
	encoded, err := asn1.Marshal(k.DecryptedEncPart)
	if err != nil {
		return err
	}
	defer clear(encoded)
	plaintext := asn1tools.AddASNAppTag(encoded, asnAppTag.EncKrbCredPart)
	defer clear(plaintext)
	k.EncPart, err = crypto.GetEncryptedData(plaintext, key, keyusage.KRB_CRED_ENCPART, 0)
	return err
}
