package rpcdce

import (
	"context"
	"errors"
	"fmt"
	"math"
	"time"

	"github.com/jcmturner/gofork/encoding/asn1"

	"github.com/deploymenttheory/go-sdk-activedirectory/3rd_party/gokrb5/v8/asn1tools"
	krbcrypto "github.com/deploymenttheory/go-sdk-activedirectory/3rd_party/gokrb5/v8/crypto"
	"github.com/deploymenttheory/go-sdk-activedirectory/3rd_party/gokrb5/v8/iana/asnAppTag"
	"github.com/deploymenttheory/go-sdk-activedirectory/3rd_party/gokrb5/v8/iana/keyusage"
	"github.com/deploymenttheory/go-sdk-activedirectory/3rd_party/gokrb5/v8/messages"
	"github.com/deploymenttheory/go-sdk-activedirectory/3rd_party/gokrb5/v8/types"
	record "github.com/deploymenttheory/go-sdk-activedirectory/3rd_party/msrpc/ssp/krb5/crypto"
)

type RecordCipher interface {
	WrapEx(context.Context, uint64, [][]byte, [][]byte) ([]byte, error)
	UnwrapEx(context.Context, uint64, [][]byte, [][]byte, []byte) (bool, error)
	Size(context.Context, bool) int
	Destroy()
}

// RecordContext owns copied directional record state after an authenticated
// AP-REP. RPC acceptance/protection is still unconfirmed until a valid protected
// application response arrives. The caller must destroy both keys on retirement.
type RecordContext struct {
	Realm, ServicePrincipal       string
	Send, Receive                 RecordCipher
	SendSequence, ReceiveSequence uint64
	ExpiresAt                     time.Time
	EncryptionType                int32
	AcceptorSubkey                bool
}

func (r *RecordContext) Destroy() {
	if r != nil {
		if r.Send != nil {
			r.Send.Destroy()
		}
		if r.Receive != nil {
			r.Receive.Destroy()
		}
	}
}

func marshalAPReply(key types.EncryptionKey, part messages.EncAPRepPart) ([]byte, error) {
	plain, err := asn1.Marshal(part)
	if err != nil {
		return nil, fmt.Errorf("encode final DCE AP-REP part: %w", err)
	}
	plain = asn1tools.AddASNAppTag(plain, asnAppTag.EncAPRepPart)
	defer clear(plain)
	encrypted, err := krbcrypto.GetEncryptedData(plain, key, keyusage.AP_REP_ENCPART, 0)
	if err != nil {
		return nil, err
	}
	wire, err := asn1.Marshal(messages.APRep{PVNO: 5, MsgType: 15, EncPart: encrypted})
	if err != nil {
		return nil, fmt.Errorf("encode final DCE AP-REP: %w", err)
	}
	return asn1tools.AddASNAppTag(wire, asnAppTag.APREP), nil
}

// Accept authenticates the first AP-REP and emits the DCE third-leg AP-REP.
// Its returned records remain separate from final RPC/application acceptance.
func (c *Client) Accept(ctx context.Context, wire []byte) (thirdLeg []byte, records *RecordContext, err error) {
	c.mu.Lock()
	defer c.mu.Unlock()
	if err = c.check(ctx, 1); err != nil {
		c.destroy()
		return nil, nil, err
	}
	defer func() {
		if err != nil {
			c.destroy()
		}
	}()
	if len(wire) == 0 || len(wire) > 65535 {
		return nil, nil, ErrAuthentication
	}
	var rep messages.APRep
	if err = rep.Unmarshal(wire); err != nil {
		return nil, nil, errors.Join(ErrAuthentication, err)
	}
	if rep.EncPart.EType != c.key.KeyType {
		return nil, nil, ErrAuthentication
	}
	plain, err := krbcrypto.DecryptEncPart(rep.EncPart, c.key, keyusage.AP_REP_ENCPART)
	if err != nil {
		return nil, nil, errors.Join(ErrAuthentication, err)
	}
	defer clear(plain)
	var part messages.EncAPRepPart
	if err = part.Unmarshal(plain); err != nil {
		return nil, nil, errors.Join(ErrAuthentication, err)
	}
	defer clear(part.Subkey.KeyValue)
	if !part.CTime.Equal(c.authTime) || part.Cusec != c.authUsec || part.SequenceNumber < 0 || part.SequenceNumber > math.MaxUint32 {
		return nil, nil, ErrAuthentication
	}
	key := c.initiatorKey
	acceptorSubkey := len(part.Subkey.KeyValue) != 0
	if acceptorSubkey {
		if part.Subkey.KeyType != c.key.KeyType || len(part.Subkey.KeyValue) != len(c.key.KeyValue) {
			return nil, nil, ErrAuthentication
		}
		key = part.Subkey
	} else if part.Subkey.KeyType != 0 {
		return nil, nil, ErrAuthentication
	}
	// DCE's final leg echoes the acceptor sequence, with no new subkey. The
	// acceptor verifies sequence/key possession; it does not recheck timestamps.
	now := time.Now().UTC()
	thirdLeg, err = marshalAPReply(c.key, messages.EncAPRepPart{CTime: now.Truncate(time.Second), Cusec: now.Nanosecond() / 1000, SequenceNumber: part.SequenceNumber})
	if err != nil {
		return nil, nil, err
	}
	et, err := krbcrypto.GetEtype(key.KeyType)
	if err != nil {
		return nil, nil, err
	}
	setting := record.CipherSetting{Type: et, Key: key, IsSubKey: acceptorSubkey, IsLocal: true, DCEStyle: true}
	send, err := record.NewCipher(ctx, setting)
	if err != nil {
		return nil, nil, err
	}
	setting.IsLocal = false
	receive, err := record.NewCipher(ctx, setting)
	if err != nil {
		send.Destroy()
		return nil, nil, err
	}
	records = &RecordContext{
		Realm: c.clientRealm, ServicePrincipal: c.service,
		Send: send, Receive: receive, SendSequence: c.sendSequence,
		ReceiveSequence: uint64(part.SequenceNumber), ExpiresAt: c.expiresAt, EncryptionType: key.KeyType, AcceptorSubkey: acceptorSubkey,
	}
	clear(c.key.KeyValue)
	clear(c.initiatorKey.KeyValue)
	clear(c.ticket.EncPart.Cipher)
	c.key, c.initiatorKey = types.EncryptionKey{}, types.EncryptionKey{}
	c.ticket = messages.Ticket{}
	c.phase = 2
	return thirdLeg, records, nil
}
