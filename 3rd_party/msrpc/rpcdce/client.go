// Package rpcdce implements an isolated, explicit Kerberos DCE authentication
// actor. The SDK dispatcher does not use it pending full qualification.
package rpcdce

import (
	"context"
	"crypto/rand"
	"encoding/binary"
	"errors"
	"fmt"
	"math"
	"strings"
	"sync"
	"time"

	krbclient "github.com/deploymenttheory/go-sdk-activedirectory/3rd_party/gokrb5/v8/client"
	krbcrypto "github.com/deploymenttheory/go-sdk-activedirectory/3rd_party/gokrb5/v8/crypto"
	"github.com/deploymenttheory/go-sdk-activedirectory/3rd_party/gokrb5/v8/iana/chksumtype"
	"github.com/deploymenttheory/go-sdk-activedirectory/3rd_party/gokrb5/v8/iana/flags"
	"github.com/deploymenttheory/go-sdk-activedirectory/3rd_party/gokrb5/v8/messages"
	"github.com/deploymenttheory/go-sdk-activedirectory/3rd_party/gokrb5/v8/types"
	record "github.com/deploymenttheory/go-sdk-activedirectory/3rd_party/msrpc/ssp/krb5/crypto"
)

var (
	ErrIdentity       = errors.New("RPC Kerberos ticket does not match the pinned identity")
	ErrAuthentication = errors.New("RPC Kerberos mutual authentication failed")
	ErrExpired        = errors.New("RPC Kerberos service context expired")
	ErrState          = errors.New("RPC Kerberos authentication state is invalid")
)

// Client owns one ticket's copied key and one two-response DCE authentication
// exchange. Ticket acquisition and explicit target/stage validation are separate.
type Client struct {
	mu                  sync.Mutex
	ticket              messages.Ticket
	key, initiatorKey   types.EncryptionKey
	clientRealm         string
	service             string
	clientName          types.PrincipalName
	expiresAt, authTime time.Time
	authUsec            int
	sendSequence        uint64
	phase               uint8
}

func NewClient(
	ctx context.Context,
	expectedRealm string,
	expectedService types.PrincipalName,
	clientRealm string,
	clientName types.PrincipalName,
	selected krbclient.ServiceTicket,
) (*Client, error) {
	if err := context.Cause(ctx); err != nil {
		return nil, fmt.Errorf("create RPC authentication actor: %w", err)
	}
	if expectedRealm == "" || clientRealm != expectedRealm || len(expectedService.NameString) != 2 || len(clientName.NameString) == 0 ||
		selected.Ticket.TktVNO != 5 || selected.Ticket.Realm != expectedRealm || !selected.Ticket.SName.Equal(expectedService) {
		return nil, ErrIdentity
	}
	if selected.Key.KeyType != 17 && selected.Key.KeyType != 18 {
		return nil, record.ErrUnsupportedProfile
	}
	et, err := krbcrypto.GetEtype(selected.Key.KeyType)
	if err != nil || len(selected.Key.KeyValue) != et.GetKeyByteSize() {
		return nil, record.ErrInvalidKey
	}
	if selected.StartTime.IsZero() || selected.EndTime.IsZero() || !selected.EndTime.After(time.Now()) || !selected.EndTime.After(selected.StartTime) {
		return nil, ErrExpired
	}
	if selected.StartTime.After(time.Now().Add(5 * time.Minute)) {
		return nil, ErrExpired
	}
	if selected.Ticket.EncPart.EType < 17 || selected.Ticket.EncPart.EType > 20 || len(selected.Ticket.EncPart.Cipher) == 0 {
		return nil, ErrIdentity
	}
	ticket := selected.Ticket
	ticket.SName.NameString = append([]string(nil), ticket.SName.NameString...)
	ticket.EncPart.Cipher = append([]byte(nil), ticket.EncPart.Cipher...)
	ticket.DecryptedEncPart = messages.EncTicketPart{}
	return &Client{
		ticket:      ticket,
		key:         types.EncryptionKey{KeyType: selected.Key.KeyType, KeyValue: append([]byte(nil), selected.Key.KeyValue...)},
		clientRealm: clientRealm,
		service:     strings.Join(ticket.SName.NameString, "/"),
		clientName:  types.PrincipalName{NameType: clientName.NameType, NameString: append([]string(nil), clientName.NameString...)},
		expiresAt:   selected.EndTime,
	}, nil
}

func (c *Client) Destroy() { c.mu.Lock(); defer c.mu.Unlock(); c.destroy() }
func (c *Client) destroy() {
	clear(c.key.KeyValue)
	clear(c.initiatorKey.KeyValue)
	clear(c.ticket.EncPart.Cipher)
	c.key = types.EncryptionKey{}
	c.initiatorKey = types.EncryptionKey{}
	c.ticket = messages.Ticket{}
	c.clientName = types.PrincipalName{}
	c.clientRealm = ""
	c.service = ""
	c.authTime = time.Time{}
	c.authUsec = 0
	c.phase = 3
}

// TicketIdentity returns the validated ticket selection. It does not assert
// authentication or RPC acceptance; those require subsequent protocol evidence.
func (c *Client) TicketIdentity() (realm, service string) {
	c.mu.Lock()
	defer c.mu.Unlock()
	return c.clientRealm, c.service
}

func (c *Client) check(ctx context.Context, phase uint8) error {
	if err := context.Cause(ctx); err != nil {
		return fmt.Errorf("check RPC authentication state: %w", err)
	}
	if c.phase != phase {
		return ErrState
	}
	if !time.Now().Before(c.expiresAt) {
		return ErrExpired
	}
	return nil
}

// Begin creates a raw AP-REQ with DCE/mutual/replay/sequence/integrity/privacy
// requests. No requested flag is reported as an established protection fact.
func (c *Client) Begin(ctx context.Context) (wire []byte, err error) {
	c.mu.Lock()
	defer c.mu.Unlock()
	if err = c.check(ctx, 0); err != nil {
		c.destroy()
		return nil, err
	}
	defer func() {
		if err != nil {
			c.destroy()
		}
	}()
	authenticator, err := types.NewAuthenticator(c.clientRealm, c.clientName)
	if err != nil {
		return nil, err
	}
	checksum := make([]byte, 24)
	binary.LittleEndian.PutUint32(checksum, 16)
	binary.LittleEndian.PutUint32(checksum[20:], 0x1000|2|4|8|16|32)
	authenticator.Cksum = types.Checksum{CksumType: chksumtype.GSSAPI, Checksum: checksum}
	c.initiatorKey = types.EncryptionKey{KeyType: c.key.KeyType, KeyValue: make([]byte, len(c.key.KeyValue))}
	if _, err = rand.Read(c.initiatorKey.KeyValue); err != nil {
		return nil, fmt.Errorf("create RPC initiator key: %w", err)
	}
	authenticator.SubKey = c.initiatorKey
	req, err := messages.NewAPReq(c.ticket, c.key, authenticator)
	if err != nil {
		return nil, err
	}
	types.SetFlag(&req.APOptions, flags.APOptionMutualRequired)
	wire, err = req.Marshal()
	if err != nil {
		return nil, err
	}
	if len(wire) > 65535 || context.Cause(ctx) != nil {
		return nil, errors.Join(ErrAuthentication, context.Cause(ctx))
	}
	c.authTime, c.authUsec = authenticator.CTime, authenticator.Cusec
	if authenticator.SeqNumber < 0 || authenticator.SeqNumber > math.MaxUint32 {
		return nil, ErrAuthentication
	}
	c.sendSequence = uint64(authenticator.SeqNumber)
	c.phase = 1
	return wire, nil
}
