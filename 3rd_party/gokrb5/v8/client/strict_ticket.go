package client

import (
	"errors"
	"fmt"
	"time"

	"github.com/deploymenttheory/go-sdk-activedirectory/3rd_party/gokrb5/v8/iana/flags"
	"github.com/deploymenttheory/go-sdk-activedirectory/3rd_party/gokrb5/v8/messages"
	"github.com/deploymenttheory/go-sdk-activedirectory/3rd_party/gokrb5/v8/types"
)

// ServiceTicket contains the validated service ticket and its actual lifetime.
// KeyValue is an owned copy; the caller must clear it after use.
type ServiceTicket struct {
	Ticket             messages.Ticket
	Key                types.EncryptionKey
	StartTime, EndTime time.Time
}

// GetServiceTicketWithValidity returns the selected ticket's validated lifetime.
// StrictRealm refuses expired cached tickets instead of renewing or changing identity.
func (cl *Client) GetServiceTicketWithValidity(spn string) (ServiceTicket, error) {
	ticket, key, err := cl.GetServiceTicket(spn)
	if err != nil {
		return ServiceTicket{}, err
	}
	entry, ok := cl.cache.getEntry(spn)
	if !ok {
		return ServiceTicket{}, errors.New("service ticket validity is unavailable")
	}
	start := entry.StartTime
	if start.IsZero() {
		start = entry.AuthTime
	}
	return ServiceTicket{Ticket: ticket, Key: types.EncryptionKey{KeyType: key.KeyType, KeyValue: append([]byte(nil), key.KeyValue...)},
		StartTime: start, EndTime: entry.EndTime}, nil
}

func validStrictKey(key types.EncryptionKey) bool {
	switch key.KeyType {
	case 17, 19:
		return len(key.KeyValue) == 16
	case 18, 20:
		return len(key.KeyValue) == 32
	default:
		return false
	}
}

func strictEncryptionType(id int32) bool { return id == 17 || id == 18 || id == 19 || id == 20 }

func validateStrictTicket(ticket messages.Ticket, part messages.EncKDCRepPart, realm string, service types.PrincipalName) error {
	if ticket.TktVNO != 5 || ticket.Realm != realm || part.SRealm != realm || !ticket.SName.Equal(service) || !part.SName.Equal(service) {
		return errors.New("Kerberos ticket does not match the explicit realm and service principal")
	}
	if !validStrictKey(part.Key) || !strictEncryptionType(ticket.EncPart.EType) {
		return errors.New("Kerberos ticket requires a supported AES profile and valid key size")
	}
	now := time.Now().UTC()
	start := part.StartTime
	if start.IsZero() {
		start = part.AuthTime
	}
	if start.IsZero() || start.After(now) || !part.EndTime.After(now) || !part.EndTime.After(start) || part.AuthTime.After(start) || types.IsFlagSet(&part.Flags, flags.Invalid) {
		return errors.New("Kerberos ticket is expired, not yet valid or invalid")
	}
	return nil
}

func (cl *Client) validateStrictReply(reply messages.KDCRepFields, service types.PrincipalName) error {
	if cl.settings.strictRealm == "" {
		return nil
	}
	if reply.PVNO != 5 || reply.CRealm != cl.Credentials.Realm() || !reply.CName.Equal(cl.Credentials.CName()) {
		return errors.New("Kerberos reply does not match the explicit client identity")
	}
	return validateStrictTicket(reply.Ticket, reply.DecryptedEncPart, cl.settings.strictRealm, service)
}

func (cl *Client) strictCachedService(spn string) (messages.Ticket, types.EncryptionKey, bool, error) {
	entry, ok := cl.cache.getEntry(spn)
	if !ok {
		return messages.Ticket{}, types.EncryptionKey{}, false, nil
	}
	part := messages.EncKDCRepPart{Key: entry.SessionKey, AuthTime: entry.AuthTime, StartTime: entry.StartTime, EndTime: entry.EndTime,
		SRealm: entry.Ticket.Realm, SName: entry.Ticket.SName}
	if err := validateStrictTicket(entry.Ticket, part, cl.settings.strictRealm, types.NewPrincipalName(2, spn)); err != nil {
		return messages.Ticket{}, types.EncryptionKey{}, false, fmt.Errorf("cached service ticket rejected: %w", err)
	}
	return entry.Ticket, entry.SessionKey, true, nil
}
