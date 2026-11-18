package client

import (
	"errors"
	"fmt"
	"time"

	"github.com/deploymenttheory/go-sdk-activedirectory/3rd_party/gokrb5/v8/credentials"
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

func (ServiceTicket) String() string               { return "ServiceTicket{redacted}" }
func (ServiceTicket) GoString() string             { return "ServiceTicket{redacted}" }
func (ServiceTicket) MarshalJSON() ([]byte, error) { return []byte(`{"redacted":true}`), nil }

func cloneKerberosKey(key types.EncryptionKey) types.EncryptionKey {
	return types.EncryptionKey{KeyType: key.KeyType, KeyValue: append([]byte(nil), key.KeyValue...)}
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
	return ServiceTicket{
		Ticket: ticket, Key: types.EncryptionKey{KeyType: key.KeyType, KeyValue: append([]byte(nil), key.KeyValue...)},
		StartTime: start, EndTime: entry.EndTime,
	}, nil
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

func validateStrictTicket(ticket messages.Ticket, part messages.EncKDCRepPart, realm string, service types.PrincipalName, clockSkew time.Duration) error {
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
	if clockSkew < 0 || start.IsZero() || start.After(now.Add(clockSkew)) || !part.EndTime.After(now) || !part.EndTime.After(start) || part.AuthTime.After(start) ||
		len(part.Flags.Bytes) < 4 || part.Flags.BitLength < 32 || types.IsFlagSet(&part.Flags, flags.Invalid) {
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
	return validateStrictTicket(reply.Ticket, reply.DecryptedEncPart, cl.settings.strictRealm, service, cl.Config.LibDefaults.Clockskew)
}

func (cl *Client) validateStrictRequestedReply(reply messages.KDCRepFields, request messages.KDCReqFields) error {
	if cl.settings.strictRealm == "" {
		return nil
	}
	if err := cl.validateStrictReply(reply, request.ReqBody.SName); err != nil {
		return err
	}
	found := false
	for _, id := range request.ReqBody.EType {
		if id == reply.DecryptedEncPart.Key.KeyType {
			found = true
			break
		}
	}
	if !found || request.ReqBody.Till.IsZero() || reply.DecryptedEncPart.EndTime.After(request.ReqBody.Till) {
		return errors.New("Kerberos reply changed requested key profile or exceeded requested ticket lifetime")
	}
	return nil
}

func (cl *Client) strictCachedService(spn string) (messages.Ticket, types.EncryptionKey, bool, error) {
	entry, ok := cl.cache.getEntry(spn)
	if !ok {
		return messages.Ticket{}, types.EncryptionKey{}, false, nil
	}
	part := messages.EncKDCRepPart{
		Key: entry.SessionKey, AuthTime: entry.AuthTime, StartTime: entry.StartTime, EndTime: entry.EndTime,
		SRealm: entry.Ticket.Realm, SName: entry.Ticket.SName, Flags: types.NewKrbFlags(),
	}
	if err := validateStrictTicket(entry.Ticket, part, cl.settings.strictRealm, types.NewPrincipalName(2, spn), cl.Config.LibDefaults.Clockskew); err != nil {
		return messages.Ticket{}, types.EncryptionKey{}, false, fmt.Errorf("cached service ticket rejected: %w", err)
	}
	return entry.Ticket, entry.SessionKey, true, nil
}

func validateStrictCache(cache *credentials.CCache, realm string, clockSkew time.Duration) error {
	if cache.GetClientRealm() != realm || len(cache.GetClientPrincipalName().NameString) == 0 {
		return errors.New("cache client does not match explicit realm")
	}
	for _, entry := range cache.GetEntries() {
		if entry.Client.Realm != realm || !entry.Client.PrincipalName.Equal(cache.GetClientPrincipalName()) || entry.Server.Realm != realm || entry.IsSKey ||
			len(entry.SecondTicket) != 0 {
			return errors.New("cache credential does not match explicit client and realm")
		}
		var ticket messages.Ticket
		if err := ticket.Unmarshal(entry.Ticket); err != nil {
			return err
		}
		part := messages.EncKDCRepPart{
			Key: entry.Key, Flags: entry.TicketFlags, AuthTime: entry.AuthTime, StartTime: entry.StartTime, EndTime: entry.EndTime,
			SRealm: entry.Server.Realm, SName: entry.Server.PrincipalName,
		}
		if err := validateStrictTicket(ticket, part, realm, entry.Server.PrincipalName, clockSkew); err != nil {
			return err
		}
	}
	return nil
}
