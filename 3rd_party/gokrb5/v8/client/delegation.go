package client

import (
	"errors"
	"time"

	"github.com/deploymenttheory/go-sdk-activedirectory/3rd_party/gokrb5/v8/iana/flags"
	"github.com/deploymenttheory/go-sdk-activedirectory/3rd_party/gokrb5/v8/messages"
	"github.com/deploymenttheory/go-sdk-activedirectory/3rd_party/gokrb5/v8/types"
)

// GetServiceTicketWithDelegation requires fresh KDC-authenticated service policy
// and a fresh FORWARDED/FORWARDABLE TGT. It never substitutes cached policy or
// forwards the original TGT. StrictRealm pins the explicit actor/realm/SPN and
// AES profiles; every reply retains ordinary nonce/time/principal validation.
// The returned key and encrypted KRB-CRED are owned copies and must be cleared.
// Successful forwarding is not proof of the acceptor's remote authorization.
func (cl *Client) GetServiceTicketWithDelegation(spn string) (ServiceTicket, []byte, time.Time, error) {
	if cl.settings.strictRealm == "" || cl.settings.strictRealm != cl.Credentials.Realm() {
		return ServiceTicket{}, nil, time.Time{}, errors.New("delegation requires an explicit strict client realm")
	}
	realm := cl.settings.strictRealm
	tgt, borrowed, err := cl.sessionTGT(realm)
	if err != nil {
		return ServiceTicket{}, nil, time.Time{}, err
	}
	tgtKey := cloneKerberosKey(borrowed)
	defer clear(tgtKey.KeyValue)
	_, originalExpiry, _, _, err := cl.sessionTimes(realm)
	if err != nil {
		return ServiceTicket{}, nil, time.Time{}, err
	}
	service := types.NewPrincipalName(2, spn)
	_, authenticated, err := cl.TGSREQGenerateAndExchange(service, realm, tgt, tgtKey, false)
	defer clear(authenticated.DecryptedEncPart.Key.KeyValue)
	if err != nil {
		return ServiceTicket{}, nil, time.Time{}, err
	}
	if !types.IsFlagSet(&authenticated.DecryptedEncPart.Flags, flags.OKAsDelegate) || authenticated.DecryptedEncPart.EndTime.After(originalExpiry) {
		return ServiceTicket{}, nil, time.Time{}, errors.New("authenticated service policy does not permit credential delegation")
	}
	request, err := messages.NewForwardedTGSReq(cl.Credentials.CName(), realm, cl.Config, tgt, tgtKey)
	if err != nil {
		return ServiceTicket{}, nil, time.Time{}, err
	}
	_, forwarded, err := cl.TGSExchange(request, realm, tgt, tgtKey, 0)
	defer clear(forwarded.DecryptedEncPart.Key.KeyValue)
	if err != nil {
		return ServiceTicket{}, nil, time.Time{}, err
	}
	part := forwarded.DecryptedEncPart
	if !types.IsFlagSet(&part.Flags, flags.Forwarded) || !types.IsFlagSet(&part.Flags, flags.Forwardable) || part.EndTime.After(originalExpiry) {
		return ServiceTicket{}, nil, time.Time{}, errors.New("KDC did not issue the required fresh forwarded credential")
	}
	credential := messages.KRBCred{
		PVNO: 5, MsgType: 22, Tickets: []messages.Ticket{forwarded.Ticket},
		DecryptedEncPart: messages.EncKrbCredPart{TicketInfo: []messages.KrbCredInfo{{
			Key: part.Key, PRealm: forwarded.CRealm, PName: forwarded.CName, Flags: part.Flags,
			AuthTime: part.AuthTime, StartTime: part.StartTime, EndTime: part.EndTime, RenewTill: part.RenewTill,
			SRealm: part.SRealm, SName: part.SName, CAddr: part.CAddr,
		}}},
	}
	now := time.Now().UTC()
	credential.DecryptedEncPart.Timestamp = now.Truncate(time.Second)
	credential.DecryptedEncPart.Usec = now.Nanosecond() / 1000
	if err := credential.EncryptEncPart(authenticated.DecryptedEncPart.Key); err != nil {
		return ServiceTicket{}, nil, time.Time{}, err
	}
	encoded, err := credential.Marshal()
	if err != nil {
		return ServiceTicket{}, nil, time.Time{}, err
	}
	start := authenticated.DecryptedEncPart.StartTime
	if start.IsZero() {
		start = authenticated.DecryptedEncPart.AuthTime
	}
	selected := ServiceTicket{
		Ticket: authenticated.Ticket, Key: cloneKerberosKey(authenticated.DecryptedEncPart.Key),
		StartTime: start, EndTime: authenticated.DecryptedEncPart.EndTime,
	}
	return selected, encoded, part.EndTime, nil
}
