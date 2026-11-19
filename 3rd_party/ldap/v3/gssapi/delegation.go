package gssapi

import (
	"errors"
	"math"
	"time"

	krbclient "github.com/deploymenttheory/go-sdk-activedirectory/3rd_party/gokrb5/v8/client"
	krbgss "github.com/deploymenttheory/go-sdk-activedirectory/3rd_party/gokrb5/v8/gssapi"
)

func (client *Client) serviceTicketForContext(target string) (krbclient.ServiceTicket, []byte, time.Time, error) {
	if client.delegationRequested {
		return client.GetServiceTicketWithDelegation(target)
	}
	ticket, err := client.GetServiceTicketWithValidity(target)
	return ticket, nil, time.Time{}, err
}

// SetDelegation explicitly selects credential forwarding for a new context.
// Changing the request after establishment begins is refused. A true request
// must obtain/emit a fresh validated KRB-CRED, never an ordinary-bind fallback.
func (client *Client) SetDelegation(enabled bool) error {
	if len(client.ekey.KeyValue) != 0 || client.mutualAuthenticated || client.saslNegotiated {
		return errors.New("ldap: delegation policy cannot change during a Kerberos context")
	}
	client.delegationRequested = enabled
	return nil
}

func (client *Client) delegationChecksum(flags []uint32, binding *[16]byte, credential []byte) ([]byte, error) {
	if len(credential) > math.MaxUint16 {
		return nil, errors.New("ldap: forwarding credential exceeds the GSS length bound")
	}
	if client.delegationRequested != (len(credential) != 0) {
		return nil, errors.New("ldap: required Kerberos forwarding credential is missing or exceeds the GSS length bound")
	}
	checksum := newAuthenticatorChecksum(flags, binding)
	if len(credential) == 0 {
		return checksum, nil
	}
	le.PutUint32(checksum[20:24], le.Uint32(checksum[20:24])|krbgss.ContextFlagDeleg)
	checksum = le.AppendUint16(checksum, 1)
	// Encode the already-bounded length as explicit octets; no narrowing signed
	// conversion is needed at this protocol boundary.
	checksum = append(checksum, byte(len(credential)&0xff), byte((len(credential)>>8)&0xff))
	checksum = append(checksum, credential...)
	return checksum, nil
}
