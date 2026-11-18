package gssapi

import (
	"errors"
	"time"
)

// AuthenticationContext is a keyless snapshot of the mechanism exchange.
// Complete proves mutual authentication and authenticated layer negotiation;
// the LDAP bind caller must separately require the final successful LDAP result.
// ChannelBound records the certificate binding emitted in this context, not a
// discovery of the acceptor's channel-binding enforcement policy.
type AuthenticationContext struct {
	MutualAuthentication bool
	ChannelBound         bool
	Delegated            bool
	ExpiresAt            time.Time
	SASLSecurity         int
	Complete             bool
}

// AuthenticationContext returns only facts retained from the actual exchange.
// Requested security modes and configured channel bindings alone yield no facts.
func (client *Client) AuthenticationContext() (AuthenticationContext, error) {
	if !client.mutualAuthenticated || !client.saslNegotiated || client.contextExpiresAt.IsZero() || !time.Now().Before(client.contextExpiresAt) {
		return AuthenticationContext{}, errors.New("ldap: authenticated Kerberos mechanism context is incomplete or expired")
	}
	return AuthenticationContext{MutualAuthentication: true, ChannelBound: client.channelBindingSent, ExpiresAt: client.contextExpiresAt,
		SASLSecurity: client.negotiatedSASLSecurity, Complete: true}, nil
}
