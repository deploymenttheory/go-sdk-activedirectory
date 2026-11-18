package gssapi

import (
	"errors"
	"time"
)

// AuthenticationContext is a keyless snapshot of the mechanism exchange.
// Complete proves mutual authentication and authenticated layer negotiation;
// the LDAP bind caller must separately require the final successful LDAP result.
// ChannelBindingSent records the certificate binding emitted in this context.
// Kerberos provides no peer confirmation of binding verification (RFC4121 §7),
// so ChannelBound remains unconfirmed; successful mutual authentication is not
// evidence that the acceptor enforced channel binding.
type AuthenticationContext struct {
	MutualAuthentication bool
	ChannelBound         bool
	ChannelBindingSent   bool
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
	return AuthenticationContext{MutualAuthentication: true, ChannelBindingSent: client.channelBindingSent, ExpiresAt: client.contextExpiresAt,
		SASLSecurity: client.negotiatedSASLSecurity, Complete: true}, nil
}
