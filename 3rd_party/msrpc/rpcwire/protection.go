package rpcwire

import "time"

// Protection contains copied keyless facts. MutualAuthentication follows a
// verified AP-REP; ProtectedReply follows an actually verified confidential RPC
// response/fault. Complete additionally requires an unretired association.
type Protection struct {
	Realm, ServicePrincipal                        string
	EncryptionType                                 int32
	ExpiresAt                                      time.Time
	MutualAuthentication, ProtectedReply, Complete bool
}

func (c *Client) Protection() Protection {
	verified := c.protectedReply.Load()
	return Protection{
		Realm: c.realm, ServicePrincipal: c.service, EncryptionType: c.encryptionType, ExpiresAt: c.expiresAt,
		MutualAuthentication: true, ProtectedReply: verified, Complete: verified && c.stream.transport.HasErr() == nil && time.Now().Before(c.expiresAt),
	}
}
