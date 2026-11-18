package ldap

import (
	"crypto/x509"
	"fmt"
)

// tlsServerCertificate accepts channel binding only from a completed, verified
// TLS channel, including an SDK-owned connection that retains that actual state.
func (l *Conn) tlsServerCertificate() (*x509.Certificate, error) {
	state, ok := l.TLSConnectionState()
	if !ok || !state.HandshakeComplete || len(state.VerifiedChains) == 0 || len(state.PeerCertificates) == 0 {
		return nil, fmt.Errorf("ldap: channel binding requires a completed verified TLS connection")
	}
	return state.PeerCertificates[0], nil
}
