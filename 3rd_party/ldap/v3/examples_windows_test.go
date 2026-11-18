//go:build windows
// +build windows

package ldap

import (
	"log"

	"github.com/deploymenttheory/go-sdk-activedirectory/3rd_party/ldap/v3/gssapi"
)

// This example demonstrates passwordless bind using the current process' user
// credentials on Windows (SASL GSSAPI mechanism bind with SSPI client).
func ExampleConn_GSSAPIBind() {
	l, err := exampleDialTLS()
	if err != nil {
		log.Fatal(err)
	}
	defer l.Close()
	state, ok := l.TLSConnectionState()
	if !ok || !state.HandshakeComplete || len(state.VerifiedChains) == 0 || len(state.PeerCertificates) == 0 {
		log.Fatal("verified TLS leaf is required before acquiring credentials")
	}
	// Windows SSPI uses the current process identity and the actual TLS leaf.
	sspiClient, err := gssapi.NewSSPIClientWithChannelBinding(state.PeerCertificates[0])
	if err != nil {
		log.Fatal("could not acquire channel-bound SSPI credentials")
	}
	defer sspiClient.Close()

	// Bind using supplied GSSAPIClient implementation
	err = l.GSSAPIBind(sspiClient, "ldap/ldap.example.com", "")
	if err != nil {
		log.Fatal(err)
	}
}
