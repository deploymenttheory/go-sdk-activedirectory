package acceptance

import (
	"context"
	"fmt"
	"net"
	"testing"

	ber "github.com/go-asn1-ber/asn1-ber"

	ldap "github.com/deploymenttheory/go-sdk-activedirectory/3rd_party/ldap/v3"
	adengine "github.com/deploymenttheory/go-sdk-activedirectory/activedirectory/internal/engine"
	admodel "github.com/deploymenttheory/go-sdk-activedirectory/activedirectory/internal/model"
)

func TestPortableKerberosPasswordMutualCBTAndUsableTLSDirectorySession(t *testing.T) {
	certificate, roots := portableKerberosTLSCertificate(t)
	for _, transport := range []admodel.Transport{admodel.TransportLDAPS, admodel.TransportStartTLS} {
		for _, credential := range []struct {
			source        admodel.KerberosCredentialSource
			cachedService bool
		}{
			{admodel.KerberosPassword, false}, {admodel.KerberosKeytabFile, false}, {admodel.KerberosCredentialCacheFile, false}, {admodel.KerberosCredentialCacheFile, true},
		} {
			t.Run(fmt.Sprintf("transport-%d/source-%d/cached-%t", transport, credential.source, credential.cachedService), func(t *testing.T) {
				kdc := newPortableKerberosKDC(t)
				acceptor := newPortableKerberosAcceptor(t, kdc, certificate.Leaf)
				wire := newPortableLDAPWire(t, transport, certificate, acceptor.authenticate, acceptor.offer, acceptor.accept,
					func(conn net.Conn, request *ber.Packet) error {
						if _, err := conn.Write(portableLDAPEntry(request, map[string][][]byte{"name": {[]byte("owned-kerberos-session")}}).Bytes()); err != nil {
							return err
						}
						_, err := conn.Write(portableLDAPResult(request, ldap.ApplicationSearchResultDone, 0).Bytes())
						return err
					})
				options := portableTLSConfig(transport, roots)
				options.Authentication = admodel.AuthenticationKerberos
				options.Credentials = nil
				options.Kerberos = portableKerberosSource(t, kdc, credential.source, credential.cachedService)
				session, err := adengine.InternalDialPortableWithDial(t.Context(), options, portableKerberosDialer{ldap: wire, kdc: kdc})
				if err != nil {
					t.Fatal(err)
				}
				t.Cleanup(func() { _ = session.InternalClose() })
				observed, err := session.(admodel.InternalSessionProtectionObserver).InternalSessionProtection(context.Background())
				if err != nil || !observed.Complete || !observed.TLSVerified || !observed.MutualAuthentication || !observed.ChannelBindingSent || observed.ChannelBound ||
					observed.Delegated || observed.Authentication != admodel.AuthenticationKerberos || observed.SASLProtection != admodel.SASLProtectionNone {
					t.Fatalf("unproved Kerberos protection facts: %+v, %v", observed, err)
				}
				object, err := session.InternalBaseObject(t.Context(), "CN=owned,DC=ad,DC=sdk,DC=test", []string{"name"})
				if err != nil || len(object["name"]) != 1 || string(object["name"][0]) != "owned-kerberos-session" {
					t.Fatalf("authenticated directory read failed: %v", err)
				}
				if err := session.InternalClose(); err != nil {
					t.Fatal(err)
				}
				wire.wait(t)
				wantRequests := int32(3)
				if credential.source == admodel.KerberosCredentialCacheFile {
					wantRequests = 1
					if credential.cachedService {
						wantRequests = 0
					}
				}
				if kdc.requests.Load() != wantRequests || wire.requests.Load() != 4 {
					t.Fatalf("Kerberos exchange replayed or fell back: KDC=%d LDAP=%d", kdc.requests.Load(), wire.requests.Load())
				}
			})
		}
	}
}
