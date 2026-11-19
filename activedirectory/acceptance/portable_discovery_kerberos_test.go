package acceptance

import (
	"context"
	"crypto/sha256"
	"fmt"
	"os"
	"testing"

	ldap "github.com/deploymenttheory/go-sdk-activedirectory/3rd_party/ldap/v3"
	adengine "github.com/deploymenttheory/go-sdk-activedirectory/activedirectory/internal/engine"
	admodel "github.com/deploymenttheory/go-sdk-activedirectory/activedirectory/internal/model"
	"github.com/deploymenttheory/go-sdk-activedirectory/activedirectory/services/discovery"
)

func discoveryCredentialDigest(t *testing.T, config admodel.Config) [32]byte {
	t.Helper()
	path := config.Kerberos.KeytabPath
	if path == "" {
		path = config.Kerberos.CachePath
	}
	if path == "" {
		return [32]byte{}
	}
	data, err := os.ReadFile(path)
	if err != nil {
		t.Fatal("cannot hash owned credential fixture")
	}
	defer clear(data)
	return sha256.Sum256(data)
}

func TestPortableDiscoveryRealKerberosSourcesAndProtectedProfiles(t *testing.T) {
	profiles := []struct {
		transport admodel.Transport
		mode      admodel.SASLProtection
		vendor    ldap.SASLSecurityMode
	}{
		{admodel.TransportLDAPS, admodel.SASLProtectionNone, ldap.SASLSecurityNone},
		{admodel.TransportStartTLS, admodel.SASLProtectionNone, ldap.SASLSecurityNone},
		{admodel.TransportLDAP, admodel.SASLProtectionSign, ldap.SASLSecuritySign},
		{admodel.TransportLDAP, admodel.SASLProtectionSeal, ldap.SASLSecuritySeal},
	}
	for _, profile := range profiles {
		for _, source := range []admodel.KerberosCredentialSource{admodel.KerberosPassword, admodel.KerberosKeytabFile, admodel.KerberosCredentialCacheFile} {
			t.Run(fmt.Sprintf("transport%d/layer%d/source%d", profile.transport, profile.mode, source), func(t *testing.T) {
				certificate, roots := portableKerberosTLSCertificate(t)
				kdc := newPortableKerberosKDC(t)
				fixture := portableDiscoveryTopology("valid")
				var steps []portableLDAPStep
				for range 32 {
					steps = append(steps, fixture.read)
				}
				var dialer adengine.InternalPortableDialer
				var wait func(*testing.T)
				if profile.transport == admodel.TransportLDAP {
					wire := newPortableSASLWire(t, profile.transport, certificate, kdc, profile.vendor, 7, "", steps...)
					dialer = wire
					wait = wire.wait
				} else {
					acceptor := newPortableKerberosAcceptor(t, kdc, certificate.Leaf)
					steps = append([]portableLDAPStep{acceptor.authenticate, acceptor.offer, acceptor.accept}, steps...)
					wire := newPortableLDAPWire(t, profile.transport, certificate, steps...)
					dialer = portableKerberosDialer{ldap: wire, kdc: kdc}
					wait = wire.wait
				}
				config := portableTLSConfig(profile.transport, roots)
				config.Authentication, config.Credentials, config.SASLProtection = admodel.AuthenticationKerberos, nil, profile.mode
				if profile.transport == admodel.TransportLDAP {
					config.TLS = nil
				}
				config.Kerberos = portableKerberosSource(t, kdc, source, false)
				before := discoveryCredentialDigest(t, config)
				connection, observed, err := adengine.InternalDialDomainController(
					t.Context(),
					config,
					discovery.DomainControllerSelection{DomainDNS: "example.test"},
					func(ctx context.Context, selected admodel.Config) (*adengine.Client, error) {
						session, err := adengine.InternalDialPortableWithDial(ctx, selected, dialer)
						if err != nil {
							return nil, err
						}
						return adengine.InternalNewClient(selected, session), nil
					},
				)
				if err != nil || connection == nil || !observed.Complete || !observed.Protection.Complete || !observed.Protection.MutualAuthentication ||
					observed.Protection.SASLProtection != profile.mode ||
					observed.Protection.TLSVerified != (profile.transport != admodel.TransportLDAP) ||
					observed.Protection.ChannelBindingSent != observed.Protection.TLSVerified ||
					observed.Protection.ChannelBound {
					t.Fatalf("actual Kerberos discovery protection incomplete or inferred: %v", err)
				}
				if discoveryCredentialDigest(t, config) != before {
					t.Fatal("caller credential file changed")
				}
				if err = connection.Close(); err != nil {
					t.Fatal(err)
				}
				wait(t)
				wantKDC := int32(3)
				if source == admodel.KerberosCredentialCacheFile {
					wantKDC = 1
				}
				if kdc.requests.Load() != wantKDC {
					t.Fatal("credential/endpoint fallback or authentication replay")
				}
			})
		}
	}
}
