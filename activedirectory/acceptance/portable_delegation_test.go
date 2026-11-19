package acceptance

import (
	"bytes"
	"encoding/binary"
	"errors"
	"fmt"
	"os"
	"sync/atomic"
	"testing"
	"time"

	krbgss "github.com/deploymenttheory/go-sdk-activedirectory/3rd_party/gokrb5/v8/gssapi"
	"github.com/deploymenttheory/go-sdk-activedirectory/3rd_party/gokrb5/v8/iana/flags"
	"github.com/deploymenttheory/go-sdk-activedirectory/3rd_party/gokrb5/v8/messages"
	"github.com/deploymenttheory/go-sdk-activedirectory/3rd_party/gokrb5/v8/types"
	ldap "github.com/deploymenttheory/go-sdk-activedirectory/3rd_party/ldap/v3"
	adengine "github.com/deploymenttheory/go-sdk-activedirectory/activedirectory/internal/engine"
	admodel "github.com/deploymenttheory/go-sdk-activedirectory/activedirectory/internal/model"
)

func verifyPortableForwarding(kdc *portableKerberosKDC, ap *messages.APReq) error {
	checksum := ap.Authenticator.Cksum.Checksum
	if len(checksum) < 28 || binary.LittleEndian.Uint32(checksum[20:24])&krbgss.ContextFlagDeleg == 0 ||
		binary.LittleEndian.Uint16(checksum[24:26]) != 1 || int(binary.LittleEndian.Uint16(checksum[26:28])) != len(checksum)-28 {
		return errors.New("actual GSS authenticator omitted valid forwarding envelope")
	}
	var credential messages.KRBCred
	if err := credential.Unmarshal(checksum[28:]); err != nil {
		return err
	}
	if err := credential.DecryptEncPart(ap.Authenticator.SubKey); err == nil {
		return errors.New("forwarded credential used initiator subkey instead of service session key")
	}
	if err := credential.DecryptEncPart(ap.Ticket.DecryptedEncPart.Key); err != nil {
		return err
	}
	if len(credential.Tickets) != 1 || len(credential.DecryptedEncPart.TicketInfo) != 1 {
		return errors.New("actual GSS forwarding changed credential cardinality")
	}
	ticket := &credential.Tickets[0]
	if err := ticket.DecryptEncPart(kdc.keys, nil); err != nil {
		return err
	}
	defer clear(ticket.DecryptedEncPart.Key.KeyValue)
	info := credential.DecryptedEncPart.TicketInfo[0]
	defer clear(info.Key.KeyValue)
	if ticket.Realm != portableKerberosRealm || ticket.SName.PrincipalNameString() != "krbtgt/"+portableKerberosRealm ||
		!types.IsFlagSet(&ticket.DecryptedEncPart.Flags, flags.Forwarded) || !types.IsFlagSet(&ticket.DecryptedEncPart.Flags, flags.Forwardable) ||
		!ticket.DecryptedEncPart.CName.Equal(ap.Authenticator.CName) || ticket.DecryptedEncPart.CRealm != ap.Authenticator.CRealm ||
		!info.PName.Equal(ap.Authenticator.CName) || info.PRealm != ap.Authenticator.CRealm || !info.SName.Equal(ticket.SName) || info.SRealm != ticket.Realm ||
		!bytes.Equal(info.Key.KeyValue, ticket.DecryptedEncPart.Key.KeyValue) || !bytes.Equal(info.Flags.Bytes, ticket.DecryptedEncPart.Flags.Bytes) ||
		!info.EndTime.Equal(ticket.DecryptedEncPart.EndTime) || !time.Now().Before(info.EndTime) {
		return errors.New("GSS forwarding did not preserve fresh KDC ticket identity, key, flags and lifetime")
	}
	return nil
}

func TestPortableDelegationActualForwardingAndProtectedSession(t *testing.T) {
	certificate, roots := portableKerberosTLSCertificate(t)
	for _, profile := range []struct {
		transport  admodel.Transport
		mode       ldap.SASLSecurityMode
		protection admodel.SASLProtection
	}{
		{admodel.TransportLDAPS, ldap.SASLSecurityNone, admodel.SASLProtectionNone},
		{admodel.TransportStartTLS, ldap.SASLSecurityNone, admodel.SASLProtectionNone},
		{admodel.TransportLDAP, ldap.SASLSecuritySign, admodel.SASLProtectionSign},
		{admodel.TransportLDAP, ldap.SASLSecuritySeal, admodel.SASLProtectionSeal},
	} {
		for _, source := range []admodel.KerberosCredentialSource{admodel.KerberosPassword, admodel.KerberosKeytabFile, admodel.KerberosCredentialCacheFile} {
			t.Run(fmt.Sprintf("transport=%d/layer=%d/source=%d", profile.transport, profile.mode, source), func(t *testing.T) {
				var forwarded atomic.Int32
				kdc := newPortableKerberosKDC(t, func(k *portableKerberosKDC) {
					k.delegation = true
					k.inspectAP = func(ap *messages.APReq) error {
						if err := verifyPortableForwarding(k, ap); err != nil {
							return err
						}
						forwarded.Add(1)
						return nil
					}
				})
				payload := []byte{0, 128, 255, 1}
				var dialer adengine.InternalPortableDialer
				var wait func(*testing.T)
				if profile.transport == admodel.TransportLDAP {
					wire := newPortableSASLWire(t, profile.transport, certificate, kdc, profile.mode, 7, "", portableSASLReadStep(payload))
					dialer, wait = wire, wire.wait
				} else {
					acceptor := newPortableKerberosAcceptor(t, kdc, certificate.Leaf)
					wire := newPortableLDAPWire(t, profile.transport, certificate, acceptor.authenticate, acceptor.offer, acceptor.accept, portableSASLReadStep(payload))
					dialer, wait = portableKerberosDialer{ldap: wire, kdc: kdc}, wire.wait
				}
				options := portableTLSConfig(profile.transport, roots)
				if profile.transport == admodel.TransportLDAP {
					options.TLS = nil
				}
				options.Authentication, options.Credentials, options.SASLProtection = admodel.AuthenticationKerberos, nil, profile.protection
				options.AllowDelegation = true
				options.Kerberos = portableKerberosSource(t, kdc, source, true)
				path := options.Kerberos.KeytabPath
				if path == "" {
					path = options.Kerberos.CachePath
				}
				var before []byte
				if path != "" {
					var err error
					before, err = os.ReadFile(path)
					if err != nil {
						t.Fatal(err)
					}
					defer clear(before)
				}
				session, err := adengine.InternalDialPortableWithDial(t.Context(), options, dialer)
				if err != nil {
					t.Fatal(err)
				}
				t.Cleanup(func() { _ = session.InternalClose() })
				observed, err := session.(admodel.InternalSessionProtectionObserver).InternalSessionProtection(t.Context())
				if err != nil || !observed.Complete || !observed.MutualAuthentication || !observed.DelegationSent || !observed.Delegated ||
					!observed.DelegationExpiresAt.After(time.Now()) || observed.SASLProtection != profile.protection || forwarded.Load() != 1 {
					t.Fatalf("actual delegated session facts missing: %+v, %v", observed, err)
				}
				security, err := session.(admodel.InternalMoveSecuritySession).InternalMoveSecurity(t.Context())
				if err != nil || !security.Complete || !security.Delegated || security.Package != "Kerberos" || !security.Protection.DelegationSent {
					t.Fatal("source move observer did not preserve established security facts")
				}
				object, err := session.InternalBaseObject(t.Context(), "CN=owned,DC=ad,DC=sdk,DC=test", []string{"thumbnailPhoto"})
				if err != nil || len(object["thumbnailphoto"]) != 1 || !bytes.Equal(object["thumbnailphoto"][0], payload) {
					t.Fatalf("delegated protected application read failed: %v", err)
				}
				if err := session.InternalClose(); err != nil {
					t.Fatal(err)
				}
				wait(t)
				if path != "" {
					after, err := os.ReadFile(path)
					if err != nil || !bytes.Equal(before, after) {
						t.Fatal("delegation modified caller-owned credential bytes")
					}
					clear(after)
				}
				want := int32(4)
				if source == admodel.KerberosCredentialCacheFile {
					want = 2
				}
				if kdc.requests.Load() != want {
					t.Fatalf("delegation skipped fresh forwarding or replayed authentication: %d", kdc.requests.Load())
				}
			})
		}
	}
}
