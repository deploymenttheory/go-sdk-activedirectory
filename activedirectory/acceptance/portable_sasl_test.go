package acceptance

import (
	"bytes"
	"errors"
	"fmt"
	"net"
	"testing"

	ber "github.com/go-asn1-ber/asn1-ber"

	ldap "github.com/deploymenttheory/go-sdk-activedirectory/3rd_party/ldap/v3"
	adengine "github.com/deploymenttheory/go-sdk-activedirectory/activedirectory/internal/engine"
	admodel "github.com/deploymenttheory/go-sdk-activedirectory/activedirectory/internal/model"
)

func portableSASLReadStep(payload []byte) portableLDAPStep {
	return func(conn net.Conn, request *ber.Packet) error {
		if request.Children[1].Tag != ldap.ApplicationSearchRequest {
			return errors.New("protected fixture received a different application operation")
		}
		if _, err := conn.Write(portableLDAPEntry(request, map[string][][]byte{"thumbnailPhoto": {payload}}).Bytes()); err != nil {
			return err
		}
		_, err := conn.Write(portableLDAPResult(request, ldap.ApplicationSearchResultDone, 0).Bytes())
		return err
	}
}

func TestPortableKerberosSASLRealCredentialExchangeAndProtectedStream(t *testing.T) {
	certificate, roots := portableKerberosTLSCertificate(t)
	for _, transport := range []admodel.Transport{admodel.TransportLDAP, admodel.TransportLDAPS, admodel.TransportStartTLS} {
		for _, layer := range []struct {
			vendor ldap.SASLSecurityMode
			sdk    admodel.SASLProtection
		}{{ldap.SASLSecuritySign, admodel.SASLProtectionSign}, {ldap.SASLSecuritySeal, admodel.SASLProtectionSeal}} {
			for _, credential := range []struct {
				source        admodel.KerberosCredentialSource
				cachedService bool
			}{
				{admodel.KerberosPassword, false},
				{admodel.KerberosKeytabFile, false},
				{admodel.KerberosCredentialCacheFile, false},
				{admodel.KerberosCredentialCacheFile, true},
			} {
				t.Run(fmt.Sprintf("transport=%d/layer=%d/source=%d/cached=%t", transport, layer.vendor, credential.source, credential.cachedService), func(t *testing.T) {
					kdc := newPortableKerberosKDC(t)
					payload := bytes.Repeat([]byte{0, 255, 128, 3}, 100)
					wire := newPortableSASLWire(t, transport, certificate, kdc, layer.vendor, 7, "", portableSASLReadStep(payload),
						func(conn net.Conn, request *ber.Packet) error {
							if request.Children[1].Tag != ldap.ApplicationDelRequest {
								return errors.New("protected fixture expected one deletion attempt")
							}
							_, err := conn.Write(portableLDAPResult(request, ldap.ApplicationDelResponse, ldap.LDAPResultInsufficientAccessRights).Bytes())
							return err
						}, portableSASLReadStep(payload))
					options := portableTLSConfig(transport, roots)
					if transport == admodel.TransportLDAP {
						options.TLS = nil
					}
					options.Authentication, options.Credentials, options.SASLProtection = admodel.AuthenticationKerberos, nil, layer.sdk
					options.Kerberos = portableKerberosSource(t, kdc, credential.source, credential.cachedService)
					session, err := adengine.InternalDialPortableWithDial(t.Context(), options, wire)
					if err != nil {
						t.Fatal(err)
					}
					t.Cleanup(func() { _ = session.InternalClose() })
					observed, err := session.(admodel.InternalSessionProtectionObserver).InternalSessionProtection(t.Context())
					if err != nil || !observed.Complete || !observed.MutualAuthentication || observed.SASLProtection != layer.sdk ||
						observed.TLSVerified != (transport != admodel.TransportLDAP) || observed.ChannelBindingSent != observed.TLSVerified || observed.ChannelBound ||
						observed.SASLEncryptionType != 18 {
						t.Fatalf("protected stream facts were not established: %+v, %v", observed, err)
					}
					if layer.sdk == admodel.SASLProtectionSeal && observed.SASLCipherBits != 256 ||
						layer.sdk == admodel.SASLProtectionSign && observed.SASLCipherBits != 0 {
						t.Fatal("SASL confidentiality was inferred from authentication or signing")
					}
					_, protectionErr := session.(admodel.InternalPasswordSession).InternalPasswordProtection(t.Context(), transport)
					if transport == admodel.TransportLDAP && layer.sdk == admodel.SASLProtectionSign {
						if !errors.Is(protectionErr, admodel.ErrPasswordProtection) {
							t.Fatal("integrity-only channel accepted a password write")
						}
					} else if protectionErr != nil {
						t.Fatal(protectionErr)
					}
					for operation := range 2 {
						object, err := session.InternalBaseObject(t.Context(), "CN=owned,DC=ad,DC=sdk,DC=test", []string{"thumbnailPhoto"})
						if err != nil || len(object["thumbnailphoto"]) != 1 || !bytes.Equal(object["thumbnailphoto"][0], payload) {
							t.Fatalf("fragmented protected binary read failed: %v", err)
						}
						if operation == 0 {
							attempt := session.(admodel.InternalLdapWriteSession).InternalLdapWrite(t.Context(), admodel.InternalLdapWriteRequest{
								InternalOperation: admodel.InternalLdapWriteDelete, InternalDn: "CN=owned,DC=ad,DC=sdk,DC=test",
							})
							if attempt.State != admodel.InternalLdapWriteRejected || admodel.Classify(attempt.Err) != admodel.ClassDenied {
								t.Fatalf("authenticated server refusal lost its outcome: %+v", attempt)
							}
						}
					}
					if err := session.InternalClose(); err != nil {
						t.Fatal(err)
					}
					wire.wait(t)
					if wire.requests.Load() != 6 || wire.peer.readFrames.Load() <= 3 || wire.peer.writeFrames.Load() <= 3 {
						t.Fatal("application traffic bypassed protection or did not exercise fragmentation")
					}
				})
			}
		}
	}
}

func TestPortableKerberosSASLSubmittedWriteFailureRemainsUncertain(t *testing.T) {
	certificate, roots := portableKerberosTLSCertificate(t)
	for _, mode := range []ldap.SASLSecurityMode{ldap.SASLSecuritySign, ldap.SASLSecuritySeal} {
		for _, scenario := range []string{"tampered", "reordered", "truncated-prefix", "truncated-body", "plaintext"} {
			t.Run(fmt.Sprintf("layer=%d/%s", mode, scenario), func(t *testing.T) {
				kdc := newPortableKerberosKDC(t)
				wire := newPortableSASLWire(t, admodel.TransportLDAP, certificate, kdc, mode, 7, scenario,
					func(conn net.Conn, request *ber.Packet) error {
						_, err := conn.Write(portableLDAPResult(request, ldap.ApplicationDelResponse, 0).Bytes())
						return err
					})
				options := portableTLSConfig(admodel.TransportLDAP, roots)
				options.TLS = nil
				options.Authentication, options.Credentials, options.SASLProtection = admodel.AuthenticationKerberos, nil, admodel.SASLProtectionSign
				if mode == ldap.SASLSecuritySeal {
					options.SASLProtection = admodel.SASLProtectionSeal
				}
				options.Kerberos = portableKerberosSource(t, kdc, admodel.KerberosPassword, false)
				session, err := adengine.InternalDialPortableWithDial(t.Context(), options, wire)
				if err != nil {
					t.Fatal(err)
				}
				result := admodel.ObjectMutationResult{}
				writeErr := admodel.InternalSubmitObjectWrite(t.Context(), session.(admodel.InternalLdapWriteSession), admodel.InternalLdapWriteRequest{
					InternalOperation: admodel.InternalLdapWriteDelete, InternalDn: "CN=owned,DC=ad,DC=sdk,DC=test",
				}, false, &result)
				if result.State != admodel.ObjectWriteUncertain || admodel.Classify(writeErr) != admodel.ClassUncertain ||
					!errors.Is(writeErr, admodel.ErrConnection) || !errors.Is(writeErr, admodel.InternalLDAPWriteUncertainError()) {
					t.Fatalf("submitted write was hidden or inferred from an unverified response: %+v, %v", result, writeErr)
				}
				observed, err := session.(admodel.InternalSessionProtectionObserver).InternalSessionProtection(t.Context())
				if err == nil || observed.Complete || !observed.MutualAuthentication || observed.SASLProtection != options.SASLProtection {
					t.Fatal("poisoned stream still reported complete protection")
				}
				if _, err := session.InternalBaseObject(t.Context(), "CN=owned,DC=ad,DC=sdk,DC=test", []string{"name"}); !errors.Is(err, admodel.ErrClosed) {
					t.Fatal("poisoned stream accepted another operation")
				}
				wire.wait(t)
				if wire.requests.Load() != 4 {
					t.Fatal("failed submitted mutation was retried")
				}
			})
		}
	}
}

func TestPortableKerberosSASLDefaultAndUnofferedLayersHaveNoFallback(t *testing.T) {
	certificate, roots := portableKerberosTLSCertificate(t)
	for _, scenario := range []struct {
		name      string
		requested admodel.SASLProtection
		mode      ldap.SASLSecurityMode
		offer     byte
		accepted  bool
	}{
		{"default-seals-plain-ldap", admodel.SASLProtectionDefault, ldap.SASLSecuritySeal, 7, true},
		{"seal-refuses-sign-only", admodel.SASLProtectionSeal, ldap.SASLSecuritySeal, 2, false},
		{"sign-refuses-seal-only", admodel.SASLProtectionSign, ldap.SASLSecuritySign, 4, false},
	} {
		t.Run(scenario.name, func(t *testing.T) {
			kdc := newPortableKerberosKDC(t)
			payload := []byte("default-protected-control")
			wire := newPortableSASLWire(t, admodel.TransportLDAP, certificate, kdc, scenario.mode, scenario.offer, "", portableSASLReadStep(payload))
			options := portableTLSConfig(admodel.TransportLDAP, roots)
			options.TLS, options.Credentials, options.Authentication = nil, nil, admodel.AuthenticationKerberos
			options.SASLProtection = scenario.requested
			options.Kerberos = portableKerberosSource(t, kdc, admodel.KerberosPassword, false)
			session, err := adengine.InternalDialPortableWithDial(t.Context(), options, wire)
			if !scenario.accepted {
				if err == nil || session != nil {
					t.Fatal("unoffered exact layer yielded a usable session")
				}
				wire.wait(t)
				if wire.requests.Load() != 2 || wire.peer != nil || kdc.requests.Load() != 3 {
					t.Fatal("refused layer triggered an application request, authentication retry or fallback")
				}
				return
			}
			if err != nil {
				t.Fatal(err)
			}
			object, err := session.InternalBaseObject(t.Context(), "CN=owned,DC=ad,DC=sdk,DC=test", []string{"thumbnailPhoto"})
			if err != nil || len(object["thumbnailphoto"]) != 1 || !bytes.Equal(object["thumbnailphoto"][0], payload) {
				t.Fatalf("default did not establish usable sealing: %v", err)
			}
			observed, err := session.(admodel.InternalSessionProtectionObserver).InternalSessionProtection(t.Context())
			if err != nil || !observed.Complete || observed.SASLProtection != admodel.SASLProtectionSeal || observed.SASLCipherBits != 256 {
				t.Fatal("default plaintext protection did not report actual sealing")
			}
			if err := session.InternalClose(); err != nil {
				t.Fatal(err)
			}
			wire.wait(t)
		})
	}
}
