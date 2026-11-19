package acceptance

import (
	"bytes"
	"errors"
	"net"
	"os"
	"testing"
	"time"

	ber "github.com/go-asn1-ber/asn1-ber"

	"github.com/deploymenttheory/go-sdk-activedirectory/3rd_party/gokrb5/v8/iana/flags"
	"github.com/deploymenttheory/go-sdk-activedirectory/3rd_party/gokrb5/v8/messages"
	"github.com/deploymenttheory/go-sdk-activedirectory/3rd_party/gokrb5/v8/types"
	ldap "github.com/deploymenttheory/go-sdk-activedirectory/3rd_party/ldap/v3"
	adengine "github.com/deploymenttheory/go-sdk-activedirectory/activedirectory/internal/engine"
	admodel "github.com/deploymenttheory/go-sdk-activedirectory/activedirectory/internal/model"
)

func TestPortableDelegationCannotFallBackAfterFreshKDCRefusal(t *testing.T) {
	certificate, roots := portableKerberosTLSCertificate(t)
	for _, fault := range []string{"service-policy", "forwarded", "forwardable", "nonce", "realm", "expired", "KDC-refusal"} {
		t.Run(fault, func(t *testing.T) {
			kdc := newPortableKerberosKDC(t, func(k *portableKerberosKDC) {
				k.delegation = true
				if fault == "KDC-refusal" {
					k.refuseTGS = 13
				}
				k.mutateIssuedPart = func(request messages.KDCReqFields, part *messages.EncKDCRepPart) {
					if fault == "service-policy" && request.ReqBody.SName.PrincipalNameString() == "ldap/"+portableTLSHost {
						types.UnsetFlag(&part.Flags, flags.OKAsDelegate)
					}
					if !types.IsFlagSet(&request.ReqBody.KDCOptions, flags.Forwarded) {
						return
					}
					switch fault {
					case "forwarded":
						types.UnsetFlag(&part.Flags, flags.Forwarded)
					case "forwardable":
						types.UnsetFlag(&part.Flags, flags.Forwardable)
					case "nonce":
						part.Nonce++
					case "realm":
						part.SRealm = "OTHER.TEST"
					case "expired":
						part.EndTime = time.Now().Add(-time.Minute)
					}
				}
			})
			// No LDAP request is expected: policy failures happen before AP emission.
			wire := newPortableLDAPWire(t, admodel.TransportLDAPS, certificate)
			options := portableTLSConfig(admodel.TransportLDAPS, roots)
			options.Authentication, options.Credentials, options.AllowDelegation = admodel.AuthenticationKerberos, nil, true
			options.Kerberos = portableKerberosSource(t, kdc, admodel.KerberosCredentialCacheFile, true)
			before, err := os.ReadFile(options.Kerberos.CachePath)
			if err != nil {
				t.Fatal(err)
			}
			defer clear(before)
			session, err := adengine.InternalDialPortableWithDial(t.Context(), options, portableKerberosDialer{ldap: wire, kdc: kdc})
			if err == nil || session != nil || wire.requests.Load() != 0 || kdc.requests.Load() > 2 {
				t.Fatal("required delegation returned a session, emitted LDAP intent or retried weaker authentication")
			}
			if fault == "KDC-refusal" {
				var protocol messages.KRBError
				if !errors.As(err, &protocol) || protocol.ErrorCode != 13 {
					t.Fatal("actual KDC refusal cause was lost")
				}
			}
			after, readErr := os.ReadFile(options.Kerberos.CachePath)
			if readErr != nil || !bytes.Equal(before, after) {
				t.Fatal("refused delegation modified the caller cache")
			}
			clear(after)
			wire.wait(t)
		})
	}
}

func TestPortableDelegationRequiresFinalLDAPAcceptance(t *testing.T) {
	certificate, roots := portableKerberosTLSCertificate(t)
	for _, fault := range []string{"refused", "lost", "wrong-operation", "invalid-mutual"} {
		t.Run(fault, func(t *testing.T) {
			kdc := newPortableKerberosKDC(t, func(k *portableKerberosKDC) {
				k.delegation = true
				k.inspectAP = func(ap *messages.APReq) error { return verifyPortableForwarding(k, ap) }
			})
			acceptor := newPortableKerberosAcceptor(t, kdc, certificate.Leaf)
			if fault == "invalid-mutual" {
				acceptor.mutateReply = func(part *messages.EncAPRepPart) { part.Cusec++ }
			}
			steps := []portableLDAPStep{acceptor.authenticate}
			if fault != "invalid-mutual" {
				steps = append(steps, acceptor.offer, func(conn net.Conn, request *ber.Packet) error {
					if err := acceptor.verifySelection(request); err != nil {
						return err
					}
					switch fault {
					case "lost":
						return conn.Close()
					case "wrong-operation":
						_, err := conn.Write(portableLDAPResult(request, ldap.ApplicationModifyResponse, 0).Bytes())
						return err
					default:
						return portableKerberosBindReply(conn, request, 49, nil)
					}
				})
			}
			wire := newPortableLDAPWire(t, admodel.TransportLDAPS, certificate, steps...)
			options := portableTLSConfig(admodel.TransportLDAPS, roots)
			options.Authentication, options.Credentials, options.AllowDelegation = admodel.AuthenticationKerberos, nil, true
			options.Kerberos = portableKerberosSource(t, kdc, admodel.KerberosPassword, false)
			session, err := adengine.InternalDialPortableWithDial(t.Context(), options, portableKerberosDialer{ldap: wire, kdc: kdc})
			if err == nil || session != nil || kdc.requests.Load() != 4 || wire.requests.Load() != int32(len(steps)) {
				t.Fatal("incomplete delegated bind returned a usable session or replayed authentication")
			}
			if fault == "refused" {
				var status *admodel.LDAPError
				if !errors.As(err, &status) || status.Code != 49 {
					t.Fatal("actual server authentication status was lost")
				}
			}
			wire.wait(t)
		})
	}
}

func TestPortableDelegationExpiresWithForwardedTGTEvenWhenServiceTicketLives(t *testing.T) {
	certificate, roots := portableKerberosTLSCertificate(t)
	expiry := time.Now().UTC().Add(3 * time.Second).Truncate(time.Second)
	kdc := newPortableKerberosKDC(t, func(k *portableKerberosKDC) {
		k.delegation = true
		k.inspectAP = func(ap *messages.APReq) error { return verifyPortableForwarding(k, ap) }
		k.ticketEnd = func(request messages.KDCReqFields, normal time.Time) time.Time {
			if types.IsFlagSet(&request.ReqBody.KDCOptions, flags.Forwarded) {
				return expiry
			}
			return normal
		}
	})
	acceptor := newPortableKerberosAcceptor(t, kdc, certificate.Leaf)
	wire := newPortableLDAPWire(t, admodel.TransportLDAPS, certificate, acceptor.authenticate, acceptor.offer, acceptor.accept)
	options := portableTLSConfig(admodel.TransportLDAPS, roots)
	options.Authentication, options.Credentials, options.AllowDelegation = admodel.AuthenticationKerberos, nil, true
	options.Kerberos = portableKerberosSource(t, kdc, admodel.KerberosPassword, false)
	session, err := adengine.InternalDialPortableWithDial(t.Context(), options, portableKerberosDialer{ldap: wire, kdc: kdc})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = session.InternalClose() })
	before, err := session.(admodel.InternalMoveSecuritySession).InternalMoveSecurity(t.Context())
	if err != nil || !before.Complete || !before.Protection.DelegationExpiresAt.Equal(expiry) {
		t.Fatal("actual forwarded TGT lifetime was not observed")
	}
	timer := time.NewTimer(time.Until(expiry) + 10*time.Millisecond)
	defer timer.Stop()
	select {
	case <-timer.C:
	case <-t.Context().Done():
		t.Fatal(t.Context().Err())
	}
	after, err := session.(admodel.InternalMoveSecuritySession).InternalMoveSecurity(t.Context())
	if !errors.Is(err, admodel.ErrKerberosExpired) || !errors.Is(err, admodel.ErrMoveDelegation) || after.Complete || wire.requests.Load() != 3 {
		t.Fatal("expired forwarded TGT authorized a move or caused an application retry")
	}
	wire.wait(t)
}
