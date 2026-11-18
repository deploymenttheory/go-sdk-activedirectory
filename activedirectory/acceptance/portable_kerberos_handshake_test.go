package acceptance

import (
	"errors"
	"io"
	"net"
	"testing"

	ber "github.com/go-asn1-ber/asn1-ber"

	"github.com/deploymenttheory/go-sdk-activedirectory/3rd_party/gokrb5/v8/messages"
	ldap "github.com/deploymenttheory/go-sdk-activedirectory/3rd_party/ldap/v3"
	adengine "github.com/deploymenttheory/go-sdk-activedirectory/activedirectory/internal/engine"
	admodel "github.com/deploymenttheory/go-sdk-activedirectory/activedirectory/internal/model"
)

type portableKerberosCorruptWrite struct{ net.Conn }

func (c portableKerberosCorruptWrite) Write(data []byte) (int, error) {
	copy := append([]byte(nil), data...)
	copy[len(copy)-1] ^= 1
	return c.Conn.Write(copy)
}

func TestPortableKerberosFullHandshakeRefusalsAndMalformedAcknowledgementsNeverYieldSession(t *testing.T) {
	for _, scenario := range []string{"final-refusal", "early-success", "lost-final-response", "malformed-final-response", "bad-APREP-integrity", "unbound-APREP-time", "bad-offer-integrity"} {
		t.Run(scenario, func(t *testing.T) {
			certificate, roots := portableKerberosTLSCertificate(t)
			kdc := newPortableKerberosKDC(t)
			acceptor := newPortableKerberosAcceptor(t, kdc, certificate.Leaf, func(a *portableKerberosAcceptor) {
				if scenario == "unbound-APREP-time" {
					a.mutateReply = func(part *messages.EncAPRepPart) { part.Cusec = (part.Cusec + 1) % 1000000 }
				}
			})
			first := portableLDAPStep(acceptor.authenticate)
			offer := portableLDAPStep(acceptor.offer)
			final := portableLDAPStep(acceptor.accept)
			wantRequests := int32(3)
			switch scenario {
			case "early-success":
				first = func(conn net.Conn, request *ber.Packet) error {
					return portableKerberosBindReply(conn, request, 0, nil)
				}
				wantRequests = 1
			case "bad-APREP-integrity":
				first = func(conn net.Conn, request *ber.Packet) error {
					return acceptor.authenticate(portableKerberosCorruptWrite{conn}, request)
				}
				wantRequests = 1
			case "unbound-APREP-time":
				wantRequests = 1
			case "bad-offer-integrity":
				offer = func(conn net.Conn, request *ber.Packet) error {
					return acceptor.offer(portableKerberosCorruptWrite{conn}, request)
				}
				wantRequests = 2
			case "final-refusal":
				final = func(conn net.Conn, request *ber.Packet) error {
					return portableKerberosBindReply(conn, request, 49, nil)
				}
			case "lost-final-response":
				final = func(net.Conn, *ber.Packet) error { return io.EOF }
			case "malformed-final-response":
				final = func(conn net.Conn, request *ber.Packet) error {
					result := ber.Encode(ber.ClassApplication, ber.TypeConstructed, ldap.ApplicationBindResponse, nil, "")
					result.AppendChild(ber.NewInteger(ber.ClassUniversal, ber.TypePrimitive, ber.TagEnumerated, 0, ""))
					result.AppendChild(ber.NewInteger(ber.ClassUniversal, ber.TypePrimitive, ber.TagInteger, 0, ""))
					result.AppendChild(ber.NewString(ber.ClassUniversal, ber.TypePrimitive, ber.TagOctetString, "", ""))
					_, err := conn.Write(portableLDAPEnvelope(request, result).Bytes())
					return err
				}
			}
			steps := []portableLDAPStep{first, offer, final}
			steps = steps[:wantRequests]
			wire := newPortableLDAPWire(t, admodel.TransportLDAPS, certificate, steps...)
			options := portableTLSConfig(admodel.TransportLDAPS, roots)
			options.Authentication, options.Credentials = admodel.AuthenticationKerberos, nil
			options.Kerberos = portableKerberosSource(t, kdc, admodel.KerberosPassword, false)
			session, err := adengine.InternalDialPortableWithDial(t.Context(), options, portableKerberosDialer{ldap: wire, kdc: kdc})
			if session != nil || err == nil {
				t.Fatal("unproved or unacknowledged Kerberos authentication returned a session")
			}
			var server *admodel.LDAPError
			if scenario == "final-refusal" {
				if !errors.As(err, &server) || server.Code != 49 || admodel.Classify(err) != admodel.ClassDenied {
					t.Fatalf("actual final refusal lost its status: %v", err)
				}
			} else if errors.As(err, &server) {
				t.Fatalf("unproved authentication manufactured an LDAP refusal: %v", err)
			}
			if scenario == "malformed-final-response" && !errors.Is(err, admodel.ErrInvalidResult) {
				t.Fatalf("malformed success lost protocol identity: %v", err)
			}
			wire.wait(t)
			if kdc.requests.Load() != 3 || wire.requests.Load() != wantRequests {
				t.Fatal("failed authentication retried or submitted an application operation")
			}
		})
	}
}
