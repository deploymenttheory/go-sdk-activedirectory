package acceptance

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"io"
	"net"
	"strings"
	"testing"

	ber "github.com/go-asn1-ber/asn1-ber"

	ldap "github.com/deploymenttheory/go-sdk-activedirectory/3rd_party/ldap/v3"
	adengine "github.com/deploymenttheory/go-sdk-activedirectory/activedirectory/internal/engine"
	admodel "github.com/deploymenttheory/go-sdk-activedirectory/activedirectory/internal/model"
)

func TestPortableLDAPBinaryPagingLimitReleasesCookieAndMeasuresBind(t *testing.T) {
	certificate, roots := portableTLSCertificate(t, portableTLSHost, false, false)
	for _, transport := range []admodel.Transport{admodel.TransportLDAPS, admodel.TransportStartTLS} {
		t.Run(fmt.Sprint(transport), func(t *testing.T) {
			cookie := []byte{0, 0xff, 3}
			value := []byte{0, 0xff, 0x80, 0, 42}
			wire := newPortableLDAPWire(t, transport, certificate, portableLDAPBind(0),
				func(connection net.Conn, request *ber.Packet) error {
					size, previous, err := portableLDAPPaging(request)
					if err != nil || size != 1 || len(previous) != 0 {
						return fmt.Errorf("first bounded page: %v size=%d", err, size)
					}
					if _, err := connection.Write(portableLDAPEntry(request, map[string][][]byte{"objectGUID": {value}}).Bytes()); err != nil {
						return err
					}
					_, err = connection.Write(portableLDAPResult(request, ldap.ApplicationSearchResultDone, 0, &ldap.ControlPaging{Cookie: cookie}).Bytes())
					return err
				}, func(connection net.Conn, request *ber.Packet) error {
					size, previous, err := portableLDAPPaging(request)
					if err != nil || size != 0 || !bytes.Equal(previous, cookie) {
						return fmt.Errorf("last cookie not explicitly released: %v", err)
					}
					_, err = connection.Write(portableLDAPResult(request, ldap.ApplicationSearchResultDone, 0, &ldap.ControlPaging{}).Bytes())
					return err
				})
			options := portableTLSConfig(transport, roots)
			_, client := portableLDAPSession(t, options, wire)
			observed, err := client.Protection(t.Context())
			if err != nil || !observed.Complete || !observed.TLSVerified || observed.Authentication != admodel.AuthenticationSimple ||
				observed.SASLProtection != admodel.SASLProtectionNone ||
				observed.ChannelBound ||
				observed.Delegated ||
				observed.MutualAuthentication ||
				observed.CipherBits < 128 {
				t.Fatalf("inaccurate bind/protection observation: %+v %v", observed, err)
			}
			result, err := client.Search(
				t.Context(),
				admodel.SearchOptions{Base: "DC=ad,DC=sdk,DC=test", Scope: admodel.ScopeSubtree, PageSize: 2, ResultLimit: 1, Properties: []string{"objectGUID"}},
			)
			if err != nil || result.Complete || !result.LimitReached || len(result.Objects) != 1 || !bytes.Equal(result.Objects[0].Attributes["objectguid"][0], value) {
				t.Fatalf("binary/limit result: %+v %v", result, err)
			}
			if err := client.Close(); err != nil {
				t.Fatal(err)
			}
			wire.wait(t)
			if wire.requests.Load() != 3 {
				t.Fatalf("replayed or missing request: %d", wire.requests.Load())
			}
		})
	}
}

func TestPortableLDAPBindRefusalPreservesStatusAndRedactsDiagnostics(t *testing.T) {
	certificate, roots := portableTLSCertificate(t, portableTLSHost, false, false)
	wire := newPortableLDAPWire(t, admodel.TransportLDAPS, certificate, portableLDAPBind(49))
	session, err := adengine.InternalDialPortableWithDial(t.Context(), portableTLSConfig(admodel.TransportLDAPS, roots), wire)
	var server *admodel.LDAPError
	if session != nil || !errors.As(err, &server) || server.Code != 49 || server.Diagnostic == "" || admodel.Classify(err) != admodel.ClassDenied ||
		strings.Contains(err.Error(), "owned-private-diagnostic") {
		t.Fatalf("imprecise or unredacted bind refusal: %v", err)
	}
	wire.wait(t)
	if wire.requests.Load() != 1 {
		t.Fatal("refused authentication retried")
	}
}

func TestPortableLDAPPartialRefusedSearchKeepsBinaryObservation(t *testing.T) {
	certificate, roots := portableTLSCertificate(t, portableTLSHost, false, false)
	wire := newPortableLDAPWire(t, admodel.TransportLDAPS, certificate, portableLDAPBind(0), func(connection net.Conn, request *ber.Packet) error {
		if _, err := connection.Write(portableLDAPEntry(request, map[string][][]byte{"name": {[]byte("owned")}}).Bytes()); err != nil {
			return err
		}
		_, err := connection.Write(portableLDAPResult(request, ldap.ApplicationSearchResultDone, 50).Bytes())
		return err
	})
	_, client := portableLDAPSession(t, portableTLSConfig(admodel.TransportLDAPS, roots), wire)
	result, err := client.Search(t.Context(), admodel.SearchOptions{Base: "DC=ad,DC=sdk,DC=test", Scope: admodel.ScopeSubtree})
	var server *admodel.LDAPError
	if err == nil || result.Complete || len(result.Objects) != 1 || !errors.As(err, &server) || server.Code != 50 {
		t.Fatalf("partial refusal was lost: %+v %v", result, err)
	}
	_ = client.Close()
	wire.wait(t)
}

func TestPortableLDAPMalformedSearchPreservesObservationAndRetires(t *testing.T) {
	certificate, roots := portableTLSCertificate(t, portableTLSHost, false, false)
	wire := newPortableLDAPWire(t, admodel.TransportLDAPS, certificate, portableLDAPBind(0), func(connection net.Conn, request *ber.Packet) error {
		if _, err := connection.Write(portableLDAPEntry(request, map[string][][]byte{"name": {[]byte("owned")}}).Bytes()); err != nil {
			return err
		}
		malformed := ber.Encode(ber.ClassApplication, ber.TypeConstructed, ldap.ApplicationSearchResultEntry, nil, "")
		_, err := connection.Write(portableLDAPEnvelope(request, malformed).Bytes())
		return err
	})
	session, client := portableLDAPSession(t, portableTLSConfig(admodel.TransportLDAPS, roots), wire)
	result, err := client.Search(t.Context(), admodel.SearchOptions{Base: "DC=ad,DC=sdk,DC=test", Scope: admodel.ScopeSubtree})
	if err == nil || result.Complete || len(result.Objects) != 1 || !errors.Is(err, admodel.ErrInvalidResult) || !errors.Is(err, admodel.ErrConnection) {
		t.Fatalf("malformed response looked complete: %+v %v", result, err)
	}
	if _, err := session.InternalBaseObject(t.Context(), "", nil); !errors.Is(err, admodel.ErrClosed) {
		t.Fatalf("malformed session reused: %v", err)
	}
	_ = client.Close()
	wire.wait(t)
}

func TestPortableLDAPRangedAndOrdinaryBaseReadsRemainDistinct(t *testing.T) {
	certificate, roots := portableTLSCertificate(t, portableTLSHost, false, false)
	response := func(connection net.Conn, request *ber.Packet) error {
		if request.Children[1].Children[1].Value != int64(ldap.ScopeBaseObject) {
			return fmt.Errorf("ranged read was not base-scoped")
		}
		if _, err := connection.Write(portableLDAPEntry(request, map[string][][]byte{"member;range=0-*": {[]byte("CN=member,DC=ad,DC=sdk,DC=test")}}).Bytes()); err != nil {
			return err
		}
		_, err := connection.Write(portableLDAPResult(request, ldap.ApplicationSearchResultDone, 0).Bytes())
		return err
	}
	wire := newPortableLDAPWire(t, admodel.TransportLDAPS, certificate, portableLDAPBind(0), response, response)
	session, client := portableLDAPSession(t, portableTLSConfig(admodel.TransportLDAPS, roots), wire)
	attributes, err := session.InternalRangedBaseObject(t.Context(), "CN=owned,DC=ad,DC=sdk,DC=test", []string{"member;range=0-*"})
	if err != nil || len(attributes["member;range=0-*"]) != 1 {
		t.Fatalf("raw range description lost: %v %v", attributes, err)
	}
	if _, err := session.InternalBaseObject(t.Context(), "CN=owned,DC=ad,DC=sdk,DC=test", []string{"member"}); !errors.Is(err, admodel.ErrIncompleteResult) {
		t.Fatalf("ordinary read accepted a partial range: %v", err)
	}
	_ = client.Close()
	wire.wait(t)
}

func TestPortableLDAPWriteOutcomesRemainDistinctAndNeverReplay(t *testing.T) {
	for _, name := range []string{
		"accepted", "accepted-with-control", "rejected", "malformed-result", "malformed-utf8-success", "malformed-utf8-refusal", "empty-result-code",
		"malformed-trailing-result", "malformed-response-control",
		"wrong-response", "wrong-message-id", "lost-response", "truncated-response", "cancelled",
	} {
		t.Run(name, func(t *testing.T) {
			certificate, roots := portableTLSCertificate(t, portableTLSHost, false, false)
			received := make(chan struct{})
			wire := newPortableLDAPWire(t, admodel.TransportLDAPS, certificate, portableLDAPBind(0), func(connection net.Conn, request *ber.Packet) error {
				if request.Children[1].Tag != ldap.ApplicationModifyRequest {
					return fmt.Errorf("write was not a modify")
				}
				close(received)
				switch name {
				case "lost-response":
					return io.EOF
				case "truncated-response":
					_, err := connection.Write([]byte{0x30, 0x82, 0x01})
					if err != nil {
						return err
					}
					return io.EOF
				case "cancelled":
					_, err := io.Copy(io.Discard, connection)
					return err
				}
				tag, code := ber.Tag(ldap.ApplicationModifyResponse), int64(0)
				if name == "rejected" {
					code = 50
				}
				if name == "wrong-response" {
					tag = ldap.ApplicationSearchResultDone
				}
				if name == "malformed-trailing-result" {
					result := portableLDAPResult(request, tag, code).Children[1]
					result.AppendChild(ber.NewInteger(ber.ClassUniversal, ber.TypePrimitive, ber.TagInteger, 0, "unexpected trailing field"))
					_, err := connection.Write(portableLDAPEnvelope(request, result).Bytes())
					return err
				}
				if name == "malformed-response-control" {
					envelope := portableLDAPResult(request, tag, code)
					controls := ber.Encode(ber.ClassContext, ber.TypeConstructed, 0, nil, "")
					control := ber.NewSequence("")
					control.AppendChild(ber.NewInteger(ber.ClassUniversal, ber.TypePrimitive, ber.TagInteger, 0, "invalid control OID"))
					controls.AppendChild(control)
					envelope.AppendChild(controls)
					_, err := connection.Write(envelope.Bytes())
					return err
				}
				if name == "accepted-with-control" {
					_, err := connection.Write(portableLDAPResult(request, tag, code, ldap.NewControlString("1.2.3.4", false, string([]byte{0, 0xff, 0x80}))).Bytes())
					return err
				}
				if name == "malformed-result" {
					result := ber.Encode(ber.ClassApplication, ber.TypeConstructed, ldap.ApplicationModifyResponse, nil, "")
					result.AppendChild(ber.NewInteger(ber.ClassUniversal, ber.TypePrimitive, ber.TagEnumerated, 0, ""))
					result.AppendChild(ber.NewInteger(ber.ClassUniversal, ber.TypePrimitive, ber.TagInteger, 0, "invalid matchedDN"))
					result.AppendChild(ber.NewString(ber.ClassUniversal, ber.TypePrimitive, ber.TagOctetString, "", ""))
					_, err := connection.Write(portableLDAPEnvelope(request, result).Bytes())
					return err
				}
				if name == "malformed-utf8-success" || name == "malformed-utf8-refusal" || name == "empty-result-code" {
					result := ber.Encode(ber.ClassApplication, ber.TypeConstructed, ldap.ApplicationModifyResponse, nil, "")
					status, matchedDN, diagnostic := int64(0), "", ""
					if name == "malformed-utf8-success" {
						matchedDN = string([]byte{0xff})
					} else if name == "malformed-utf8-refusal" {
						status, diagnostic = 50, string([]byte{0xff})
					}
					if name == "empty-result-code" {
						result.AppendChild(ber.Encode(ber.ClassUniversal, ber.TypePrimitive, ber.TagEnumerated, nil, ""))
					} else {
						result.AppendChild(ber.NewInteger(ber.ClassUniversal, ber.TypePrimitive, ber.TagEnumerated, status, ""))
					}
					result.AppendChild(ber.NewString(ber.ClassUniversal, ber.TypePrimitive, ber.TagOctetString, matchedDN, ""))
					result.AppendChild(ber.NewString(ber.ClassUniversal, ber.TypePrimitive, ber.TagOctetString, diagnostic, ""))
					_, err := connection.Write(portableLDAPEnvelope(request, result).Bytes())
					return err
				}
				if name == "wrong-message-id" {
					wrong := portableLDAPResult(request, tag, code)
					wrong.Children[0] = ber.NewInteger(ber.ClassUniversal, ber.TypePrimitive, ber.TagInteger, request.Children[0].Value.(int64)+100, "")
					// Re-encode rather than reusing the already-built sequence data.
					wrongEnvelope := ber.Encode(ber.ClassUniversal, ber.TypeConstructed, ber.TagSequence, nil, "")
					for _, child := range wrong.Children {
						wrongEnvelope.AppendChild(child)
					}
					if _, err := connection.Write(wrongEnvelope.Bytes()); err != nil {
						return err
					}
				}
				_, err := connection.Write(portableLDAPResult(request, tag, code).Bytes())
				return err
			})
			session, client := portableLDAPSession(t, portableTLSConfig(admodel.TransportLDAPS, roots), wire)
			writer := session.(admodel.InternalLdapWriteSession)
			request := admodel.InternalLdapWriteRequest{
				InternalOperation: admodel.InternalLdapWriteModify,
				InternalDn:        "CN=owned,DC=ad,DC=sdk,DC=test",
				InternalModifications: []admodel.InternalLdapAttributeModification{
					{InternalOperation: 2, InternalAttribute: "jpegPhoto", InternalValues: [][]byte{{0, 0xff, 0x80}}},
				},
			}
			ctx, cancel := context.WithCancel(t.Context())
			defer cancel()
			if name == "cancelled" {
				go func() { <-received; cancel() }()
			}
			attempt := writer.InternalLdapWrite(ctx, request)
			switch name {
			case "accepted", "accepted-with-control":
				if attempt.State != admodel.InternalLdapWriteAccepted || attempt.Err != nil {
					t.Fatalf("accepted effect lost: %+v", attempt)
				}
			case "rejected":
				var refusal *admodel.LDAPError
				if attempt.State != admodel.InternalLdapWriteRejected || !errors.As(attempt.Err, &refusal) || refusal.Code != 50 {
					t.Fatalf("refusal became uncertain or accepted: %+v", attempt)
				}
			default:
				if attempt.State != admodel.InternalLdapWriteUncertain || !errors.Is(attempt.Err, admodel.InternalLDAPWriteUncertainError()) {
					t.Fatalf("unknown effect became definitive: %+v", attempt)
				}
				if strings.HasPrefix(name, "malformed-") || name == "empty-result-code" {
					var synthetic *admodel.LDAPError
					if !errors.Is(attempt.Err, admodel.ErrInvalidResult) || errors.As(attempt.Err, &synthetic) {
						t.Fatalf("malformed response became a synthetic server status: %v", attempt.Err)
					}
				}
				if name == "cancelled" && !errors.Is(attempt.Err, context.Canceled) {
					t.Fatalf("cancellation cause lost: %v", attempt.Err)
				}
				if _, err := session.InternalBaseObject(t.Context(), "", nil); !errors.Is(err, admodel.ErrClosed) {
					t.Fatalf("uncertain session reused: %v", err)
				}
			}
			_ = client.Close()
			wire.wait(t)
			if wire.requests.Load() != 2 {
				t.Fatalf("mutation replayed: %d", wire.requests.Load())
			}
		})
	}
}
