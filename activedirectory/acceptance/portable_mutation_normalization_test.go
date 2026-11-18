package acceptance

import (
	"bytes"
	"errors"
	"fmt"
	"io"
	"net"
	"testing"

	ber "github.com/go-asn1-ber/asn1-ber"

	ldap "github.com/deploymenttheory/go-sdk-activedirectory/3rd_party/ldap/v3"
	admodel "github.com/deploymenttheory/go-sdk-activedirectory/activedirectory/internal/model"
	users "github.com/deploymenttheory/go-sdk-activedirectory/activedirectory/services/users"
)

const portableMutationDomain = "DC=ad,DC=sdk,DC=test"

func TestPortableTypedUserDNNormalizationRetainsAcceptedProjection(t *testing.T) {
	certificate, roots := portableTLSCertificate(t, portableTLSHost, false, false)
	requested, returned := "cn=manager,"+portableMutationDomain, "CN=manager,"+portableMutationDomain
	wire := newPortableLDAPWire(t, admodel.TransportLDAPS, certificate,
		portableLDAPBind(0), portableMutationRoot(), portableMutationObject(nil),
		func(connection net.Conn, request *ber.Packet) error {
			if request.Children[1].Tag != ldap.ApplicationModifyRequest {
				return fmt.Errorf("typed user normalization fixture expected one mutation")
			}
			_, err := connection.Write(portableLDAPResult(request, ldap.ApplicationModifyResponse, 0).Bytes())
			return err
		}, portableMutationObject(map[string][][]byte{"manager": {[]byte(returned)}}), portableMutationDNSchema("manager"))
	_, client := portableLDAPSession(t, portableTLSConfig(admodel.TransportLDAPS, roots), wire)
	identity, err := admodel.IdentityByDN("CN=owned," + portableMutationDomain)
	if err != nil {
		t.Fatal(err)
	}
	result, err := users.New(client).UpdateUser(t.Context(), users.UpdateUserRequest{
		Identity: identity, Properties: users.UserProperties{ManagerDN: &requested},
	})
	if !errors.Is(err, admodel.ErrObjectUnverifiable) || admodel.Classify(err) != admodel.ClassUnverified ||
		result.Mutation.State != admodel.ObjectWriteAccepted || result.Mutation.Verified || result.Mutation.TargetGUID == nil ||
		result.User == nil || result.User.ManagerDN == nil || *result.User.ManagerDN != returned {
		t.Fatal("typed user normalization lost accepted state or directory projection", result, err)
	}
	_ = client.Close()
	wire.wait(t)
	if wire.requests.Load() != 6 {
		t.Fatal("typed normalized mutation was replayed or schema evidence skipped", wire.requests.Load())
	}
}

func TestPortableFailedSchemaObservationPreservesAcceptedWrite(t *testing.T) {
	for _, mode := range []string{"partial", "missing", "lost", "malformed"} {
		t.Run(mode, func(t *testing.T) {
			certificate, roots := portableTLSCertificate(t, portableTLSHost, false, false)
			requested, returned := "cn=manager,"+portableMutationDomain, "CN=manager,"+portableMutationDomain
			metadata := map[string][][]byte{
				"lDAPDisplayName": {[]byte("manager")}, "attributeSyntax": {[]byte("2.5.5.1")}, "oMSyntax": {[]byte("127")},
				"oMObjectClass": {{0x2b, 0x0c, 2, 0x87, 0x73, 0x1c, 0, 0x85, 0x4a}},
			}
			if mode == "missing" {
				delete(metadata, "oMObjectClass")
			}
			schema := portableMutationSchema("manager", metadata, mode == "partial")
			if mode == "lost" || mode == "malformed" {
				schema = func(connection net.Conn, request *ber.Packet) error {
					if mode == "lost" {
						return io.EOF
					}
					malformed := ber.Encode(ber.ClassApplication, ber.TypeConstructed, ldap.ApplicationSearchResultEntry, nil, "")
					_, err := connection.Write(portableLDAPEnvelope(request, malformed).Bytes())
					return err
				}
			}
			wire := newPortableLDAPWire(t, admodel.TransportLDAPS, certificate,
				portableLDAPBind(0), portableMutationRoot(), portableMutationObject(nil),
				func(connection net.Conn, request *ber.Packet) error {
					if request.Children[1].Tag != ldap.ApplicationModifyRequest {
						return fmt.Errorf("schema failure fixture expected one mutation")
					}
					_, err := connection.Write(portableLDAPResult(request, ldap.ApplicationModifyResponse, 0).Bytes())
					return err
				}, portableMutationObject(map[string][][]byte{"manager": {[]byte(returned)}}), schema)
			session, client := portableLDAPSession(t, portableTLSConfig(admodel.TransportLDAPS, roots), wire)
			identity, err := admodel.IdentityByDN("CN=owned," + portableMutationDomain)
			if err != nil {
				t.Fatal(err)
			}
			result, err := client.UpdateObject(t.Context(), admodel.UpdateObjectRequest{
				Identity: identity, Changes: []admodel.AttributeChange{{
					Attribute: "manager", Kind: admodel.AttributeSet, Values: []admodel.RawValue{admodel.NewRawValue([]byte(requested))},
				}},
			})
			if !errors.Is(err, admodel.ErrObjectVerification) || errors.Is(err, admodel.ErrObjectUnverifiable) ||
				result.State != admodel.ObjectWriteAccepted || result.Verified || !result.ReadbackComplete || result.After == nil || result.TargetGUID == nil {
				t.Fatal("failed schema observation erased accepted effect or inferred normalization", result, err)
			}
			if mode == "partial" {
				var status *admodel.LDAPError
				if !errors.As(err, &status) || status.Code != 50 || !errors.Is(err, admodel.ErrIncompleteResult) {
					t.Fatal("partial metadata refusal lost its actual status", err)
				}
			}
			if mode == "lost" || mode == "malformed" {
				attempt := session.(admodel.InternalLdapWriteSession).InternalLdapWrite(t.Context(), admodel.InternalLdapWriteRequest{
					InternalOperation: admodel.InternalLdapWriteDelete, InternalDn: "<GUID=00000000000000000000000000000000>",
				})
				if attempt.State != admodel.InternalLdapWriteNotAttempted || !errors.Is(attempt.Err, admodel.ErrClosed) {
					t.Fatal("lost/malformed metadata session allowed another write", attempt)
				}
			}
			_ = client.Close()
			wire.wait(t)
			if wire.requests.Load() != 6 {
				t.Fatal("accepted write or failed metadata lookup was replayed", wire.requests.Load())
			}
		})
	}
}

func TestPortableAcceptedDNNormalizationIsUnverifiedRatherThanUncertain(t *testing.T) {
	certificate, roots := portableTLSCertificate(t, portableTLSHost, false, false)
	requested := "cn=manager," + portableMutationDomain
	returned := "CN=manager," + portableMutationDomain
	wire := newPortableLDAPWire(t, admodel.TransportLDAPS, certificate,
		portableLDAPBind(0), portableMutationRoot(), portableMutationObject(nil),
		func(connection net.Conn, request *ber.Packet) error {
			protocol := request.Children[1]
			if protocol.Tag != ldap.ApplicationModifyRequest || len(protocol.Children) != 2 || len(protocol.Children[1].Children) != 1 ||
				protocol.Children[0].Value != "<GUID=00000000000000000000000000000000>" {
				return fmt.Errorf("normalized-value fixture expected one GUID-addressed Modify")
			}
			change := protocol.Children[1].Children[0]
			if change.Children[0].Value != int64(2) || change.Children[1].Children[0].Value != "manager" ||
				!bytes.Equal(change.Children[1].Children[1].Children[0].Data.Bytes(), []byte(requested)) {
				return fmt.Errorf("SDK changed the caller's requested value before submission")
			}
			_, err := connection.Write(portableLDAPResult(request, ldap.ApplicationModifyResponse, 0).Bytes())
			return err
		}, portableMutationObject(map[string][][]byte{"manager": {[]byte(returned)}}), portableMutationDNSchema("manager"))
	_, client := portableLDAPSession(t, portableTLSConfig(admodel.TransportLDAPS, roots), wire)
	identity, err := admodel.IdentityByDN("CN=owned," + portableMutationDomain)
	if err != nil {
		t.Fatal(err)
	}
	result, err := client.UpdateObject(t.Context(), admodel.UpdateObjectRequest{
		Identity: identity, Changes: []admodel.AttributeChange{{
			Attribute: "manager", Kind: admodel.AttributeSet, Values: []admodel.RawValue{admodel.NewRawValue([]byte(requested))},
		}},
	})
	if !errors.Is(err, admodel.ErrObjectUnverifiable) || errors.Is(err, admodel.ErrObjectVerification) ||
		admodel.Classify(err) != admodel.ClassUnverified || result.State != admodel.ObjectWriteAccepted || result.Verified ||
		!result.ReadbackComplete || result.TargetGUID == nil || result.After == nil || result.Before == nil {
		t.Fatal("accepted normalization lost its stable identity or reported uncertainty", result, err)
	}
	value, err := result.After.Values("manager").Single()
	if err != nil || string(value.Bytes()) != returned {
		t.Fatal("normalized directory bytes were not retained", err)
	}
	_ = client.Close()
	wire.wait(t)
	if wire.requests.Load() != 6 {
		t.Fatal("normalized write was repeated or bypassed schema evidence", wire.requests.Load())
	}
}

func portableMutationRoot(controls ...string) portableLDAPStep {
	return func(connection net.Conn, request *ber.Packet) error {
		if request.Children[1].Tag != ldap.ApplicationSearchRequest || request.Children[1].Children[0].Value != "" {
			return fmt.Errorf("mutation fixture expected RootDSE")
		}
		attributes := map[string][][]byte{
			"supportedCapabilities": {[]byte(admodel.CapabilityActiveDirectory)}, "defaultNamingContext": {[]byte(portableMutationDomain)},
			"schemaNamingContext": {[]byte("CN=Schema,CN=Configuration," + portableMutationDomain)},
			"namingContexts":      {[]byte(portableMutationDomain)},
		}
		for _, control := range controls {
			attributes["supportedControl"] = append(attributes["supportedControl"], []byte(control))
		}
		return portableReaderSearchResponse(connection, request, "", attributes, false, false)
	}
}

func portableMutationObject(extra map[string][][]byte) portableLDAPStep {
	return func(connection net.Conn, request *ber.Packet) error {
		if request.Children[1].Tag != ldap.ApplicationSearchRequest {
			return fmt.Errorf("mutation fixture expected object observation")
		}
		attributes := map[string][][]byte{
			"objectGUID": {make([]byte, 16)}, "objectClass": {[]byte("user")}, "name": {[]byte("owned")},
			"distinguishedName": {[]byte("CN=owned," + portableMutationDomain)}, "uSNChanged": {[]byte("42")},
		}
		for name, values := range extra {
			attributes[name] = values
		}
		return portableReaderSearchResponse(connection, request, "CN=owned,"+portableMutationDomain, attributes, true, false)
	}
}

func portableMutationDNSchema(attribute string) portableLDAPStep {
	return portableMutationSchema(attribute, map[string][][]byte{
		"lDAPDisplayName": {[]byte(attribute)}, "attributeSyntax": {[]byte("2.5.5.1")}, "oMSyntax": {[]byte("127")},
		"oMObjectClass": {{0x2b, 0x0c, 2, 0x87, 0x73, 0x1c, 0, 0x85, 0x4a}},
	}, false)
}

func portableMutationSchema(attribute string, attributes map[string][][]byte, partial bool) portableLDAPStep {
	return func(connection net.Conn, request *ber.Packet) error {
		protocol := request.Children[1]
		if protocol.Tag != ldap.ApplicationSearchRequest || protocol.Children[0].Value != "CN=Schema,CN=Configuration,"+portableMutationDomain ||
			protocol.Children[1].Value != int64(ldap.ScopeSingleLevel) {
			return fmt.Errorf("normalization did not consult the advertised schema naming context")
		}
		filter, err := ldap.DecompileFilter(protocol.Children[6])
		if err != nil || filter != "(&(objectClass=attributeSchema)(lDAPDisplayName="+attribute+"))" {
			return fmt.Errorf("normalization did not resolve the exact attribute schema")
		}
		return portableReaderSearchResponse(connection, request, "CN=fixture-attribute,CN=Schema,CN=Configuration,"+portableMutationDomain,
			attributes, true, partial)
	}
}

func TestPortableDNLookingTextRetainsItsContradiction(t *testing.T) {
	certificate, roots := portableTLSCertificate(t, portableTLSHost, false, false)
	requested, returned := "cn=manager,"+portableMutationDomain, "CN=manager,"+portableMutationDomain
	wire := newPortableLDAPWire(t, admodel.TransportLDAPS, certificate,
		portableLDAPBind(0), portableMutationRoot(), portableMutationObject(nil),
		func(connection net.Conn, request *ber.Packet) error {
			if request.Children[1].Tag != ldap.ApplicationModifyRequest {
				return fmt.Errorf("text normalization fixture expected one mutation")
			}
			_, err := connection.Write(portableLDAPResult(request, ldap.ApplicationModifyResponse, 0).Bytes())
			return err
		}, portableMutationObject(map[string][][]byte{"description": {[]byte(returned)}}),
		portableMutationSchema("description", map[string][][]byte{
			"lDAPDisplayName": {[]byte("description")}, "attributeSyntax": {[]byte("2.5.5.12")}, "oMSyntax": {[]byte("64")},
		}, false))
	_, client := portableLDAPSession(t, portableTLSConfig(admodel.TransportLDAPS, roots), wire)
	identity, err := admodel.IdentityByDN("CN=owned," + portableMutationDomain)
	if err != nil {
		t.Fatal(err)
	}
	result, err := client.UpdateObject(t.Context(), admodel.UpdateObjectRequest{
		Identity: identity, Changes: []admodel.AttributeChange{{
			Attribute: "description", Kind: admodel.AttributeSet, Values: []admodel.RawValue{admodel.NewRawValue([]byte(requested))},
		}},
	})
	if !errors.Is(err, admodel.ErrObjectVerification) || errors.Is(err, admodel.ErrObjectUnverifiable) ||
		admodel.Classify(err) != admodel.ClassUncertain || result.State != admodel.ObjectWriteAccepted || result.Verified || result.After == nil {
		t.Fatal("DN-looking ordinary text was incorrectly treated as normalization", result, err)
	}
	_ = client.Close()
	wire.wait(t)
	if wire.requests.Load() != 6 {
		t.Fatal("ordinary text mutation was retried or schema evidence skipped", wire.requests.Load())
	}
}

func TestPortableNormalizedDNStillPresentContradictsRemoval(t *testing.T) {
	certificate, roots := portableTLSCertificate(t, portableTLSHost, false, false)
	requested, returned := "cn=manager,"+portableMutationDomain, "CN=manager,"+portableMutationDomain
	wire := newPortableLDAPWire(t, admodel.TransportLDAPS, certificate,
		portableLDAPBind(0), portableMutationRoot(), portableMutationObject(map[string][][]byte{"manager": {[]byte(requested)}}),
		func(connection net.Conn, request *ber.Packet) error {
			protocol := request.Children[1]
			if protocol.Tag != ldap.ApplicationModifyRequest || protocol.Children[1].Children[0].Children[0].Value != int64(1) {
				return fmt.Errorf("normalized DN removal fixture expected one strict remove")
			}
			_, err := connection.Write(portableLDAPResult(request, ldap.ApplicationModifyResponse, 0).Bytes())
			return err
		}, portableMutationObject(map[string][][]byte{"manager": {[]byte(returned)}}), portableMutationDNSchema("manager"))
	_, client := portableLDAPSession(t, portableTLSConfig(admodel.TransportLDAPS, roots), wire)
	identity, err := admodel.IdentityByDN("CN=owned," + portableMutationDomain)
	if err != nil {
		t.Fatal(err)
	}
	result, err := client.UpdateObject(t.Context(), admodel.UpdateObjectRequest{
		Identity: identity, Changes: []admodel.AttributeChange{{
			Attribute: "manager", Kind: admodel.AttributeRemoveValues, Values: []admodel.RawValue{admodel.NewRawValue([]byte(requested))},
		}},
	})
	if !errors.Is(err, admodel.ErrObjectVerification) || admodel.Classify(err) != admodel.ClassUncertain ||
		result.State != admodel.ObjectWriteAccepted || result.Verified || result.After == nil || result.TargetGUID == nil {
		t.Fatal("a still-present normalized DN was incorrectly verified as removed", result, err)
	}
	_ = client.Close()
	wire.wait(t)
	if wire.requests.Load() != 6 {
		t.Fatal("DN removal was replayed or schema evidence skipped", wire.requests.Load())
	}
}
