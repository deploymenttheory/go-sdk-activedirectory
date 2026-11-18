package acceptance

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"net"
	"testing"

	ber "github.com/go-asn1-ber/asn1-ber"

	ldap "github.com/deploymenttheory/go-sdk-activedirectory/3rd_party/ldap/v3"
	admodel "github.com/deploymenttheory/go-sdk-activedirectory/activedirectory/internal/model"
)

func TestPortableLDAPPagingCookiesRemainOpaque(t *testing.T) {
	certificate, roots := portableTLSCertificate(t, portableTLSHost, false, false)
	page := func(connection net.Conn, request *ber.Packet) error {
		if _, err := connection.Write(portableLDAPEntry(request, map[string][][]byte{"name": {[]byte("owned")}}).Bytes()); err != nil {
			return err
		}
		_, err := connection.Write(portableLDAPResult(request, ldap.ApplicationSearchResultDone, 0, &ldap.ControlPaging{Cookie: []byte{0, 0xff}}).Bytes())
		return err
	}
	finish := func(connection net.Conn, request *ber.Packet) error {
		_, err := connection.Write(portableLDAPResult(request, ldap.ApplicationSearchResultDone, 0, &ldap.ControlPaging{}).Bytes())
		return err
	}
	wire := newPortableLDAPWire(t, admodel.TransportLDAPS, certificate, portableLDAPBind(0), page, page, finish)
	_, client := portableLDAPSession(t, portableTLSConfig(admodel.TransportLDAPS, roots), wire)
	result, err := client.Search(t.Context(), admodel.SearchOptions{Base: "DC=ad,DC=sdk,DC=test", PageSize: 1})
	if err != nil || !result.Complete || len(result.Objects) != 2 {
		t.Fatalf("opaque repeated cookie was interpreted as a position: %+v %v", result, err)
	}
	_ = client.Close()
	wire.wait(t)
}

func TestPortableLDAPTerminalRefusalWithoutPagingPreservesSession(t *testing.T) {
	certificate, roots := portableTLSCertificate(t, portableTLSHost, false, false)
	wire := newPortableLDAPWire(t, admodel.TransportLDAPS, certificate, portableLDAPBind(0), func(connection net.Conn, request *ber.Packet) error {
		_, err := connection.Write(portableLDAPResult(request, ldap.ApplicationSearchResultDone, 32).Bytes())
		return err
	}, func(connection net.Conn, request *ber.Packet) error {
		if _, err := connection.Write(portableLDAPEntry(request, map[string][][]byte{"name": {[]byte("owned")}}).Bytes()); err != nil {
			return err
		}
		_, err := connection.Write(portableLDAPResult(request, ldap.ApplicationSearchResultDone, 0).Bytes())
		return err
	})
	session, client := portableLDAPSession(t, portableTLSConfig(admodel.TransportLDAPS, roots), wire)
	result, err := client.Search(t.Context(), admodel.SearchOptions{Base: "CN=absent,DC=ad,DC=sdk,DC=test"})
	var refusal *admodel.LDAPError
	if result.Complete || !errors.As(err, &refusal) || refusal.Code != 32 {
		t.Fatalf("actual no-such-object refusal was lost: %+v %v", result, err)
	}
	if _, err := session.InternalBaseObject(t.Context(), "CN=owned,DC=ad,DC=sdk,DC=test", []string{"name"}); err != nil {
		t.Fatal("terminal refusal incorrectly retired a valid stream:", err)
	}
	_ = client.Close()
	wire.wait(t)
}

func TestPortableLDAPTypedExtensibleFilterKeepsAssertionOctets(t *testing.T) {
	assertion := []byte{0, 0xff, '(', ')', '\\'}
	filter := admodel.FilterExtensible(admodel.ExtensibleFilter{
		Attribute: "ownedBinary", Rule: "1.2.3.4", Value: admodel.FilterBytes(assertion),
	})
	encoded, err := filter.LDAP()
	if err != nil {
		t.Fatal(err)
	}
	want, err := ldap.CompileFilter(encoded)
	if err != nil {
		t.Fatal(err)
	}
	certificate, roots := portableTLSCertificate(t, portableTLSHost, false, false)
	wire := newPortableLDAPWire(t, admodel.TransportLDAPS, certificate, portableLDAPBind(0), func(connection net.Conn, request *ber.Packet) error {
		if !bytes.Equal(request.Children[1].Children[6].Bytes(), want.Bytes()) {
			return fmt.Errorf("typed extensible assertion octets changed")
		}
		_, err := connection.Write(portableLDAPResult(request, ldap.ApplicationSearchResultDone, 0, &ldap.ControlPaging{}).Bytes())
		return err
	})
	_, client := portableLDAPSession(t, portableTLSConfig(admodel.TransportLDAPS, roots), wire)
	result, err := client.Search(t.Context(), admodel.SearchOptions{TypedFilter: filter})
	if err != nil || !result.Complete {
		t.Fatalf("portable RFC 4515 assertion was limited by WinLDAP W-string rules: %+v %v", result, err)
	}
	_ = client.Close()
	wire.wait(t)
}

func portableLDAPCheckControls(request *ber.Packet, expected []admodel.InternalLdapWriteControl) error {
	if len(request.Children) != 3 || len(request.Children[2].Children) != len(expected) {
		return fmt.Errorf("control cardinality changed")
	}
	for i, control := range request.Children[2].Children {
		want := expected[i]
		if control.Children[0].Value != want.InternalOid {
			return fmt.Errorf("control order or OID changed")
		}
		position := 1
		if want.InternalCritical {
			if len(control.Children) < 2 || control.Children[1].Value != true {
				return fmt.Errorf("critical control was weakened")
			}
			position++
		}
		if want.InternalValue == nil {
			if len(control.Children) != position {
				return fmt.Errorf("omitted control value became an explicit value")
			}
		} else if len(control.Children) != position+1 || !bytes.Equal(control.Children[position].Data.Bytes(), want.InternalValue) {
			return fmt.Errorf("binary control value changed")
		}
	}
	return nil
}

func TestPortableLDAPAddModifyDeleteAndRenameKeepBinaryAndCriticalControls(t *testing.T) {
	for _, operation := range []admodel.InternalLdapWriteOperation{admodel.InternalLdapWriteAdd, admodel.InternalLdapWriteModify, admodel.InternalLdapWriteDelete, admodel.InternalLdapWriteRename} {
		t.Run(fmt.Sprint(operation), func(t *testing.T) {
			certificate, roots := portableTLSCertificate(t, portableTLSHost, false, false)
			controls := []admodel.InternalLdapWriteControl{
				{InternalOid: "1.3.6.1.1.12", InternalCritical: true, InternalValue: []byte{0xa3, 0x00}},
				{InternalOid: "1.2.840.113556.1.4.1413", InternalCritical: true},
			}
			value := []byte{0, 0xff, 0x80, 42}
			wire := newPortableLDAPWire(t, admodel.TransportLDAPS, certificate, portableLDAPBind(0), func(connection net.Conn, request *ber.Packet) error {
				if err := portableLDAPCheckControls(request, controls); err != nil {
					return err
				}
				protocol := request.Children[1]
				tag := ber.Tag(0)
				switch operation {
				case admodel.InternalLdapWriteAdd:
					if protocol.Tag != ldap.ApplicationAddRequest || len(protocol.Children) != 2 {
						return fmt.Errorf("invalid add shape")
					}
					attributes := protocol.Children[1].Children
					if len(attributes) != 1 || len(attributes[0].Children[1].Children) != 2 || !bytes.Equal(attributes[0].Children[1].Children[0].Data.Bytes(), value) ||
						len(attributes[0].Children[1].Children[1].Data.Bytes()) != 0 {
						return fmt.Errorf("binary add or empty value changed")
					}
					tag = ldap.ApplicationAddResponse
				case admodel.InternalLdapWriteModify:
					if protocol.Tag != ldap.ApplicationModifyRequest || len(protocol.Children) != 2 {
						return fmt.Errorf("invalid modify shape")
					}
					changes := protocol.Children[1].Children
					if len(changes) != 2 || len(changes[0].Children[1].Children[1].Children) != 0 || len(changes[1].Children[1].Children[1].Children) != 1 ||
						len(changes[1].Children[1].Children[1].Children[0].Data.Bytes()) != 0 {
						return fmt.Errorf("whole delete and single empty value collapsed")
					}
					tag = ldap.ApplicationModifyResponse
				case admodel.InternalLdapWriteDelete:
					if protocol.Tag != ldap.ApplicationDelRequest || protocol.Data.String() != "CN=owned,DC=ad,DC=sdk,DC=test" {
						return fmt.Errorf("delete target changed")
					}
					tag = ldap.ApplicationDelResponse
				case admodel.InternalLdapWriteRename:
					if protocol.Tag != ldap.ApplicationModifyDNRequest || len(protocol.Children) != 4 || protocol.Children[1].Value != "CN=renamed" ||
						protocol.Children[2].Value != true ||
						protocol.Children[3].ClassType != ber.ClassContext ||
						protocol.Children[3].Tag != 0 ||
						protocol.Children[3].Data.String() != "OU=owned,DC=ad,DC=sdk,DC=test" {
						return fmt.Errorf("ModifyDN target/options changed")
					}
					tag = ldap.ApplicationModifyDNResponse
				}
				_, err := connection.Write(portableLDAPResult(request, tag, 0).Bytes())
				return err
			})
			session, client := portableLDAPSession(t, portableTLSConfig(admodel.TransportLDAPS, roots), wire)
			request := admodel.InternalLdapWriteRequest{InternalOperation: operation, InternalDn: "CN=owned,DC=ad,DC=sdk,DC=test", InternalControls: controls}
			switch operation {
			case admodel.InternalLdapWriteAdd:
				request.InternalModifications = []admodel.InternalLdapAttributeModification{
					{InternalOperation: 0, InternalAttribute: "jpegPhoto", InternalValues: [][]byte{value, {}}},
				}
			case admodel.InternalLdapWriteModify:
				request.InternalModifications = []admodel.InternalLdapAttributeModification{
					{InternalOperation: 1, InternalAttribute: "description"},
					{InternalOperation: 2, InternalAttribute: "displayName", InternalValues: [][]byte{{}}},
				}
			case admodel.InternalLdapWriteRename:
				request.InternalNewRDN = "CN=renamed"
				request.InternalNewParent = "OU=owned,DC=ad,DC=sdk,DC=test"
				request.InternalDeleteOldRDN = true
			}
			attempt := session.(admodel.InternalLdapWriteSession).InternalLdapWrite(t.Context(), request)
			if attempt.State != admodel.InternalLdapWriteAccepted || attempt.Err != nil {
				t.Fatalf("valid controlled operation failed: %+v", attempt)
			}
			_ = client.Close()
			wire.wait(t)
		})
	}
}

func TestPortableLDAPPrecancelledWriteIsNotSubmitted(t *testing.T) {
	certificate, roots := portableTLSCertificate(t, portableTLSHost, false, false)
	wire := newPortableLDAPWire(t, admodel.TransportLDAPS, certificate, portableLDAPBind(0))
	session, client := portableLDAPSession(t, portableTLSConfig(admodel.TransportLDAPS, roots), wire)
	ctx, cancel := context.WithCancel(t.Context())
	cancel()
	attempt := session.(admodel.InternalLdapWriteSession).InternalLdapWrite(
		ctx,
		admodel.InternalLdapWriteRequest{InternalOperation: admodel.InternalLdapWriteDelete, InternalDn: "CN=owned,DC=ad,DC=sdk,DC=test"},
	)
	if attempt.State != admodel.InternalLdapWriteNotAttempted || !errors.Is(attempt.Err, context.Canceled) {
		t.Fatalf("pre-cancelled write claimed submission: %+v", attempt)
	}
	_ = client.Close()
	wire.wait(t)
	if wire.requests.Load() != 1 {
		t.Fatal("pre-cancelled write reached wire")
	}
}
