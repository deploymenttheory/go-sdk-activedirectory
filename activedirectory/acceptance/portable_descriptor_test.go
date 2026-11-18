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
	"github.com/deploymenttheory/go-sdk-activedirectory/conditions"
)

func TestPortableDirectoryDACLReadUsesCriticalSectionControl(t *testing.T) {
	raw, err := conditions.DescriptorBytes("O:SYG:BAD:PAI(A;;RP;;;WD)S:(AU;SA;RP;;;WD)")
	if err != nil {
		t.Fatal(err)
	}
	certificate, roots := portableTLSCertificate(t, portableTLSHost, false, false)
	wire := newPortableLDAPWire(t, admodel.TransportLDAPS, certificate, portableLDAPBind(0), func(connection net.Conn, request *ber.Packet) error {
		if err := portableLDAPCheckControls(
			request,
			[]admodel.InternalLdapWriteControl{{InternalOid: admodel.InternalDirectorySDFlagsControl, InternalCritical: true, InternalValue: []byte{0x30, 3, 2, 1, 4}}},
		); err != nil {
			return err
		}
		if request.Children[1].Tag != ldap.ApplicationSearchRequest || request.Children[1].Children[1].Value != int64(ldap.ScopeBaseObject) {
			return fmt.Errorf("descriptor read was not base scoped")
		}
		attributes := map[string][][]byte{"nTSecurityDescriptor": {raw}, "objectGUID": {make([]byte, 16)}}
		if _, err := connection.Write(portableLDAPEntry(request, attributes).Bytes()); err != nil {
			return err
		}
		_, err := connection.Write(portableLDAPResult(request, ldap.ApplicationSearchResultDone, 0).Bytes())
		return err
	})
	session, client := portableLDAPSession(t, portableTLSConfig(admodel.TransportLDAPS, roots), wire)
	daclSession, supported := session.(admodel.InternalDirectoryDACLSession)
	if !supported {
		t.Fatal("portable directory session has no descriptor support")
	}
	object, err := daclSession.InternalReadDirectoryDACL(t.Context(), "CN=owned,DC=ad,DC=sdk,DC=test", nil)
	if err != nil || !bytes.Equal(object.Attributes["ntsecuritydescriptor"][0], raw) {
		t.Fatal("descriptor bytes changed or read failed", err)
	}
	if object.DistinguishedName != "CN=owned,DC=ad,DC=sdk,DC=test" {
		t.Fatal("descriptor entry identity was lost")
	}
	if object.SecurityDescriptorSections != 4 {
		t.Fatal("DACL-only response lost its explicit section scope")
	}
	_ = client.Close()
	wire.wait(t)
}

func TestPortableDirectoryDescriptorCodecPreservesUnownedState(t *testing.T) {
	raw, err := conditions.DescriptorBytes(`O:SYG:BAD:PAI(A;ID;RP;;;WD)(XA;;GR;;;WD;(@User.Department == "Finance"))S:(RA;;;;;WD;("Label",TS,0,"blue"))`)
	if err != nil {
		t.Fatal(err)
	}
	descriptor, err := conditions.ParseDescriptor(raw)
	if err != nil {
		t.Fatal(err)
	}
	acl := descriptor.DACL()
	acl.ACEs = append(acl.ACEs, []byte{0x7f, 0, 8, 0, 0x42, 0xa5, 0xff, 0})
	descriptor, err = descriptor.WithDACL(acl)
	if err != nil {
		t.Fatal(err)
	}
	raw, err = descriptor.MarshalBinary()
	if err != nil {
		t.Fatal(err)
	}
	session := &adengine.InternalPortableSession{}
	unchanged, err := session.InternalEncodeDACL(raw, acl.ACEs)
	if err != nil || !bytes.Equal(unchanged, raw) {
		t.Fatal("no-op service encoder changed original storage", err)
	}
	aces := append([][]byte{InternalOuTestACE(1, 0, admodel.InternalOuObjectProtectionMask)}, acl.ACEs...)
	edited, err := session.InternalEncodeDACL(raw, aces)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(raw[:16], edited[:16]) || !bytes.Equal(raw[20:], edited[20:len(raw)]) {
		t.Fatal("service encoder changed owner/group/SACL/control/opaque original storage")
	}
	preserved, err := admodel.InternalPreserveDirectoryDescriptor(raw, edited)
	if err != nil || !bytes.Equal(preserved, edited) {
		t.Fatal("whole-value service-account descriptor editor changed unrelated bytes", err)
	}
	if _, err := session.InternalEncodeDACL([]byte{1, 0, 4, 128}, aces); !errors.Is(err, admodel.ErrInvalidResult) {
		t.Fatal("malformed descriptor was not refused", err)
	}
}

func TestPortableDirectoryDACLReadRetainsPartialAndRefusal(t *testing.T) {
	for _, mode := range []string{"denied-empty", "denied-after-entry", "lost-after-entry", "malformed-after-entry", "multiple-entries"} {
		t.Run(mode, func(t *testing.T) {
			raw, err := conditions.DescriptorBytes("D:(A;;RP;;;WD)")
			if err != nil {
				t.Fatal(err)
			}
			certificate, roots := portableTLSCertificate(t, portableTLSHost, false, false)
			wire := newPortableLDAPWire(t, admodel.TransportLDAPS, certificate, portableLDAPBind(0), func(connection net.Conn, request *ber.Packet) error {
				if mode != "denied-empty" {
					if _, err := connection.Write(portableLDAPEntry(request, map[string][][]byte{"nTSecurityDescriptor": {raw}}).Bytes()); err != nil {
						return err
					}
				}
				code := int64(50)
				switch mode {
				case "lost-after-entry":
					return connection.Close()
				case "malformed-after-entry":
					_, err := connection.Write(portableLDAPResult(request, ldap.ApplicationModifyResponse, 0).Bytes())
					return err
				case "multiple-entries":
					if _, err := connection.Write(portableLDAPEntry(request, map[string][][]byte{"nTSecurityDescriptor": {raw}}).Bytes()); err != nil {
						return err
					}
					code = 0
				}
				_, err := connection.Write(portableLDAPResult(request, ldap.ApplicationSearchResultDone, code).Bytes())
				return err
			})
			session, client := portableLDAPSession(t, portableTLSConfig(admodel.TransportLDAPS, roots), wire)
			object, err := session.(admodel.InternalDirectoryDACLSession).InternalReadDirectoryDACL(t.Context(), "CN=owned,DC=ad,DC=sdk,DC=test", nil)
			if err == nil {
				t.Fatal("failed or incomplete DACL read was reported as complete success")
			}
			if mode != "denied-empty" {
				values := object.Attributes["ntsecuritydescriptor"]
				if len(values) != 1 || !bytes.Equal(values[0], raw) {
					t.Fatal("partial descriptor observation was discarded")
				}
			}
			if mode == "denied-empty" || mode == "denied-after-entry" {
				var refusal *admodel.LDAPError
				if !errors.As(err, &refusal) || refusal.Code != 50 || errors.Is(err, admodel.ErrInvalidResult) {
					t.Fatal("valid permission refusal was obscured as malformed response", err)
				}
			}
			_ = client.Close()
			wire.wait(t)
		})
	}
}
