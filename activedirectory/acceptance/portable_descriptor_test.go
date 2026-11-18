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

func TestPortableOUAssertedWritePreservesOutcomes(t *testing.T) {
	for _, mode := range []string{"accepted", "stale", "denied", "lost", "malformed", "cancelled", "partial-readback"} {
		t.Run(mode, func(t *testing.T) {
			certificate, roots := portableTLSCertificate(t, portableTLSHost, false, false)
			config := portableTLSConfig(admodel.TransportLDAPS, roots)
			guid, err := admodel.GUIDFromBytes(make([]byte, 16))
			if err != nil {
				t.Fatal(err)
			}
			raw := InternalOuTestDescriptor(InternalOuTestACE(0, 0, 0x20000))
			before := admodel.Object{DistinguishedName: "CN=owned,DC=ad,DC=sdk,DC=test", Attributes: map[string][][]byte{
				"objectguid": {guid.Bytes()}, "usnchanged": {[]byte("7")}, "ntsecuritydescriptor": {raw},
			}, SecurityDescriptorSections: 4}
			controls := []admodel.InternalLdapWriteControl{
				{
					InternalOid:      admodel.InternalObjectAssertionControl,
					InternalCritical: true,
					InternalValue:    admodel.InternalObjectVersionAssertion(admodel.ObjectVersion{GUID: guid, USNChanged: 7}),
				},
				{InternalOid: admodel.InternalDirectorySDFlagsControl, InternalCritical: true, InternalValue: []byte{0x30, 3, 2, 1, 4}},
			}
			var submitted []byte
			received := make(chan struct{})
			steps := []portableLDAPStep{portableLDAPBind(0), func(connection net.Conn, request *ber.Packet) error {
				if err := portableLDAPCheckControls(request, controls); err != nil {
					return err
				}
				protocol := request.Children[1]
				if protocol.Tag != ldap.ApplicationModifyRequest || protocol.Children[0].Value != admodel.InternalObjectGUIDTarget(guid) {
					return fmt.Errorf("derived DACL mutation lost its GUID target")
				}
				changes := protocol.Children[1].Children
				if len(changes) != 1 || changes[0].Children[0].Value != int64(2) || changes[0].Children[1].Children[0].Value != "nTSecurityDescriptor" {
					return fmt.Errorf("asserted DACL operation shape changed")
				}
				submitted = bytes.Clone(changes[0].Children[1].Children[1].Children[0].Data.Bytes())
				close(received)
				switch mode {
				case "lost":
					return connection.Close()
				case "cancelled":
					var extra [1]byte
					_, err := connection.Read(extra[:])
					return err
				case "malformed":
					_, err := connection.Write(portableLDAPResult(request, ldap.ApplicationAddResponse, 0).Bytes())
					return err
				case "stale":
					_, err := connection.Write(portableLDAPResult(request, ldap.ApplicationModifyResponse, 122).Bytes())
					return err
				case "denied":
					_, err := connection.Write(portableLDAPResult(request, ldap.ApplicationModifyResponse, 50).Bytes())
					return err
				}
				_, err := connection.Write(portableLDAPResult(request, ldap.ApplicationModifyResponse, 0).Bytes())
				return err
			}}
			if mode == "accepted" || mode == "partial-readback" {
				steps = append(steps, func(connection net.Conn, request *ber.Packet) error {
					if err := portableLDAPCheckControls(request, controls[1:]); err != nil {
						return err
					}
					if _, err := connection.Write(portableLDAPEntry(request, map[string][][]byte{
						"objectGUID": {guid.Bytes()}, "nTSecurityDescriptor": {submitted}, "uSNChanged": {[]byte("8")},
					}).Bytes()); err != nil {
						return err
					}
					code := int64(0)
					if mode == "partial-readback" {
						code = 50
					}
					_, err := connection.Write(portableLDAPResult(request, ldap.ApplicationSearchResultDone, code).Bytes())
					return err
				})
			}
			wire := newPortableLDAPWire(t, admodel.TransportLDAPS, certificate, steps...)
			session, client := portableLDAPSession(t, config, wire)
			ctx, cancel := context.WithCancel(t.Context())
			defer cancel()
			if mode == "cancelled" {
				go func() {
					select {
					case <-received:
						cancel()
					case <-ctx.Done():
					}
				}()
			}
			step := admodel.OUProtectionStep{TargetGUID: &guid, Before: &before}
			err = admodel.InternalWriteOUProtectionStep(ctx, session.(admodel.InternalOuProtectionSession),
				admodel.RootDSE{SupportedControls: []string{admodel.InternalDirectorySDFlagsControl, admodel.InternalObjectAssertionControl}},
				config, admodel.ObjectMutationOptions{}, &step, raw, admodel.InternalOuObjectProtectionMask, true)
			// Apply the same error boundary used by the public object workflow.
			err = admodel.InternalClassifyObjectWriteError(err)
			switch mode {
			case "accepted":
				if err != nil || step.State != admodel.ObjectWriteAccepted || !step.Verified {
					t.Fatal(step, err)
				}
			case "partial-readback":
				if err == nil || step.State != admodel.ObjectWriteAccepted || step.Verified || step.After == nil {
					t.Fatal("accepted effect or partial readback lost", step, err)
				}
			case "stale", "denied":
				want := admodel.ErrObjectConcurrency
				if mode == "denied" {
					want = admodel.ErrObjectWritePermission
				}
				if !errors.Is(err, want) || step.State != admodel.ObjectWriteRejected || step.Verified {
					t.Fatal("actual server refusal was obscured", step, err)
				}
			default:
				if !errors.Is(err, admodel.ErrObjectWriteUncertain) || step.State != admodel.ObjectWriteUncertain || step.Verified {
					t.Fatal("submitted interrupted DACL effect was not uncertain", step, err)
				}
				attempt := session.(admodel.InternalLdapWriteSession).InternalLdapWrite(
					t.Context(),
					admodel.InternalLdapWriteRequest{InternalOperation: admodel.InternalLdapWriteDelete, InternalDn: admodel.InternalObjectGUIDTarget(guid)},
				)
				if attempt.State != admodel.InternalLdapWriteNotAttempted || !errors.Is(attempt.Err, admodel.ErrClosed) {
					t.Fatal("retired session permitted another mutation", attempt)
				}
			}
			_ = client.Close()
			wire.wait(t)
			wantRequests := int32(2)
			if mode == "accepted" || mode == "partial-readback" {
				wantRequests = 3
			}
			if wire.requests.Load() != wantRequests {
				t.Fatal("descriptor mutation was retried or read back after an unaccepted effect")
			}
		})
	}
}

func TestPortableOUProtectionRefusesUnguardedReadModifyWrite(t *testing.T) {
	certificate, roots := portableTLSCertificate(t, portableTLSHost, false, false)
	wire := newPortableLDAPWire(t, admodel.TransportLDAPS, certificate, portableLDAPBind(0), func(connection net.Conn, request *ber.Packet) error {
		_, err := connection.Write(portableLDAPResult(request, ldap.ApplicationModifyResponse, 50).Bytes())
		return err
	})
	config := portableTLSConfig(admodel.TransportLDAPS, roots)
	session, client := portableLDAPSession(t, config, wire)
	guid, err := admodel.GUIDFromBytes(make([]byte, 16))
	if err != nil {
		t.Fatal(err)
	}
	raw := InternalOuTestDescriptor(InternalOuTestACE(0, 0, 0x20000))
	before := admodel.Object{DistinguishedName: "CN=owned,DC=ad,DC=sdk,DC=test", Attributes: map[string][][]byte{
		"objectguid": {guid.Bytes()}, "usnchanged": {[]byte("7")}, "ntsecuritydescriptor": {raw},
	}, SecurityDescriptorSections: 4}
	step := admodel.OUProtectionStep{TargetGUID: &guid, Before: &before}
	err = admodel.InternalWriteOUProtectionStep(t.Context(), session.(admodel.InternalOuProtectionSession),
		admodel.RootDSE{SupportedControls: []string{admodel.InternalDirectorySDFlagsControl}}, config,
		admodel.ObjectMutationOptions{}, &step, raw, admodel.InternalOuObjectProtectionMask, true)
	if !errors.Is(err, admodel.ErrObjectControlUnsupported) || step.State != admodel.ObjectWriteNotAttempted {
		t.Fatal("unasserted DACL replacement was permitted", step.State, err)
	}
	_ = client.Close()
	wire.wait(t)
	if wire.requests.Load() != 1 {
		t.Fatal("unsupported guard still submitted a mutation")
	}
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
