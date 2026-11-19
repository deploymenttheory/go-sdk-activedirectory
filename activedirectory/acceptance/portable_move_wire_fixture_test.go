package acceptance

import (
	"bytes"
	"context"
	"errors"
	"net"
	"strings"
	"sync"
	"testing"

	ber "github.com/go-asn1-ber/asn1-ber"

	"github.com/deploymenttheory/go-sdk-activedirectory/3rd_party/gokrb5/v8/messages"
	ldap "github.com/deploymenttheory/go-sdk-activedirectory/3rd_party/ldap/v3"
	adengine "github.com/deploymenttheory/go-sdk-activedirectory/activedirectory/internal/engine"
	admodel "github.com/deploymenttheory/go-sdk-activedirectory/activedirectory/internal/model"
)

// Only directory data/effects use the existing model fixture. Both SDK sessions
// exchange actual LDAP over sockets; source security comes from AS/TGS/AP/SASL,
// never the model fixture's synthetic MoveSecurity observation.
type portableMoveDirectory struct {
	mu       sync.Mutex
	data     *InternalMoveTestFixture
	fault    string
	submits  int
	controls [][]byte
}

func (d *portableMoveDirectory) step(source bool) portableLDAPStep {
	return func(conn net.Conn, request *ber.Packet) error {
		d.mu.Lock()
		defer d.mu.Unlock()
		if len(request.Children) < 2 {
			return errors.New("owned move received malformed LDAP envelope")
		}
		switch request.Children[1].Tag {
		case ldap.ApplicationSearchRequest:
			return d.search(conn, request, source)
		case ldap.ApplicationModifyDNRequest:
			if !source {
				return errors.New("move forwarded a mutation to the destination reader")
			}
			return d.move(conn, request)
		default:
			return errors.New("move attempted copy/delete, password operation or foreign LDAP request")
		}
	}
}

func (d *portableMoveDirectory) search(conn net.Conn, request *ber.Packet, source bool) error {
	operation := request.Children[1]
	if len(operation.Children) != 8 {
		return errors.New("move search schema changed")
	}
	base := operation.Children[0].Data.String()
	data := d.data.InternalDst
	if source {
		data = d.data.InternalSrc
	}
	object, found := data.InternalObjects[base]
	if base == "" {
		object, found = admodel.Object{Attributes: data.InternalRoot}, true
	}
	guid := portableMoveFilterGUID(operation.Children[6])
	if guid != nil {
		found = false
		for _, candidate := range data.InternalObjects {
			values := candidate.Attributes["objectguid"]
			if len(values) == 1 && bytes.Equal(values[0], guid) {
				object, found = candidate, true
				break
			}
		}
	}
	if found {
		attributes := portableLDAPEntry(request, object.Attributes).Children[1].Children[1]
		entry := ber.Encode(ber.ClassApplication, ber.TypeConstructed, ldap.ApplicationSearchResultEntry, nil, "")
		entry.AppendChild(ber.NewString(ber.ClassUniversal, ber.TypePrimitive, ber.TagOctetString, object.DistinguishedName, ""))
		entry.AppendChild(attributes)
		if _, err := conn.Write(portableLDAPEnvelope(request, entry).Bytes()); err != nil {
			return err
		}
	}
	code := int64(0)
	if !source && d.submits != 0 && len(guid) == 16 && guid[0] == 1 && d.fault == "partial-destination" {
		code = 50
	}
	var controls []ldap.Control
	if len(request.Children) == 3 {
		for _, control := range request.Children[2].Children {
			if len(control.Children) > 0 && control.Children[0].Data.String() == ldap.ControlTypePaging {
				if _, _, err := portableLDAPPaging(request); err != nil {
					return err
				}
				controls = append(controls, ldap.NewControlPaging(0))
			}
		}
	}
	_, err := conn.Write(portableLDAPResult(request, ldap.ApplicationSearchResultDone, code, controls...).Bytes())
	return err
}

func portableMoveFilterGUID(filter *ber.Packet) []byte {
	if filter.Tag == 3 && len(filter.Children) == 2 && strings.EqualFold(filter.Children[0].Data.String(), "objectGUID") {
		return filter.Children[1].Data.Bytes()
	}
	for _, child := range filter.Children {
		if value := portableMoveFilterGUID(child); value != nil {
			return value
		}
	}
	return nil
}

func (d *portableMoveDirectory) move(conn net.Conn, request *ber.Packet) error {
	d.submits++
	operation := request.Children[1]
	guid, err := admodel.GUIDFromBytes(d.data.InternalSrc.InternalObjects[InternalMoveTestSourceDN].Attributes["objectguid"][0])
	if err != nil {
		return err
	}
	parent := d.data.InternalRequest.TargetParent.String()
	if len(operation.Children) != 4 || operation.Children[0].Data.String() != admodel.InternalObjectGUIDTarget(guid) ||
		operation.Children[1].Data.String() != `CN=李\, Demo` || operation.Children[2].Value != true ||
		operation.Children[3].ClassType != ber.ClassContext || operation.Children[3].Tag != 0 || operation.Children[3].Data.String() != parent {
		return errors.New("portable move changed GUID/RDN/target/DeleteOldRDN semantics")
	}
	if d.fault == "same-domain" {
		if len(request.Children) != 2 {
			return errors.New("same-domain move requested delegation destination controls")
		}
	} else if err := d.destinationControl(request); err != nil {
		return err
	}
	if d.fault == "refused" {
		_, err := conn.Write(portableLDAPResult(request, ldap.ApplicationModifyDNResponse, 50).Bytes())
		return err
	}
	d.data.InternalSrc.InternalLdapWrite(context.Background(), admodel.InternalLdapWriteRequest{
		InternalOperation: admodel.InternalLdapWriteRename, InternalDn: operation.Children[0].Data.String(),
		InternalNewRDN: operation.Children[1].Data.String(), InternalNewParent: parent, InternalDeleteOldRDN: true,
	})
	if d.fault == "lost-ack" {
		return conn.Close()
	}
	_, err = conn.Write(portableLDAPResult(request, ldap.ApplicationModifyDNResponse, 0).Bytes())
	return err
}

func (d *portableMoveDirectory) destinationControl(request *ber.Packet) error {
	if len(request.Children) != 3 || len(request.Children[2].Children) != 1 {
		return errors.New("cross-domain move omitted its single critical destination control")
	}
	control := request.Children[2].Children[0]
	if len(control.Children) != 3 || control.Children[0].Data.String() != admodel.InternalObjectCrossDomainMoveControl ||
		control.Children[1].Value != true || !bytes.Equal(control.Children[2].Data.Bytes(), []byte("dst.child.example")) {
		return errors.New("destination control is not exact raw UTF-8 DNS without NUL/BER wrapper")
	}
	d.controls = append(d.controls, append([]byte(nil), control.Children[2].Data.Bytes()...))
	return nil
}

type portableMoveDestinationDialer struct {
	wire *portableLDAPWire
}

func (d portableMoveDestinationDialer) DialContext(ctx context.Context, network, address string) (net.Conn, error) {
	if address != "dst.child.example:636" || network != "tcp" {
		return nil, errors.New("owned destination reader attempted another endpoint")
	}
	d.wire.attempts.Add(1)
	conn, err := (&net.Dialer{}).DialContext(ctx, network, d.wire.listener.Addr().String())
	if err != nil {
		return nil, err
	}
	return &portableTLSCountedConn{Conn: conn, closes: &d.wire.closes}, nil
}

func newPortableMoveWireClients(t *testing.T, fault string) (*adengine.Client, *adengine.Client, *portableMoveDirectory, func()) {
	t.Helper()
	directory := &portableMoveDirectory{data: InternalNewMoveTestFixture(t, true, false), fault: fault}
	directory.data.InternalSrc.InternalRoot["dnshostname"] = [][]byte{[]byte(portableTLSHost)}
	if fault == "same-domain" {
		directory.data.InternalDst = directory.data.InternalSrc
		parent := "OU=local,DC=example"
		directory.data.InternalSrc.InternalObjects[parent] = InternalMoveTestObject(parent, "organizationalUnit", 7)
		directory.data.InternalRequest.TargetParent = InternalMoveIdentity(parent)
	}
	if fault == "other-forest" {
		directory.data.InternalDst.InternalObjects[InternalMoveTestConfig].Attributes["objectguid"][0][0] = 10
	}
	if fault == "wrong-RID" {
		for _, object := range directory.data.InternalSrc.InternalObjects {
			if len(object.Attributes["fsmoroleowner"]) != 0 {
				object.Attributes["fsmoroleowner"] = [][]byte{[]byte("CN=another-DSA")}
			}
		}
	}
	kdc := newPortableKerberosKDC(t, func(k *portableKerberosKDC) {
		k.delegation = fault != "not-requested" && fault != "same-domain"
		if k.delegation {
			k.inspectAP = func(ap *messages.APReq) error { return verifyPortableForwarding(k, ap) }
		}
	})
	sourceCertificate, _ := portableKerberosTLSCertificate(t)
	steps := make([]portableLDAPStep, 12)
	for i := range steps {
		steps[i] = directory.step(true)
	}
	sourceWire := newPortableSASLWire(t, admodel.TransportLDAP, sourceCertificate, kdc, ldap.SASLSecuritySeal, 7, "", steps...)
	sourceConfig := portableTLSConfig(admodel.TransportLDAP, nil)
	sourceConfig.TLS = nil
	sourceConfig.Authentication, sourceConfig.Credentials = admodel.AuthenticationKerberos, nil
	sourceConfig.AllowDelegation, sourceConfig.SASLProtection = kdc.delegation, admodel.SASLProtectionSeal
	sourceConfig.Kerberos = portableKerberosSource(t, kdc, admodel.KerberosPassword, false)
	sourceSession, err := adengine.InternalDialPortableWithDial(t.Context(), sourceConfig, sourceWire)
	if err != nil {
		t.Fatal(err)
	}
	source := adengine.InternalNewClient(sourceConfig, sourceSession)
	t.Cleanup(func() { _ = source.Close() })
	destinationCertificate, roots := portableTLSCertificate(t, "dst.child.example", false, false)
	destinationSteps := []portableLDAPStep{portableLDAPBind(0)}
	for range 12 {
		destinationSteps = append(destinationSteps, directory.step(false))
	}
	destinationWire := newPortableLDAPWire(t, admodel.TransportLDAPS, destinationCertificate, destinationSteps...)
	destinationConfig := portableTLSConfig(admodel.TransportLDAPS, roots)
	destinationConfig.Endpoint.Host = "dst.child.example"
	destinationSession, err := adengine.InternalDialPortableWithDial(t.Context(), destinationConfig, portableMoveDestinationDialer{wire: destinationWire})
	if err != nil {
		t.Fatal(err)
	}
	destination := adengine.InternalNewClient(destinationConfig, destinationSession)
	t.Cleanup(func() { _ = destination.Close() })
	return source, destination, directory, func() {
		_ = source.Close()
		_ = destination.Close()
		sourceWire.wait(t)
		destinationWire.wait(t)
	}
}
