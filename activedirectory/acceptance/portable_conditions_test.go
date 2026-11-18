package acceptance

import (
	"bytes"
	"encoding/base64"
	"encoding/binary"
	"errors"
	"fmt"
	"net"
	"testing"

	ber "github.com/go-asn1-ber/asn1-ber"

	ldap "github.com/deploymenttheory/go-sdk-activedirectory/3rd_party/ldap/v3"
	admodel "github.com/deploymenttheory/go-sdk-activedirectory/activedirectory/internal/model"
	authpolicies "github.com/deploymenttheory/go-sdk-activedirectory/activedirectory/services/authentication_policies"
	centralaccess "github.com/deploymenttheory/go-sdk-activedirectory/activedirectory/services/central_access"
	"github.com/deploymenttheory/go-sdk-activedirectory/conditions"
)

const portablePolicyConfiguration = "CN=Configuration,DC=ad,DC=sdk,DC=test"

func TestPortableAuthenticationPolicyCompilesAllTypedDescriptorsToBinary(t *testing.T) {
	certificate, roots := portableTLSCertificate(t, portableTLSHost, false, false)
	dn := "CN=owned,CN=AuthN Policies,CN=AuthN Policy Configuration,CN=Services," + portablePolicyConfiguration
	identity, err := admodel.IdentityByDN(dn)
	if err != nil {
		t.Fatal(err)
	}
	guid, err := admodel.GUIDFromBytes(make([]byte, 16))
	if err != nil {
		t.Fatal(err)
	}
	sddl := `D:(XA;;CR;;;WD;(@User.Score == 7))`
	// Retained Windows relation-eq vector, with only its GR mask changed to CR
	// according to MS-DTYP ACCESS_MASK. The conditional wire tokens are independent
	// of the portable compiler used by the workflow.
	expected, err := base64.StdEncoding.DecodeString(
		"AQAEgAAAAAAAAAAAAAAAABQAAAACADwAAQAAAAkANAAAAACAAQEAAAAAAAEAAAAAYXJ0ePkKAAAAUwBjAG8AcgBlAAQHAAAAAAAAAAMCgAA=",
	)
	if err != nil {
		t.Fatal(err)
	}
	binary.LittleEndian.PutUint32(expected[32:36], 0x100)
	var changes []portablePolicyChange
	after := map[string][][]byte{"msDS-AuthNPolicyEnforced": {[]byte("FALSE")}}
	for _, name := range []string{
		"msDS-UserAllowedToAuthenticateFrom", "msDS-UserAllowedToAuthenticateTo", "msDS-ComputerAllowedToAuthenticateTo",
		"msDS-ServiceAllowedToAuthenticateFrom", "msDS-ServiceAllowedToAuthenticateTo",
	} {
		changes = append(changes, portablePolicyChange{2, name, expected})
		after[name] = [][]byte{expected}
	}
	wire := newPortableLDAPWire(t, admodel.TransportLDAPS, certificate,
		portableLDAPBind(0), portablePolicyRoot(), portablePolicyRoot(),
		portablePolicyObject(dn, "msDS-AuthNPolicy", map[string][][]byte{"msDS-AuthNPolicyEnforced": {[]byte("FALSE")}}, false),
		portablePolicyBase("CN=NTDS Settings,CN=fixture,"+portablePolicyConfiguration, map[string][][]byte{
			"msDS-isRODC": {[]byte("FALSE")}, "objectClass": {[]byte("nTDSDSA")},
		}),
		portablePolicyBase("CN=Schema,"+portablePolicyConfiguration, map[string][][]byte{"objectVersion": {[]byte("88")}}),
		func(connection net.Conn, request *ber.Packet) error {
			if err := portablePolicyModify(request, guid, changes); err != nil {
				return err
			}
			_, err := connection.Write(portableLDAPResult(request, ldap.ApplicationModifyResponse, 0).Bytes())
			return err
		}, portablePolicyObject(dn, "msDS-AuthNPolicy", after, false))
	_, client := portableLDAPSession(t, portableTLSConfig(admodel.TransportLDAPS, roots), wire)
	result, err := authpolicies.New(client).UpdateAuthenticationPolicy(t.Context(), admodel.UpdateAuthenticationPolicyRequest{
		Identity: identity, Properties: admodel.AuthenticationPolicyProperties{
			UserAllowedToAuthenticateFrom: &sddl, UserAllowedToAuthenticateTo: &sddl, ComputerAllowedToAuthenticateTo: &sddl,
			ServiceAllowedToAuthenticateFrom: &sddl, ServiceAllowedToAuthenticateTo: &sddl,
		},
	})
	if err != nil || result.Mutation.State != admodel.ObjectWriteAccepted || !result.Mutation.Verified || result.Policy == nil ||
		result.Policy.Enforced == nil || *result.Policy.Enforced {
		t.Fatal("portable authentication policy did not verify its binary descriptors", result, err)
	}
	for name := range after {
		if name != "msDS-AuthNPolicyEnforced" {
			value, valueErr := result.Policy.Raw.Values(name).Single()
			if valueErr != nil || !bytes.Equal(value.Bytes(), expected) {
				t.Fatal("authentication policy readback lost exact descriptor bytes", name, valueErr)
			}
		}
	}
	_ = client.Close()
	wire.wait(t)
	if wire.requests.Load() != 8 {
		t.Fatal("authentication policy submitted an unexpected operation", wire.requests.Load())
	}
}

func portablePolicyBase(dn string, attributes map[string][][]byte) portableLDAPStep {
	return func(connection net.Conn, request *ber.Packet) error {
		if request.Children[1].Tag != ldap.ApplicationSearchRequest || request.Children[1].Children[0].Value != dn ||
			request.Children[1].Children[1].Value != int64(ldap.ScopeBaseObject) {
			return fmt.Errorf("policy fixture expected prerequisite base read")
		}
		return portableReaderSearchResponse(connection, request, dn, attributes, false, false)
	}
}

func TestPortableCentralAccessUpdatePreservesPolicyTextAndHistory(t *testing.T) {
	certificate, roots := portableTLSCertificate(t, portableTLSHost, false, false)
	parent := admodel.InternalCentralAccessParent(portablePolicyConfiguration, false)
	dn := "CN=owned," + parent
	old := `O:SYG:SYD:(A;;FR;;;WD)`
	current := `O:SYG:SYD:(XA;;FR;;;WD;(@Resource.Department == "Finance"))`
	conditionText := `@Resource.Department == "Finance"`
	condition := conditions.Raw(conditionText)
	guid, err := admodel.GUIDFromBytes(make([]byte, 16))
	if err != nil {
		t.Fatal(err)
	}
	object := func(acl, previous string) portableLDAPStep {
		return portablePolicyObject(dn, "msAuthz-CentralAccessRule", map[string][][]byte{
			admodel.InternalCentralCurrent: {[]byte(acl)}, admodel.InternalCentralPrevious: {[]byte(previous)},
			admodel.InternalCentralCondition: {[]byte(conditionText)},
		}, false)
	}
	wire := newPortableLDAPWire(t, admodel.TransportLDAPS, certificate,
		portableLDAPBind(0), portablePolicyRoot(), portablePolicyRoot(), object(old, "D:"),
		func(connection net.Conn, request *ber.Packet) error {
			if err := portablePolicyModify(request, guid, []portablePolicyChange{
				{2, admodel.InternalCentralCondition, []byte(conditionText)},
				{1, admodel.InternalCentralCurrent, []byte(old)},
				{0, admodel.InternalCentralCurrent, []byte(current)},
				{2, admodel.InternalCentralPrevious, []byte(old)},
			}); err != nil {
				return err
			}
			_, err := connection.Write(portableLDAPResult(request, ldap.ApplicationModifyResponse, 0).Bytes())
			return err
		}, object(current, old))
	_, client := portableLDAPSession(t, portableTLSConfig(admodel.TransportLDAPS, roots), wire)
	identity, err := admodel.IdentityByDN(dn)
	if err != nil {
		t.Fatal(err)
	}
	result, err := centralaccess.New(client).UpdateCentralAccessRule(t.Context(), admodel.UpdateCentralAccessRuleRequest{
		Identity: identity, CurrentACL: &current, ResourceCondition: &condition,
	})
	if err != nil || result.Mutation.State != admodel.ObjectWriteAccepted || !result.Mutation.Verified || result.Rule == nil ||
		result.Rule.CurrentACL == nil || *result.Rule.CurrentACL != current || result.Rule.PreviousACL == nil || *result.Rule.PreviousACL != old {
		t.Fatal("portable central-access update lost submitted text or exact observed history", result, err)
	}
	_ = client.Close()
	wire.wait(t)
	if wire.requests.Load() != 6 {
		t.Fatal("central-access update was repeated", wire.requests.Load())
	}
}

type portablePolicyChange struct {
	operation int64
	attribute string
	value     []byte
}

func portablePolicyModify(request *ber.Packet, guid admodel.GUID, expected []portablePolicyChange) error {
	if len(request.Children) != 2 {
		return fmt.Errorf("policy update used an unexpected control")
	}
	protocol := request.Children[1]
	if protocol.Tag != ldap.ApplicationModifyRequest || len(protocol.Children) != 2 ||
		protocol.Children[0].Value != admodel.InternalObjectGUIDTarget(guid) {
		return fmt.Errorf("policy update lost its GUID target or Modify shape")
	}
	changes := protocol.Children[1].Children
	if len(changes) != len(expected) {
		return fmt.Errorf("policy update changed operation count")
	}
	for i, want := range expected {
		change := changes[i]
		if len(change.Children) != 2 || change.Children[0].Value != want.operation {
			return fmt.Errorf("policy update changed operation order")
		}
		attribute := change.Children[1].Children
		if len(attribute) != 2 || attribute[0].Value != want.attribute || len(attribute[1].Children) != 1 ||
			!bytes.Equal(attribute[1].Children[0].Data.Bytes(), want.value) {
			return fmt.Errorf("policy update changed attribute encoding or exact value")
		}
	}
	return nil
}

func portablePolicyObject(dn, class string, extra map[string][][]byte, partial bool) portableLDAPStep {
	return func(connection net.Conn, request *ber.Packet) error {
		if request.Children[1].Tag != ldap.ApplicationSearchRequest {
			return fmt.Errorf("policy fixture expected object discovery")
		}
		attributes := map[string][][]byte{
			"objectGUID": {make([]byte, 16)}, "objectClass": {[]byte("top"), []byte(class)},
			"uSNChanged": {[]byte("42")}, "name": {[]byte("owned")}, "cn": {[]byte("owned")},
			"distinguishedName": {[]byte(dn)},
		}
		for name, values := range extra {
			attributes[name] = values
		}
		return portableReaderSearchResponse(connection, request, dn, attributes, true, partial)
	}
}

func TestPortableCentralAccessRejectsMalformedPolicyWithoutWrite(t *testing.T) {
	certificate, roots := portableTLSCertificate(t, portableTLSHost, false, false)
	wire := newPortableLDAPWire(t, admodel.TransportLDAPS, certificate,
		portableLDAPBind(0), portablePolicyRoot(), portablePolicyRoot())
	_, client := portableLDAPSession(t, portableTLSConfig(admodel.TransportLDAPS, roots), wire)
	invalid := "not SDDL"
	result, err := centralaccess.New(client).CreateCentralAccessRule(t.Context(), admodel.CreateCentralAccessRuleRequest{
		Name: "invalid", CurrentACL: &invalid,
	})
	if !errors.Is(err, conditions.ErrInvalidExpression) || !errors.Is(err, admodel.ErrCentralAccess) ||
		errors.Is(err, admodel.ErrUnsupported) || result.Mutation.State != admodel.ObjectWriteNotAttempted {
		t.Fatal("portable policy validation did not reject malformed input before dispatch", result.Mutation.State, err)
	}
	_ = client.Close()
	wire.wait(t)
	if wire.requests.Load() != 3 {
		t.Fatal("invalid policy unexpectedly submitted a directory operation")
	}
}

func portablePolicyRoot() portableLDAPStep {
	return func(connection net.Conn, request *ber.Packet) error {
		if request.Children[1].Tag != ldap.ApplicationSearchRequest || request.Children[1].Children[0].Value != "" ||
			request.Children[1].Children[1].Value != int64(ldap.ScopeBaseObject) {
			return fmt.Errorf("policy fixture expected RootDSE discovery")
		}
		return portableReaderSearchResponse(connection, request, "", map[string][][]byte{
			"supportedCapabilities":         {[]byte(admodel.CapabilityActiveDirectory)},
			"defaultNamingContext":          {[]byte("DC=ad,DC=sdk,DC=test")},
			"configurationNamingContext":    {[]byte("CN=Configuration,DC=ad,DC=sdk,DC=test")},
			"schemaNamingContext":           {[]byte("CN=Schema,CN=Configuration,DC=ad,DC=sdk,DC=test")},
			"namingContexts":                {[]byte("DC=ad,DC=sdk,DC=test"), []byte("CN=Configuration,DC=ad,DC=sdk,DC=test")},
			"domainControllerFunctionality": {[]byte("7")}, "domainFunctionality": {[]byte("7")},
			"isSynchronized": {[]byte("TRUE")}, "dsServiceName": {[]byte("CN=NTDS Settings,CN=fixture," + portablePolicyConfiguration)},
		}, false, false)
	}
}
