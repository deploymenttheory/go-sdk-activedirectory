package acceptance

import (
	"bytes"
	"errors"
	"fmt"
	"net"
	"testing"

	ber "github.com/go-asn1-ber/asn1-ber"

	ldap "github.com/deploymenttheory/go-sdk-activedirectory/3rd_party/ldap/v3"
	admodel "github.com/deploymenttheory/go-sdk-activedirectory/activedirectory/internal/model"
	centralaccess "github.com/deploymenttheory/go-sdk-activedirectory/activedirectory/services/central_access"
	"github.com/deploymenttheory/go-sdk-activedirectory/conditions"
)

func TestPortableCentralRuleCreateUsesExactTextAndRetainsRefusal(t *testing.T) {
	for _, code := range []int64{0, 50, 68} {
		t.Run(fmt.Sprint(code), func(t *testing.T) {
			certificate, roots := portableTLSCertificate(t, portableTLSHost, false, false)
			parent := admodel.InternalCentralAccessParent(portablePolicyConfiguration, false)
			dn := "cn=owned," + parent
			current, proposed := "O:SYG:SYD:(A;;FR;;;WD)", `D:(XA;;FW;;;WD;(@User.Department == "Cymru £"))`
			conditionText := `@Resource.Department == "Cymru £"`
			condition := conditions.Raw(conditionText)
			attributes := map[string][]byte{
				admodel.InternalCentralCurrent: []byte(current), admodel.InternalCentralProposed: []byte(proposed),
				admodel.InternalCentralCondition: []byte(conditionText), "objectClass": []byte("msAuthz-CentralAccessRule"), "cn": []byte("owned"),
			}
			steps := []portableLDAPStep{
				portableLDAPBind(0), portablePolicyRoot(), portablePolicyRoot(), portablePolicyRoot(),
				portablePolicyObject(parent, "container", nil, false),
				func(connection net.Conn, request *ber.Packet) error {
					if request.Children[1].Tag != ldap.ApplicationSearchRequest ||
						request.Children[1].Children[0].Value != "CN=Schema,"+portablePolicyConfiguration {
						return fmt.Errorf("rule naming attribute was not discovered from schema")
					}
					return portableReaderSearchResponse(connection, request, "CN=fixture-class,CN=Schema,"+portablePolicyConfiguration,
						map[string][][]byte{"rDNAttID": {[]byte("cn")}, "objectClassCategory": {[]byte("1")}}, true, false)
				},
				func(connection net.Conn, request *ber.Packet) error {
					if err := portablePolicyAdd(request, dn, attributes); err != nil {
						return err
					}
					_, err := connection.Write(portableLDAPResult(request, ldap.ApplicationAddResponse, code).Bytes())
					return err
				},
			}
			if code == 0 {
				steps = append(steps, portablePolicyObject(dn, "msAuthz-CentralAccessRule", map[string][][]byte{
					admodel.InternalCentralCurrent: {[]byte(current)}, admodel.InternalCentralProposed: {[]byte(proposed)},
					admodel.InternalCentralCondition: {[]byte(conditionText)},
				}, false))
			}
			wire := newPortableLDAPWire(t, admodel.TransportLDAPS, certificate, steps...)
			_, client := portableLDAPSession(t, portableTLSConfig(admodel.TransportLDAPS, roots), wire)
			result, err := centralaccess.New(client).CreateCentralAccessRule(t.Context(), admodel.CreateCentralAccessRuleRequest{
				Name: "owned", CurrentACL: &current, ProposedACL: &proposed, ResourceCondition: &condition,
			})
			if code == 0 {
				if err != nil || result.Mutation.State != admodel.ObjectWriteAccepted || !result.Mutation.Verified || result.Rule == nil ||
					result.Rule.ResourceCondition == nil || *result.Rule.ResourceCondition != conditionText {
					t.Fatal("portable rule creation lost exact text or readback", result, err)
				}
			} else {
				var response *admodel.LDAPError
				if result.Mutation.State != admodel.ObjectWriteRejected || result.Mutation.Verified || !errors.As(err, &response) || response.Code != uint32(code) {
					t.Fatal("portable rule creation lost actual refusal", result, err)
				}
			}
			_ = client.Close()
			wire.wait(t)
			if wire.requests.Load() != int32(len(steps)) {
				t.Fatal("rule creation was retried or a refusal was read back", wire.requests.Load())
			}
		})
	}
}

func portablePolicyAdd(request *ber.Packet, dn string, expected map[string][]byte) error {
	if len(request.Children) != 2 {
		return fmt.Errorf("rule Add used an unexpected control")
	}
	protocol := request.Children[1]
	if protocol.Tag != ldap.ApplicationAddRequest || len(protocol.Children) != 2 || protocol.Children[0].Value != dn ||
		len(protocol.Children[1].Children) != len(expected) {
		return fmt.Errorf("rule Add changed its target or attribute count")
	}
	seen := make(map[string]bool)
	for _, attribute := range protocol.Children[1].Children {
		name, ok := attribute.Children[0].Value.(string)
		if !ok || seen[name] || len(attribute.Children) != 2 || len(attribute.Children[1].Children) != 1 {
			return fmt.Errorf("rule Add duplicated or changed an attribute")
		}
		seen[name] = true
		want, found := expected[name]
		if !found || !bytes.Equal(attribute.Children[1].Children[0].Data.Bytes(), want) {
			return fmt.Errorf("rule Add changed policy text into binary or approximated it")
		}
	}
	return nil
}
