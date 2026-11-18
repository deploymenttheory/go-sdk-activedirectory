package acceptance

import (
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
			"supportedCapabilities":      {[]byte(admodel.CapabilityActiveDirectory)},
			"defaultNamingContext":       {[]byte("DC=ad,DC=sdk,DC=test")},
			"configurationNamingContext": {[]byte("CN=Configuration,DC=ad,DC=sdk,DC=test")},
			"schemaNamingContext":        {[]byte("CN=Schema,CN=Configuration,DC=ad,DC=sdk,DC=test")},
			"namingContexts":             {[]byte("DC=ad,DC=sdk,DC=test"), []byte("CN=Configuration,DC=ad,DC=sdk,DC=test")},
		}, false, false)
	}
}
