package acceptance

import (
	"errors"
	"strings"
	"testing"

	admodel "github.com/deploymenttheory/go-sdk-activedirectory/activedirectory/internal/model"
	authpolicies "github.com/deploymenttheory/go-sdk-activedirectory/activedirectory/services/authentication_policies"
	centralaccess "github.com/deploymenttheory/go-sdk-activedirectory/activedirectory/services/central_access"
	"github.com/deploymenttheory/go-sdk-activedirectory/conditions"
)

func TestPortablePolicyRejectsUnsupportedSyntaxWithoutApproximateWrite(t *testing.T) {
	for _, fixture := range []struct {
		name, descriptor, condition string
	}{
		{name: "missing-right-operand", descriptor: `D:(XA;;CR;;;WD;(@User.Score ==))`},
		{name: "unknown-operator", condition: `@Resource.Score Matches 7`},
		{name: "domain-context-required", descriptor: "D:(A;;GA;;;DA)"},
		{name: "unknown-ace", descriptor: "D:(ZZ;;GA;;;WD)"},
	} {
		t.Run(fixture.name, func(t *testing.T) {
			certificate, roots := portableTLSCertificate(t, portableTLSHost, false, false)
			wire := newPortableLDAPWire(t, admodel.TransportLDAPS, certificate,
				portableLDAPBind(0), portablePolicyRoot(), portablePolicyRoot())
			_, client := portableLDAPSession(t, portableTLSConfig(admodel.TransportLDAPS, roots), wire)
			request := admodel.CreateCentralAccessRuleRequest{Name: "invalid"}
			if fixture.condition != "" {
				expression := conditions.Raw(fixture.condition)
				request.ResourceCondition = &expression
			} else {
				request.ProposedACL = &fixture.descriptor
			}
			result, err := centralaccess.New(client).CreateCentralAccessRule(t.Context(), request)
			if result.Mutation.State != admodel.ObjectWriteNotAttempted || !errors.Is(err, conditions.ErrInvalidExpression) ||
				!errors.Is(err, admodel.ErrCentralAccess) || errors.Is(err, admodel.ErrUnsupported) {
				t.Fatal("portable central rule did not reject unsupported syntax explicitly", result, err)
			}
			if fixture.name == "domain-context-required" && !strings.Contains(err.Error(), "explicit domain SID required") {
				t.Fatal("missing SID context diagnostic was lost", err)
			}
			_ = client.Close()
			wire.wait(t)
			if wire.requests.Load() != 3 {
				t.Fatal("unsupported central policy submitted a write", wire.requests.Load())
			}
		})
	}
}

func TestPortableAuthenticationPolicyRejectsInvalidBinaryInputBeforeDiscovery(t *testing.T) {
	for _, sddl := range []string{
		`D:(XA;;CR;;;WD;(@User.Score ==))`, `D:(XA;;CR;;;WD;(@User.Score Matches 7))`,
		"D:(A;;GR;;;WD)", "D:NO_ACCESS_CONTROL", "D:(A;;GA;;;DA)",
	} {
		t.Run(sddl, func(t *testing.T) {
			certificate, roots := portableTLSCertificate(t, portableTLSHost, false, false)
			wire := newPortableLDAPWire(t, admodel.TransportLDAPS, certificate, portableLDAPBind(0))
			_, client := portableLDAPSession(t, portableTLSConfig(admodel.TransportLDAPS, roots), wire)
			result, err := authpolicies.New(client).CreateAuthenticationPolicy(t.Context(), admodel.CreateAuthenticationPolicyRequest{
				Name: "invalid", Properties: admodel.AuthenticationPolicyProperties{UserAllowedToAuthenticateTo: &sddl},
			})
			if result.Mutation.State != admodel.ObjectWriteNotAttempted || !errors.Is(err, admodel.ErrAuthenticationPolicyDescriptor) {
				t.Fatal("invalid authentication descriptor was approximated or submitted", result, err)
			}
			_ = client.Close()
			wire.wait(t)
			if wire.requests.Load() != 1 {
				t.Fatal("invalid authentication policy reached directory discovery", wire.requests.Load())
			}
		})
	}
}
