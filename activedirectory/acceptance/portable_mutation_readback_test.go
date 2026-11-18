package acceptance

import (
	"errors"
	"fmt"
	"net"
	"testing"

	ber "github.com/go-asn1-ber/asn1-ber"

	ldap "github.com/deploymenttheory/go-sdk-activedirectory/3rd_party/ldap/v3"
	admodel "github.com/deploymenttheory/go-sdk-activedirectory/activedirectory/internal/model"
	claims "github.com/deploymenttheory/go-sdk-activedirectory/activedirectory/services/claims"
)

func TestPortableClaimLinkClearUsesTheCommonVerificationContract(t *testing.T) {
	for _, retained := range []bool{false, true} {
		t.Run(fmt.Sprint("retained=", retained), func(t *testing.T) {
			attribute := admodel.InternalClaimTransformEgressAttribute
			before := map[string][][]byte{"objectClass": {[]byte("trustedDomain")}, attribute: {[]byte("CN=Policy,CN=Configuration," + portableMutationDomain)}}
			after := map[string][][]byte{"objectClass": {[]byte("trustedDomain")}}
			if retained {
				after[attribute] = before[attribute]
			}
			certificate, roots := portableTLSCertificate(t, portableTLSHost, false, false)
			wire := newPortableLDAPWire(t, admodel.TransportLDAPS, certificate,
				portableLDAPBind(0), portableMutationRoot(), portableMutationObject(before),
				func(connection net.Conn, request *ber.Packet) error {
					protocol := request.Children[1]
					if protocol.Tag != ldap.ApplicationModifyRequest || len(protocol.Children[1].Children) != 1 {
						return fmt.Errorf("claim link fixture expected one explicit clear")
					}
					change := protocol.Children[1].Children[0]
					if change.Children[0].Value != int64(1) || change.Children[1].Children[0].Value != attribute || len(change.Children[1].Children[1].Children) != 0 {
						return fmt.Errorf("claim link clear changed the requested attribute or value semantics")
					}
					_, err := connection.Write(portableLDAPResult(request, ldap.ApplicationModifyResponse, 0).Bytes())
					return err
				}, portableMutationObject(after))
			_, client := portableLDAPSession(t, portableTLSConfig(admodel.TransportLDAPS, roots), wire)
			identity, err := admodel.IdentityByDN("CN=owned," + portableMutationDomain)
			if err != nil {
				t.Fatal(err)
			}
			result, err := claims.New(client).ClearClaimTransformLink(t.Context(), claims.ClaimTransformLinkRequest{Trust: identity, Direction: claims.ClaimTransformEgress})
			want := admodel.ErrObjectUnverifiable
			if retained {
				want = admodel.ErrObjectVerification
			}
			if !errors.Is(err, want) || result.Mutation.State != admodel.ObjectWriteAccepted || result.Mutation.Verified ||
				!result.Mutation.ReadbackComplete || result.Mutation.After == nil || result.Mutation.Before == nil || result.Mutation.TargetGUID == nil {
				t.Fatal("claim link clear bypassed the common unverified/contradicted observation contract", result, err)
			}
			_ = client.Close()
			wire.wait(t)
			if wire.requests.Load() != 5 {
				t.Fatal("accepted clear was replayed", wire.requests.Load())
			}
		})
	}
}
