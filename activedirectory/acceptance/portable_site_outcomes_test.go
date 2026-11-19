package acceptance

import (
	"bytes"
	"errors"
	"fmt"
	"maps"
	"net"
	"testing"

	ber "github.com/go-asn1-ber/asn1-ber"

	ldap "github.com/deploymenttheory/go-sdk-activedirectory/3rd_party/ldap/v3"
	admodel "github.com/deploymenttheory/go-sdk-activedirectory/activedirectory/internal/model"
	replication "github.com/deploymenttheory/go-sdk-activedirectory/activedirectory/services/replication"
)

func TestPortableSiteUpdateKeepsAcceptedRootAcrossSecondObjectFailure(t *testing.T) {
	for _, mode := range []string{"denied", "lost", "malformed"} {
		t.Run(mode, func(t *testing.T) {
			configuration := "CN=Configuration," + portableMutationDomain
			siteDN := "CN=owned,CN=Sites," + configuration
			fixture := &portableSiteOutcomeFixture{
				mode: mode, configuration: configuration,
				site: InternalTopologyTestObject(siteDN, "site", 1), settings: InternalTopologyTestObject("CN=NTDS Site Settings,"+siteDN, "nTDSSiteSettings", 2),
			}
			fixture.settings.Attributes["options"] = [][]byte{[]byte("65536")}
			steps := []portableLDAPStep{portableLDAPBind(0)}
			// The fixture answers only these two pinned objects and RootDSE; it
			// independently validates both actual Modify messages, never retries.
			for range 20 {
				steps = append(steps, fixture.step)
			}
			certificate, roots := portableTLSCertificate(t, portableTLSHost, false, false)
			wire := newPortableLDAPWire(t, admodel.TransportLDAPS, certificate, steps...)
			_, client := portableLDAPSession(t, portableTLSConfig(admodel.TransportLDAPS, roots), wire)
			identity, err := admodel.IdentityByDN(siteDN)
			if err != nil {
				t.Fatal(err)
			}
			description := "accepted-owned-description"
			result, err := replication.New(client).UpdateReplicationSite(t.Context(), replication.UpdateReplicationSiteRequest{
				Identity: identity, Description: &description, Settings: &replication.ReplicationSiteSettingsPatch{SetOptions: replication.SiteDisableAutomaticTopology},
			})
			if !errors.Is(err, replication.ErrReplicationTopologyIncomplete) || admodel.Classify(err) != admodel.ClassUncertain || result.Complete ||
				!result.Mutation.PartialEffectsPossible || result.Mutation.Verified || result.Mutation.ReadbackComplete ||
				result.Mutation.TargetGUID == nil || result.Mutation.TargetDN != siteDN || result.Mutation.Before == nil || result.Mutation.After == nil ||
				len(result.Steps) != 2 || result.Steps[0].Mutation.State != admodel.ObjectWriteAccepted || !result.Steps[0].Mutation.Verified ||
				result.Steps[0].Mutation.TargetGUID == nil || *result.Mutation.TargetGUID != *result.Steps[0].Mutation.TargetGUID ||
				result.Steps[1].Mutation.TargetGUID == nil || *result.Steps[1].Mutation.TargetGUID == *result.Mutation.TargetGUID {
				t.Fatal("second-object failure hid or misidentified the accepted site-root effect", result, err)
			}
			value, valueErr := result.Mutation.After.Values("description").Single()
			if valueErr != nil || string(value.Bytes()) != description {
				t.Fatal("aggregate lost the observed root change", result, err)
			}
			if mode == "denied" {
				var status *admodel.LDAPError
				if !errors.As(err, &status) || status.Code != 50 || result.Mutation.State != admodel.ObjectWriteAccepted ||
					result.Steps[1].Mutation.State != admodel.ObjectWriteRejected {
					t.Fatal("later actual denial replaced the earlier acknowledgement", result, err)
				}
			} else if result.Mutation.State != admodel.ObjectWriteUncertain || result.Steps[1].Mutation.State != admodel.ObjectWriteUncertain ||
				!errors.Is(err, admodel.ErrObjectWriteUncertain) {
				t.Fatal("submitted second-object uncertainty was fabricated as a refusal", result, err)
			}
			_ = client.Close()
			wire.wait(t)
			if fixture.writes != 2 {
				t.Fatal("site workflow replayed or skipped a requested object write", fixture.writes)
			}
		})
	}
}

type portableSiteOutcomeFixture struct {
	mode, configuration string
	site, settings      admodel.Object
	writes              int
}

func (f *portableSiteOutcomeFixture) step(connection net.Conn, request *ber.Packet) error {
	protocol := request.Children[1]
	if protocol.Tag == ldap.ApplicationModifyRequest {
		f.writes++
		object := f.site
		expected := []struct {
			operation int64
			attribute string
			value     string
		}{{2, "description", "accepted-owned-description"}}
		if f.writes == 2 {
			object = f.settings
			expected = append(expected[:0], struct {
				operation int64
				attribute string
				value     string
			}{1, "options", "65536"}, struct {
				operation int64
				attribute string
				value     string
			}{0, "options", "65537"})
		}
		if f.writes > 2 || protocol.Children[0].Value != InternalMembershipObjectKey(object) || len(protocol.Children[1].Children) != len(expected) || len(request.Children) != 2 {
			return fmt.Errorf("site fixture expected exactly two distinct GUID-addressed unguarded writes")
		}
		for i, wanted := range expected {
			change := protocol.Children[1].Children[i]
			if change.Children[0].Value != wanted.operation || change.Children[1].Children[0].Value != wanted.attribute ||
				string(change.Children[1].Children[1].Children[0].Data.Bytes()) != wanted.value {
				return fmt.Errorf("site fixture observed different mutation intent or lost unrelated option bits")
			}
		}
		if f.writes == 2 {
			switch f.mode {
			case "lost":
				return connection.Close()
			case "malformed":
				_, err := connection.Write(portableMutationMalformedResult(request, ldap.ApplicationModifyResponse).Bytes())
				return err
			default:
				_, err := connection.Write(portableLDAPResult(request, ldap.ApplicationModifyResponse, 50).Bytes())
				return err
			}
		}
		f.site.Attributes = maps.Clone(f.site.Attributes)
		f.site.Attributes["description"] = [][]byte{[]byte("accepted-owned-description")}
		_, err := connection.Write(portableLDAPResult(request, ldap.ApplicationModifyResponse, 0).Bytes())
		return err
	}
	if protocol.Tag != ldap.ApplicationSearchRequest {
		return fmt.Errorf("site fixture expected a bounded identity observation")
	}
	if protocol.Children[0].Value == "" {
		attributes := map[string][][]byte{
			"supportedCapabilities": {[]byte(admodel.CapabilityActiveDirectory)}, "defaultNamingContext": {[]byte(portableMutationDomain)},
			"configurationNamingContext": {[]byte(f.configuration)}, "namingContexts": {[]byte(portableMutationDomain), []byte(f.configuration)},
		}
		return portableReaderSearchResponse(connection, request, "", attributes, false, false)
	}
	for _, object := range []admodel.Object{f.site, f.settings} {
		value, err := object.Values("objectGUID").Single()
		if err != nil {
			return err
		}
		filter, err := ldap.CompileFilter("(objectGUID=" + admodel.InternalIdentityBinaryLiteral(value.Bytes()) + ")")
		if err != nil {
			return err
		}
		if protocol.Children[0].Value == object.DistinguishedName ||
			(protocol.Children[0].Value == f.configuration && bytes.Equal(filter.Bytes(), protocol.Children[6].Bytes())) {
			return portableReaderSearchResponse(connection, request, object.DistinguishedName, object.Attributes, true, false)
		}
	}
	return fmt.Errorf("site fixture observed an unpinned identity query")
}
