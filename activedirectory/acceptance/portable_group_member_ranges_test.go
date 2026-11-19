package acceptance

import (
	"fmt"
	"net"
	"testing"

	ber "github.com/go-asn1-ber/asn1-ber"

	ldap "github.com/deploymenttheory/go-sdk-activedirectory/3rd_party/ldap/v3"
	admodel "github.com/deploymenttheory/go-sdk-activedirectory/activedirectory/internal/model"
	"github.com/deploymenttheory/go-sdk-activedirectory/activedirectory/services/memberships"
)

// TestPortableGroupMemberLinksRanges reaches the public service over a real protected portable LDAP connection.
func TestPortableGroupMemberLinksRanges(t *testing.T) {
	for _, mode := range []string{"plain", "ttl", "partial"} {
		t.Run(mode, func(t *testing.T) {
			group := InternalMembershipObject("group", portableMutationDomain, "group", 2, 1101, 1)
			certificate, roots := portableTLSCertificate(t, portableTLSHost, false, false)
			wire := newPortableLDAPWire(t, admodel.TransportLDAPS, certificate,
				portableLDAPBind(0), portableMutationRoot(admodel.InternalGroupLinkTTL), portableMembershipObject(group, false),
				portableGroupMemberRange(group, "member;range=0-9", "member;range=0-1", 0, 2, mode == "ttl", false),
				portableGroupMemberRange(group, "member;range=2-9", "member;range=2-*", 2, 1, mode == "ttl", mode == "partial"),
			)
			_, client := portableLDAPSession(t, portableTLSConfig(admodel.TransportLDAPS, roots), wire)
			identity := InternalGroupMemberDN(t, group.DistinguishedName)
			result, err := memberships.New(client).GroupMemberLinks(t.Context(), identity, memberships.GroupMemberLinksOptions{MaxValues: 10, IncludeTTL: mode == "ttl"})
			if mode == "partial" {
				if err == nil || result.Complete || len(result.Members) != 3 || len(result.Ranges) != 2 || result.Ranges[1].Error == nil {
					t.Fatal("partial ranged observation was discarded or claimed complete", err)
				}
			} else if err != nil || !result.Complete || !result.AttributeReturned || len(result.Members) != 3 || len(result.Ranges) != 2 {
				t.Fatal("portable session did not support direct member ranges", err, result.Complete, len(result.Ranges))
			}
			for _, member := range result.Members {
				if (member.RemainingTTLSeconds != nil) != (mode == "ttl") {
					t.Fatal("TTL observation was invented or discarded")
				}
			}
			_ = client.Close()
			wire.wait(t)
			if wire.requests.Load() != 5 {
				t.Fatal("range read opened another session, skipped a batch or replayed an operation", wire.requests.Load())
			}
		})
	}
}

// portableGroupMemberRange checks exact GUID-addressed range selection and optional critical TTL control on the wire.
func portableGroupMemberRange(group admodel.Object, requested, returned string, first, count int, ttl, partial bool) portableLDAPStep {
	return func(connection net.Conn, request *ber.Packet) error {
		protocol := request.Children[1]
		if protocol.Tag != ldap.ApplicationSearchRequest || protocol.Children[0].Value != InternalMembershipObjectKey(group) ||
			protocol.Children[1].Value != int64(ldap.ScopeBaseObject) || protocol.Children[7].Children[0].Value != requested {
			return fmt.Errorf("portable member range lost its exact GUID, base scope or requested range")
		}
		if ttl {
			if len(request.Children) != 3 || len(request.Children[2].Children) != 1 {
				return fmt.Errorf("portable TTL member range omitted its single control")
			}
			control := request.Children[2].Children[0]
			if len(control.Children) != 2 || control.Children[0].Value != admodel.InternalGroupLinkTTL || control.Children[1].Value != true {
				return fmt.Errorf("portable TTL member range changed control identity or criticality")
			}
		} else if len(request.Children) != 2 {
			return fmt.Errorf("plain portable member range introduced an unrelated control")
		}
		attributes := map[string][][]byte{"objectGUID": group.Attributes["objectguid"], "uSNChanged": group.Attributes["usnchanged"]}
		for index := range count {
			dn := fmt.Sprintf("CN=member%d,%s", first+index, portableMutationDomain)
			if ttl {
				dn = "<TTL=60," + dn + ">"
			}
			attributes[returned] = append(attributes[returned], []byte(dn))
		}
		return portableReaderSearchResponse(connection, request, group.DistinguishedName, attributes, false, partial)
	}
}
