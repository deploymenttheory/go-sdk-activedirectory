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
	"github.com/deploymenttheory/go-sdk-activedirectory/activedirectory/services/memberships"
)

// TestPortableGroupMembersNamingContext reproduces AD DS continuation references on an empty group's primary-member search.
func TestPortableGroupMembersNamingContext(t *testing.T) {
	for _, mode := range []string{"empty", "primary", "refused", "references", "denied"} {
		t.Run(mode, func(t *testing.T) { portableGroupMembersNamingContext(t, mode) })
	}
}

func portableGroupMembersNamingContext(t *testing.T, mode string) {
	t.Helper()
	group := InternalMembershipObject("group", portableMutationDomain, "group", 2, 1101, 1)
	member := InternalMembershipObject("member", portableMutationDomain, "user", 3, 1102, 1)
	member.Attributes["primarygroupid"] = [][]byte{[]byte("1101")}
	certificate, roots := portableTLSCertificate(t, portableTLSHost, false, false)
	wire := newPortableLDAPWire(t, admodel.TransportLDAPS, certificate,
		portableLDAPBind(0), portableMutationRoot(), portableMutationRoot(), portableMembershipObject(group, false),
		portableGroupMemberRange(group, "member;range=0-1499", "member;range=0-*", 0, 0, false, false),
		portableGroupMembersPrimarySearch(mode, member),
	)
	_, client := portableLDAPSession(t, portableTLSConfig(admodel.TransportLDAPS, roots), wire)
	result, err := memberships.New(client).GroupMembers(t.Context(), InternalGroupMemberDN(t, group.DistinguishedName), memberships.GroupMembersOptions{})
	_ = client.Close()
	wire.wait(t)
	if len(result.Groups) != 1 || !result.Groups[0].Links.Complete {
		t.Fatal("membership query lost its completed direct ranges", err)
	}
	switch mode {
	case "empty", "primary":
		if err != nil || !result.Complete || !result.Groups[0].PrimaryMembers.Complete {
			t.Fatal("single-context primary search was incomplete", err)
		}
		if mode == "empty" && len(result.Members) != 0 {
			t.Fatal("empty group acquired a fabricated member")
		}
		if mode == "primary" && (len(result.Members) != 1 || !result.Members[0].Primary ||
			result.Members[0].Object.DistinguishedName != member.DistinguishedName) {
			t.Fatal("primary membership was discarded or misidentified")
		}
	case "references":
		if !errors.Is(err, admodel.ErrSearchReferences) || result.Complete || result.Groups[0].PrimaryMembers.Complete ||
			len(result.Groups[0].PrimaryMembers.Objects) != 1 {
			t.Fatal("unexpected continuation references were hidden or partial observations discarded", err)
		}
	case "refused", "denied":
		code := uint32(12)
		if mode == "denied" {
			code = 50
		}
		var refusal *admodel.LDAPError
		if !errors.As(err, &refusal) || refusal.Code != code || result.Complete || result.Groups[0].PrimaryMembers.Complete {
			t.Fatal("critical-control refusal or access denial was hidden", err)
		}
	}
	if wire.requests.Load() != 6 {
		t.Fatal("membership search opened another connection or replayed a request", wire.requests.Load())
	}
}

// portableGroupMembersPrimarySearch models the server's naming-context boundary without chasing references.
func portableGroupMembersPrimarySearch(mode string, member admodel.Object) portableLDAPStep {
	return func(connection net.Conn, request *ber.Packet) error {
		protocol := request.Children[1]
		if protocol.Tag != ldap.ApplicationSearchRequest || protocol.Children[0].Value != portableMutationDomain ||
			protocol.Children[1].Value != int64(ldap.ScopeWholeSubtree) {
			return fmt.Errorf("primary membership search lost its explicit naming context")
		}
		if _, _, err := portableLDAPPaging(request); err != nil {
			return err
		}
		filter, err := ldap.CompileFilter("(&(objectSid=*)(primaryGroupID=1101))")
		if err != nil || !bytes.Equal(protocol.Children[6].Bytes(), filter.Bytes()) {
			return fmt.Errorf("primary membership search changed the selected group's RID filter")
		}
		scoped := false
		for _, control := range request.Children[2].Children {
			if control.Children[0].Value == "1.2.840.113556.1.4.1339" {
				if len(control.Children) != 2 || control.Children[1].Value != true {
					return fmt.Errorf("naming-context control must be critical and have no value")
				}
				scoped = true
			}
		}
		if !scoped {
			return portableDeletionReferenceResponse(connection, request, "", nil, "empty-references")
		}
		if len(request.Children[2].Children) != 2 {
			return fmt.Errorf("membership search added unrelated controls")
		}
		if mode == "primary" {
			return portableReaderSearchResponse(connection, request, member.DistinguishedName, member.Attributes, true, false)
		}
		if mode == "references" {
			return portableDeletionReferenceResponse(connection, request, member.DistinguishedName, member.Attributes, "references")
		}
		code := int64(0)
		if mode == "refused" {
			code = 12
		} else if mode == "denied" {
			code = 50
		}
		_, err = connection.Write(portableLDAPResult(request, ldap.ApplicationSearchResultDone, code, &ldap.ControlPaging{}).Bytes())
		return err
	}
}

// TestPortableOrdinarySearchRetainsReferences proves the membership boundary does not change public Search scope or diagnostics.
func TestPortableOrdinarySearchRetainsReferences(t *testing.T) {
	for _, mode := range []string{"public", "catalog-namespace"} {
		t.Run(mode, func(t *testing.T) { portableUnscopedSearchRetainsReferences(t, mode) })
	}
}

func portableUnscopedSearchRetainsReferences(t *testing.T, mode string) {
	t.Helper()
	certificate, roots := portableTLSCertificate(t, portableTLSHost, false, false)
	wire := newPortableLDAPWire(t, admodel.TransportLDAPS, certificate, portableLDAPBind(0),
		func(connection net.Conn, request *ber.Packet) error {
			if len(request.Children) != 3 || len(request.Children[2].Children) != 1 ||
				request.Children[2].Children[0].Children[0].Value != ldap.ControlTypePaging {
				return fmt.Errorf("ordinary search unexpectedly changed its naming-context scope")
			}
			return portableDeletionReferenceResponse(connection, request, "", nil, "empty-references")
		},
	)
	_, client := portableLDAPSession(t, portableTLSConfig(admodel.TransportLDAPS, roots), wire)
	query := admodel.SearchOptions{Base: portableMutationDomain, Scope: admodel.ScopeSubtree}
	search := client.Search
	if mode == "catalog-namespace" {
		query.Base = ""
		endpoint := adengine.InternalMembershipEndpoint{InternalClient: client}
		search = endpoint.InternalSearch
	}
	result, err := search(t.Context(), query)
	_ = client.Close()
	wire.wait(t)
	if !errors.Is(err, admodel.ErrSearchReferences) || result.Complete || len(result.Objects) != 0 {
		t.Fatal("ordinary search lost its continuation-reference diagnostic", err)
	}
}
