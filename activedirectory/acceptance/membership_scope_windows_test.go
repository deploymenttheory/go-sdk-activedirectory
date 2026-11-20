//go:build windows && (amd64 || arm64)

package acceptance

import (
	"errors"
	"testing"
	"unsafe"

	"github.com/deploymenttheory/go-bindings-win32/bindings/win32/networking/ldap"
	adengine "github.com/deploymenttheory/go-sdk-activedirectory/activedirectory/internal/engine"
	admodel "github.com/deploymenttheory/go-sdk-activedirectory/activedirectory/internal/model"
)

// TestNativeMembershipNamingContextControls checks the WinLDAP control boundary on every page and cookie release.
// Authentication is covered by protected lab runs; this loopback fixture exercises native cursor ownership and parsing.
func TestNativeMembershipNamingContextControls(t *testing.T) {
	for _, mode := range []string{"complete", "limit", "refused", "references"} {
		t.Run(mode, func(t *testing.T) {
			pages := []InternalSearchWirePage{{}, {InternalEmptyCookie: true}}
			query := admodel.SearchOptions{Base: "DC=example", Scope: admodel.ScopeSubtree, PageSize: 2}
			switch mode {
			case "limit":
				pages = []InternalSearchWirePage{{InternalCount: 1}}
				query.ResultLimit = 1
			case "refused":
				pages = []InternalSearchWirePage{{InternalCode: 12, InternalEmptyCookie: true}}
			case "references":
				pages = []InternalSearchWirePage{{InternalCount: 1, InternalReference: true, InternalEmptyCookie: true}}
			}
			fixture := InternalNewSearchWireFixture(t, pages)
			var owners InternalSearchNativeCounts
			api := InternalCountedSearchAPI(&owners)
			search := api.InternalSearch
			calls := 0
			api.InternalSearch = func(
				handle *ldap.LDAP, base *string, scope uint32, filter string, attributes **uint16, attributesOnly uint32,
				serverControls, clientControls **ldap.LDAPControlW, seconds, limit uint32, id *uint32,
			) uint32 {
				calls++
				if serverControls == nil || clientControls != nil {
					t.Fatal("membership query lost its server controls")
				}
				controls := unsafe.Slice(serverControls, 3)
				if controls[0] == nil || controls[1] == nil || controls[2] != nil {
					t.Fatal("membership query did not retain exactly paging and domain scope")
				}
				oid, err := adengine.InternalCopyLDAPText(controls[1].Ldctl_oid)
				if err != nil || oid != "1.2.840.113556.1.4.1339" || controls[1].Ldctl_iscritical != 1 ||
					controls[1].Ldctl_value.Bv_len != 0 {
					t.Fatal("membership naming-context control changed identity, criticality or value", err)
				}
				return search(handle, base, scope, filter, attributes, attributesOnly, serverControls, clientControls, seconds, limit, id)
			}
			client := InternalSearchWireClient(t, fixture, api)
			endpoint := adengine.InternalMembershipEndpoint{InternalClient: client, InternalPartition: query.Base}
			result, err := endpoint.InternalSearch(t.Context(), query)
			switch mode {
			case "complete":
				if err != nil || !result.Complete || calls != 2 {
					t.Fatal("scoped search did not complete through both pages", err, calls)
				}
			case "limit":
				if err != nil || result.Complete || !result.LimitReached || len(result.Objects) != 1 || calls != 2 {
					t.Fatal("bounded search did not retain its result and release the scoped cookie", err, calls)
				}
			case "refused":
				var refusal *admodel.LDAPError
				if !errors.As(err, &refusal) || refusal.Code != 12 || result.Complete || calls != 1 {
					t.Fatal("native critical-control refusal was hidden", err, calls)
				}
			case "references":
				if !errors.Is(err, admodel.ErrSearchReferences) || result.Complete || len(result.Objects) != 1 || calls != 1 {
					t.Fatal("native unexpected reference or partial result was hidden", err, calls)
				}
			}
			if err := client.Close(); err != nil {
				t.Fatal(err)
			}
			if owners != (InternalSearchNativeCounts{}) {
				t.Fatal("native membership query leaked cursor ownership", owners)
			}
		})
	}
}
