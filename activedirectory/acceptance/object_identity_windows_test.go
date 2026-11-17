//go:build windows && (amd64 || arm64)

package acceptance

import (
	"context"
	"errors"
	"testing"

	"github.com/deploymenttheory/go-bindings-win32/bindings/win32/networking/ldap"
	adengine "github.com/deploymenttheory/go-sdk-activedirectory/activedirectory/internal/engine"
	admodel "github.com/deploymenttheory/go-sdk-activedirectory/activedirectory/internal/model"
)

// Only discovery is fixed. Search uses real WinLDAP against the existing
// loopback BER responder, including paging, copying and allocation cleanup.
type InternalIdentityNativeSession struct {
	admodel.InternalDirectorySession
}

func (s InternalIdentityNativeSession) InternalBaseObject(
	ctx context.Context,
	base string,
	properties []string,
) (map[string][][]byte, error) {
	if base == "" {
		return InternalIdentityTestRoot(admodel.CapabilityActiveDirectory), nil
	}
	return s.InternalDirectorySession.InternalBaseObject(ctx, base, properties)
}

func TestNativeIdentityResolutionRetainsErrorsAndReleasesSearchOwners(t *testing.T) {
	for _, tc := range []struct {
		InternalName string
		InternalPage InternalSearchWirePage
		InternalWant error
	}{
		{"unique", InternalSearchWirePage{InternalCount: 1, InternalEmptyCookie: true}, nil},
		// A continuation reference names a partition this search never asked
		// about. It must not withhold a unique in-scope match, or no GUID, SID
		// or account name could resolve in a domain, every one of which holds
		// subordinate naming contexts beneath its root.
		{"reference", InternalSearchWirePage{InternalCount: 1, InternalEmptyCookie: true, InternalReference: true}, nil},
		// A reference must not excuse a failure beside it: the permission error
		// still has to surface.
		{"reference with permission failure", InternalSearchWirePage{InternalCount: 1, InternalCode: 50, InternalEmptyCookie: true, InternalReference: true}, admodel.ErrIncompleteResult},
		{"ambiguous", InternalSearchWirePage{InternalCount: 2}, admodel.ErrAmbiguousIdentity},
		{"permission partial", InternalSearchWirePage{InternalCount: 1, InternalCode: 50, InternalEmptyCookie: true}, admodel.ErrIncompleteResult},
	} {
		t.Run(tc.InternalName, func(t *testing.T) {
			fixture := InternalNewSearchWireFixture(t, []InternalSearchWirePage{tc.InternalPage})
			counts := &InternalSearchNativeCounts{}
			api := InternalCountedSearchAPI(counts)
			original := api.InternalSearch
			searches := 0
			api.InternalSearch = func(handle *ldap.LDAP, base *string, scope uint32, filter string, properties **uint16, attrsOnly uint32, server, client **ldap.LDAPControlW, timeout, limit uint32, id *uint32) uint32 {
				if base != nil && *base != "" {
					searches++
					if *base != "DC=example" || scope != uint32(admodel.ScopeSubtree) ||
						filter != `(objectGUID=\33\22\11\00\55\44\77\66\88\99\aa\bb\cc\dd\ee\ff)` {
						t.Errorf(
							"unexpected native identity search: %s %d %s",
							*base,
							scope,
							filter,
						)
					}
				}
				return original(
					handle,
					base,
					scope,
					filter,
					properties,
					attrsOnly,
					server,
					client,
					timeout,
					limit,
					id,
				)
			}
			client := InternalSearchWireClient(t, fixture, api)
			(*adengine.InternalClientSessionPointer(client)) = InternalIdentityNativeSession{
				adengine.InternalClientSession(client),
			}
			identity, _ := admodel.IdentityByGUID("00112233-4455-6677-8899-aabbccddeeff")
			result, err := client.ResolveIdentity(
				context.Background(),
				identity,
				admodel.ResolveIdentityOptions{},
			)
			if !errors.Is(err, tc.InternalWant) || searches == 0 ||
				*counts != (InternalSearchNativeCounts{}) {
				t.Fatalf("%+v %v searches=%d owners=%+v", result, err, searches, counts)
			}
			if tc.InternalWant == nil && (!result.Complete || result.Object == nil) {
				t.Fatal("unique native resolution incomplete")
			}
			if tc.InternalWant != nil && (result.Object != nil || result.Complete) {
				t.Fatal("partial match selected")
			}
			if tc.InternalPage.InternalCode == 50 {
				var native *admodel.LDAPError
				if !errors.As(err, &native) || native.Code != 50 ||
					native.Diagnostic != "private test diagnostic" {
					t.Fatal("native details lost", err)
				}
			}
			// The responder deliberately emits malformed five-byte GUIDs. Raw
			// access survives native release, while explicit conversion rejects it.
			value, valueErr := result.Candidates[0].Values("objectGUID").Single()
			if valueErr != nil || len(value.Bytes()) != 5 {
				t.Fatal("copied raw value lost", valueErr)
			}
			if _, err := value.GUID(); !errors.Is(err, admodel.ErrInvalidValue) {
				t.Fatal("malformed GUID accepted")
			}
		})
	}
}
