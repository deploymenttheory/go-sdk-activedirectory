//go:build windows && (amd64 || arm64)

package activedirectory

import (
	"context"
	"errors"
	"testing"

	"github.com/deploymenttheory/go-bindings-win32/bindings/win32/networking/ldap"
)

// Only discovery is fixed. Search uses real WinLDAP against the existing
// loopback BER responder, including paging, copying and allocation cleanup.
type identityNativeSession struct{ directorySession }

func (s identityNativeSession) baseObject(ctx context.Context, base string, properties []string) (map[string][][]byte, error) {
	if base == "" {
		return identityTestRoot(CapabilityActiveDirectory), nil
	}
	return s.directorySession.baseObject(ctx, base, properties)
}

func TestNativeIdentityResolutionRetainsErrorsAndReleasesSearchOwners(t *testing.T) {
	for _, tc := range []struct {
		name string
		page searchWirePage
		want error
	}{
		{"unique", searchWirePage{count: 1, emptyCookie: true}, nil},
		{"ambiguous", searchWirePage{count: 2}, ErrAmbiguousIdentity},
		{"permission partial", searchWirePage{count: 1, code: 50, emptyCookie: true}, ErrIncompleteResult},
	} {
		t.Run(tc.name, func(t *testing.T) {
			fixture := newSearchWireFixture(t, []searchWirePage{tc.page})
			counts := &searchNativeCounts{}
			api := countedSearchAPI(counts)
			original := api.search
			searches := 0
			api.search = func(handle *ldap.LDAP, base *string, scope uint32, filter string, properties **uint16, attrsOnly uint32, server, client **ldap.LDAPControlW, timeout, limit uint32, id *uint32) uint32 {
				if base != nil && *base != "" {
					searches++
					if *base != "DC=example" || scope != uint32(ScopeSubtree) || filter != `(objectGUID=\33\22\11\00\55\44\77\66\88\99\aa\bb\cc\dd\ee\ff)` {
						t.Errorf("unexpected native identity search: %s %d %s", *base, scope, filter)
					}
				}
				return original(handle, base, scope, filter, properties, attrsOnly, server, client, timeout, limit, id)
			}
			client := searchWireClient(t, fixture, api)
			client.session = identityNativeSession{client.session}
			identity, _ := IdentityByGUID("00112233-4455-6677-8899-aabbccddeeff")
			result, err := client.ResolveIdentity(context.Background(), identity, ResolveIdentityOptions{})
			if !errors.Is(err, tc.want) || searches == 0 || *counts != (searchNativeCounts{}) {
				t.Fatalf("%+v %v searches=%d owners=%+v", result, err, searches, counts)
			}
			if tc.want == nil && (!result.Complete || result.Object == nil) {
				t.Fatal("unique native resolution incomplete")
			}
			if tc.want != nil && (result.Object != nil || result.Complete) {
				t.Fatal("partial match selected")
			}
			if tc.page.code == 50 {
				var native *LDAPError
				if !errors.As(err, &native) || native.Code != 50 || native.Diagnostic != "private test diagnostic" {
					t.Fatal("native details lost", err)
				}
			}
			// The responder deliberately emits malformed five-byte GUIDs. Raw
			// access survives native release, while explicit conversion rejects it.
			value, valueErr := result.Candidates[0].Values("objectGUID").Single()
			if valueErr != nil || len(value.Bytes()) != 5 {
				t.Fatal("copied raw value lost", valueErr)
			}
			if _, err := value.GUID(); !errors.Is(err, ErrInvalidValue) {
				t.Fatal("malformed GUID accepted")
			}
		})
	}
}
