//go:build windows && (amd64 || arm64)

package activedirectory

import (
	"context"
	"errors"
	"testing"

	"github.com/deploymenttheory/go-bindings-win32/bindings/win32/networking/ldap"
)

func TestNativeAccountCreationDefaultMappingAndCleanup(t *testing.T) {
	for _, code := range []byte{0, 50} {
		container := `OU=People: Jörg\, 李,DC=example`
		fixture := newSearchWireFixture(t, []searchWirePage{{count: 1, code: code, emptyCookie: true, dn: "DC=example", attributes: map[string][][]byte{
			"objectGUID":       {objectTestGUID().Bytes()},
			"wellKnownObjects": {[]byte("B:32:" + wellKnownUsers + ":" + container)},
		}}})
		counts := &searchNativeCounts{}
		api := countedSearchAPI(counts)
		original := api.search
		searches := 0
		api.search = func(handle *ldap.LDAP, base *string, scope uint32, filter string, properties **uint16, attrsOnly uint32, server, client **ldap.LDAPControlW, timeout, limit uint32, id *uint32) uint32 {
			if base != nil && *base != "" {
				searches++
				if *base != "DC=example" || scope != uint32(ScopeBase) || filter != "(objectClass=*)" {
					t.Errorf("unexpected default-container search: %s %d %s", *base, scope, filter)
				}
			}
			return original(handle, base, scope, filter, properties, attrsOnly, server, client, timeout, limit, id)
		}
		client := searchWireClient(t, fixture, api)
		root, err := decodeRootDSE(identityTestRoot(CapabilityActiveDirectory), defaultRootDSEAttributes())
		if err != nil {
			t.Fatal(err)
		}
		var parent Identity
		err = client.read(context.Background(), func(ctx context.Context) error {
			var readErr error
			parent, readErr = accountCreationParent(ctx, client.session, client.config, root, Identity{}, ObjectMutationOptions{}, wellKnownUsers)
			return readErr
		})
		if searches != 1 || *counts != (searchNativeCounts{}) {
			t.Fatal("unexpected dispatch or retained native owner", searches, counts)
		}
		if code == 0 {
			if err != nil || parent.value != container {
				t.Fatal(parent, err)
			}
		} else {
			var native *LDAPError
			var lookup *AccountCreationParentError
			if !errors.As(err, &native) || native.Code != 50 || !errors.As(err, &lookup) || len(lookup.Observation.Candidates) != 1 || parent.Form() != 0 {
				t.Fatal("partial lookup selected a parent or lost native detail", parent, err)
			}
		}
	}
}
