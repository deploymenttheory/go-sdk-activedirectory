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

func TestNativeAccountCreationDefaultMappingAndCleanup(t *testing.T) {
	for _, code := range []byte{0, 50} {
		container := `OU=People: Jörg\, 李,DC=example`
		fixture := InternalNewSearchWireFixture(
			t,
			[]InternalSearchWirePage{
				{
					InternalCount:       1,
					InternalCode:        code,
					InternalEmptyCookie: true,
					InternalDn:          "DC=example",
					InternalAttributes: map[string][][]byte{
						"objectGUID": {InternalObjectTestGUID().Bytes()},
						"wellKnownObjects": {
							[]byte("B:32:" + admodel.InternalWellKnownUsers + ":" + container),
						},
					},
				},
			},
		)
		counts := &InternalSearchNativeCounts{}
		api := InternalCountedSearchAPI(counts)
		original := api.InternalSearch
		searches := 0
		api.InternalSearch = func(handle *ldap.LDAP, base *string, scope uint32, filter string, properties **uint16, attrsOnly uint32, server, client **ldap.LDAPControlW, timeout, limit uint32, id *uint32) uint32 {
			if base != nil && *base != "" {
				searches++
				if *base != "DC=example" || scope != uint32(admodel.ScopeBase) ||
					filter != "(objectClass=*)" {
					t.Errorf("unexpected default-container search: %s %d %s", *base, scope, filter)
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
		root, err := admodel.InternalDecodeRootDSE(
			InternalIdentityTestRoot(admodel.CapabilityActiveDirectory),
			admodel.InternalDefaultRootDSEAttributes(),
		)
		if err != nil {
			t.Fatal(err)
		}
		var parent admodel.Identity
		err = adengine.InternalClientRead(
			client,
			context.Background(),
			func(ctx context.Context) error {
				var readErr error
				parent, readErr = admodel.InternalAccountCreationParent(
					ctx,
					adengine.InternalClientSession(client),
					adengine.InternalClientConfig(client),
					root,
					admodel.Identity{},
					admodel.ObjectMutationOptions{},
					admodel.InternalWellKnownUsers,
				)
				return readErr
			},
		)
		if searches != 1 || *counts != (InternalSearchNativeCounts{}) {
			t.Fatal("unexpected dispatch or retained native owner", searches, counts)
		}
		if code == 0 {
			if err != nil || admodel.InternalIdentityValue(parent) != container {
				t.Fatal(parent, err)
			}
		} else {
			var native *admodel.LDAPError
			var lookup *admodel.AccountCreationParentError
			if !errors.As(err, &native) || native.Code != 50 || !errors.As(err, &lookup) ||
				len(lookup.Observation.Candidates) != 1 ||
				parent.Form() != 0 {
				t.Fatal("partial lookup selected a parent or lost native detail", parent, err)
			}
		}
	}
}
