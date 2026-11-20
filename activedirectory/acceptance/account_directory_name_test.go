package acceptance

import (
	"context"
	"slices"
	"strings"
	"testing"

	admodel "github.com/deploymenttheory/go-sdk-activedirectory/activedirectory/internal/model"
	accounts "github.com/deploymenttheory/go-sdk-activedirectory/activedirectory/services/accounts"
)

// TestAccountReadsPreferDirectoryName reproduces lower-case base-search echoes disagreeing with the server's authoritative distinguishedName attribute.
func TestAccountReadsPreferDirectoryName(t *testing.T) {
	const canonical = "CN=sample,DC=example"
	const submitted = "cn=sample,dc=example"
	for _, operation := range []string{"control", "expiration"} {
		for _, lookup := range []string{"dn", "guid"} {
			t.Run(operation+"/"+lookup, func(t *testing.T) {
				requested := false
				rawDN := canonical
				if lookup == "dn" {
					rawDN = submitted
				}
				client := InternalObjectTestClient(t, nil, func(_ context.Context, query admodel.SearchOptions) (admodel.InternalSearchCursor, error) {
					object := InternalAccountTestEntry(512)
					object.DistinguishedName = rawDN
					object.Attributes["accountexpires"] = [][]byte{[]byte("0")}
					requested = slices.ContainsFunc(query.Properties, func(name string) bool { return strings.EqualFold(name, "distinguishedName") })
					if requested {
						object.Attributes["distinguishedname"] = [][]byte{[]byte(canonical)}
					}
					return InternalObjectTestCursor(object), nil
				}, func(context.Context, admodel.InternalLdapWriteRequest) admodel.InternalLdapWriteAttempt {
					t.Error("read-only account observation attempted a directory write")
					return admodel.InternalLdapWriteAttempt{}
				})
				target, _ := admodel.IdentityByDN(submitted)
				if lookup == "guid" {
					target, _ = admodel.IdentityByGUID(InternalObjectTestGUID().String())
				}
				service := accounts.New(client)
				var typedDN, originalEntry string
				switch operation {
				case "control":
					result, err := service.AccountControl(t.Context(), target, admodel.ResolveIdentityOptions{})
					if err != nil || result.Account == nil || !result.Observation.Complete {
						t.Fatal("account-control reader did not resolve the fixture identity")
					}
					typedDN, originalEntry = result.Account.DistinguishedName, result.Account.Raw.DistinguishedName
				case "expiration":
					result, err := service.AccountExpiration(t.Context(), target, admodel.ResolveIdentityOptions{})
					if err != nil || result.Expiration == nil || !result.Observation.Complete {
						t.Fatal("expiration reader did not resolve the fixture identity")
					}
					typedDN, originalEntry = result.Expiration.DistinguishedName, result.Expiration.Raw.DistinguishedName
				}
				if !requested || typedDN != canonical || originalEntry != rawDN {
					t.Fatal("typed account DN lost the authoritative attribute or rewrote the original search entry")
				}
			})
		}
	}
}
