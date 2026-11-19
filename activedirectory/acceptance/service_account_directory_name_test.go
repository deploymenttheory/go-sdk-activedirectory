package acceptance

import (
	"context"
	"errors"
	"maps"
	"slices"
	"strings"
	"testing"

	admodel "github.com/deploymenttheory/go-sdk-activedirectory/activedirectory/internal/model"
	serviceaccounts "github.com/deploymenttheory/go-sdk-activedirectory/activedirectory/services/service_accounts"
)

// TestCreateServiceAccountPasswordFailureRetainsDirectoryName reproduces authoritative attribute spelling differing from an echoed base-search DN.
func TestCreateServiceAccountPasswordFailureRetainsDirectoryName(t *testing.T) {
	client, session := InternalNewServiceAccountTestClient(t)
	session.InternalFailAt = 2
	session.InternalFailure = admodel.InternalLdapWriteAttempt{State: admodel.InternalLdapWriteRejected, Err: &admodel.LDAPError{Code: 19}}
	const submittedDN = "cn=svc,OU=target,DC=example"
	const observedDN = "CN=svc,OU=target,DC=example"
	search := session.InternalSearch
	session.InternalSearch = func(ctx context.Context, query admodel.SearchOptions) (admodel.InternalSearchCursor, error) {
		entry, found := session.InternalLookup(submittedDN)
		if found {
			guid, _ := entry.Values("objectGUID").Single()
			selected := strings.EqualFold(query.Base, submittedDN) || strings.Contains(query.Filter, admodel.InternalIdentityBinaryLiteral(guid.Bytes()))
			if selected {
				entry.Attributes = maps.Clone(entry.Attributes)
				requested := slices.ContainsFunc(query.Properties, func(name string) bool { return strings.EqualFold(name, "distinguishedName") })
				if requested {
					entry.Attributes["distinguishedname"] = [][]byte{[]byte(observedDN)}
				}
				return InternalObjectTestCursor(entry), nil
			}
		}
		return search(ctx, query)
	}
	parent, _ := admodel.IdentityByDN("OU=target,DC=example")
	enabled := true
	result, err := serviceaccounts.New(client).CreateServiceAccount(t.Context(), admodel.CreateServiceAccountRequest{
		Kind: admodel.ServiceAccountStandalone, Parent: parent, Name: "svc", InitialPassword: []byte("PUBLIC-rejected-password"),
		Control: admodel.AccountControlPatch{Enabled: &enabled},
	})
	if !errors.Is(err, admodel.ErrServiceAccountCreationIncomplete) || !result.Creation.Verified || result.Account == nil || result.Account.GUID == nil ||
		result.Account.DistinguishedName != observedDN || result.Creation.TargetDN != observedDN || result.Password == nil ||
		result.Password.State != admodel.ObjectWriteRejected || result.Enable != nil || result.Complete {
		t.Fatal("failed staged service account creation lost the directory-observed DN or accepted identity")
	}
	if result.Account.Raw.DistinguishedName != submittedDN {
		t.Fatal("raw base-search entry was rewritten")
	}
	target, _ := admodel.IdentityByGUID(result.Account.GUID.String())
	read, readErr := serviceaccounts.New(client).ServiceAccount(t.Context(), target, admodel.ResolveIdentityOptions{})
	if readErr != nil || read.Account == nil || read.Account.GUID == nil || *read.Account.GUID != *result.Account.GUID || read.Account.DistinguishedName != observedDN {
		t.Fatal("GUID recovery read disagreed with the retained typed creation observation")
	}
	if len(session.InternalWrites) != 2 || result.Account.AccountControl.Enabled == nil || *result.Account.AccountControl.Enabled {
		t.Fatal("failed password setup was replayed or followed by enablement")
	}
}
