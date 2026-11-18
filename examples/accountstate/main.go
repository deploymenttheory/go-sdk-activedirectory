// Accountstate reads expiration or searches state; writes require explicit -apply.
package main

import (
	"context"
	"errors"
	"flag"
	"fmt"
	"os"
	"time"

	ad "github.com/deploymenttheory/go-sdk-activedirectory/activedirectory"
	adaccounts "github.com/deploymenttheory/go-sdk-activedirectory/activedirectory/services/accounts"
	"github.com/deploymenttheory/go-sdk-activedirectory/examples/internal/secureauth"
)

func main() {
	server := flag.String("server", "", "explicit LDAP server")
	dn := flag.String("dn", "", "account DN for read/set/clear, or base DN for search")
	operation := flag.String(
		"operation",
		"read",
		"read, set, clear, disabled, locked, expired, expiring, inactive, password-expired, password-never",
	)
	at := flag.String("at", "", "RFC3339Nano instant: set target or expired/expiring AsOf")
	boundary := flag.String(
		"boundary",
		"",
		"RFC3339Nano expiring upper bound or inactive DateTime before synchronization allowance",
	)
	scan := flag.Int("scan-limit", 10000, "maximum candidate accounts evaluated")
	limit := flag.Int("match-limit", 100, "maximum matching accounts")
	apply := flag.Bool("apply", false, "submit set/clear once")
	flag.Parse()
	if *server == "" || *dn == "" || ((*operation == "set" || *operation == "clear") && !*apply) {
		flag.Usage()
		os.Exit(2)
	}
	if err := run(*server, *dn, *operation, *at, *boundary, *scan, *limit); err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(1)
	}
}

func run(server, dn, operation, atText, boundaryText string, scan, limit int) (err error) {
	var at, boundary time.Time
	if atText != "" {
		at, err = time.Parse(time.RFC3339Nano, atText)
		if err != nil {
			return err
		}
	}
	if boundaryText != "" {
		boundary, err = time.Parse(time.RFC3339Nano, boundaryText)
		if err != nil {
			return err
		}
	}
	identity, err := ad.IdentityByDN(dn)
	if err != nil {
		return err
	}
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()
	client, err := secureauth.Dial(ctx, server)
	if err != nil {
		return err
	}
	defer func() { err = errors.Join(err, client.Close()) }()
	switch operation {
	case "read":
		result, err := client.Accounts.AccountExpiration(ctx, identity, ad.ResolveIdentityOptions{})
		if result.Expiration != nil {
			observed := result.Expiration
			if observed.Value == nil || observed.NeverExpires == nil {
				fmt.Println("expiration was not returned or could not be converted")
			} else {
				fmt.Printf("raw=%s never=%t\n", observed.Value.LDAPString(), *observed.NeverExpires)
				if observed.ExpiresAt != nil {
					fmt.Println("expires-at=" + observed.ExpiresAt.Format(time.RFC3339Nano))
				}
			}
		}
		return err
	case "set", "clear":
		var result adaccounts.AccountExpirationMutationResult
		if operation == "set" {
			result, err = client.Accounts.SetAccountExpiration(
				ctx,
				adaccounts.SetAccountExpirationRequest{Identity: identity, At: at},
			)
		} else {
			result, err = client.Accounts.ClearAccountExpiration(
				ctx,
				identity,
				ad.ObjectMutationOptions{},
			)
		}
		fmt.Printf(
			"write-state=%d verified=%t readback=%t\n",
			result.Mutation.State,
			result.Mutation.Verified,
			result.Mutation.ReadbackComplete,
		)
		return err
	}
	conditions := map[string]adaccounts.AccountStateCondition{
		"disabled":         adaccounts.AccountDisabled,
		"locked":           adaccounts.AccountLockedOut,
		"expired":          adaccounts.AccountExpired,
		"expiring":         adaccounts.AccountExpiring,
		"inactive":         adaccounts.AccountInactive,
		"password-expired": adaccounts.AccountPasswordExpired,
		"password-never":   adaccounts.AccountPasswordNeverExpires,
	}
	condition, ok := conditions[operation]
	if !ok {
		return fmt.Errorf("unknown operation %q", operation)
	}
	result, err := client.Accounts.SearchAccountState(
		ctx,
		adaccounts.AccountStateQuery{
			Condition: condition,
			AsOf:      at,
			Boundary:  boundary,
			ScanLimit: scan,
			Search:    ad.SearchOptions{Base: dn, Scope: ad.ScopeSubtree, ResultLimit: limit},
		},
	)
	for _, account := range result.Accounts {
		fmt.Println(account.DistinguishedName)
	}
	fmt.Printf(
		"complete=%t scanned=%d matched=%d unknown=%d scan-limit=%t match-limit=%t\n",
		result.Complete,
		result.Scanned,
		len(result.Accounts),
		len(result.Unknown),
		result.ScanLimitReached,
		result.MatchLimitReached,
	)
	if result.Inactivity != nil {
		fmt.Printf(
			"inactivity-cutoff=%s interval-days=%d defaulted=%t\n",
			result.Inactivity.Cutoff.Format(time.RFC3339Nano),
			result.Inactivity.SynchronizationIntervalDays,
			result.Inactivity.Defaulted,
		)
	}
	return err
}
