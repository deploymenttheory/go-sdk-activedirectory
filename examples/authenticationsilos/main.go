// Authenticationsilos reads by default; a write requires -operation and -apply.
package main

import (
	"context"
	"errors"
	"flag"
	"fmt"
	"os"
	"time"

	ad "github.com/deploymenttheory/go-sdk-activedirectory"
)

func main() {
	server := flag.String("server", "", "explicit LDAP server")
	operation := flag.String("operation", "read", "read, create, enforce, delete, grant, revoke, assign, or clear")
	name := flag.String("name", "", "literal silo name to create")
	silo := flag.String("silo-dn", "", "explicit silo DN")
	account := flag.String("account-dn", "", "explicit account DN")
	policy := flag.String("policy-dn", "", "optional user policy on create, or direct account policy on assign")
	enforced := flag.Bool("enforced", false, "create/enforce stored state; false is audit")
	require := flag.Bool("require-granted", false, "require an observed grant before assignment")
	apply := flag.Bool("apply", false, "execute the selected write")
	flag.Parse()
	if *server == "" || (*operation != "read" && !*apply) {
		flag.Usage()
		os.Exit(2)
	}
	if err := run(*server, *operation, *name, *silo, *account, *policy, *enforced, *require); err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(1)
	}
}

func run(server, operation, name, siloDN, accountDN, policyDN string, enforced, require bool) (err error) {
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()
	client, err := ad.Dial(ctx, ad.Config{Endpoint: ad.Endpoint{Host: server}})
	if err != nil {
		return err
	}
	defer func() { err = errors.Join(err, client.Close()) }()
	if operation == "read" {
		result, readErr := client.AuthenticationPolicySilos(ctx, ad.AuthenticationPolicySiloSearchOptions{})
		for _, row := range result.Silos {
			if row.Silo != nil {
				fmt.Printf("%s grants=%d assigned=%d grantsComplete=%t assignedComplete=%t\n", row.Silo.DistinguishedName, len(row.Members.DistinguishedNames), len(row.AssignedAccounts.DistinguishedNames), row.Members.Complete, row.AssignedAccounts.Complete)
			}
		}
		fmt.Printf("searchComplete=%t limited=%t\n", result.Observation.Complete, result.Observation.LimitReached)
		return readErr
	}
	var policy *ad.Identity
	if policyDN != "" {
		value, parseErr := ad.IdentityByDN(policyDN)
		if parseErr != nil {
			return parseErr
		}
		policy = &value
	}
	var result ad.ObjectMutationResult
	if operation == "create" {
		created, createErr := client.CreateAuthenticationPolicySilo(ctx, ad.CreateAuthenticationPolicySiloRequest{Name: name, Properties: ad.AuthenticationPolicySiloProperties{Enforced: &enforced, UserAuthenticationPolicy: policy}})
		result, err = created.Mutation, createErr
	} else {
		var silo ad.Identity
		if operation != "clear" {
			silo, err = ad.IdentityByDN(siloDN)
			if err != nil {
				return err
			}
		}
		switch operation {
		case "enforce":
			updated, updateErr := client.UpdateAuthenticationPolicySilo(ctx, ad.UpdateAuthenticationPolicySiloRequest{Identity: silo, Properties: ad.AuthenticationPolicySiloProperties{Enforced: &enforced}})
			result, err = updated.Mutation, updateErr
		case "delete":
			result, err = client.DeleteAuthenticationPolicySilo(ctx, ad.DeleteAuthenticationPolicySiloRequest{Identity: silo})
		case "grant", "revoke", "assign", "clear":
			account, parseErr := ad.IdentityByDN(accountDN)
			if parseErr != nil {
				return parseErr
			}
			if operation == "grant" || operation == "revoke" {
				request := ad.AuthenticationPolicySiloAccessRequest{Identity: silo, Account: account}
				var changed ad.AuthenticationPolicySiloAccessResult
				if operation == "grant" {
					changed, err = client.GrantAuthenticationPolicySiloAccess(ctx, request)
				} else {
					changed, err = client.RevokeAuthenticationPolicySiloAccess(ctx, request)
				}
				result = changed.Mutation
			} else {
				request := ad.SetAccountAuthenticationPolicySiloRequest{Identity: account, ClearSilo: operation == "clear"}
				if operation == "assign" {
					request.Silo, request.Policy, request.RequireGranted = &silo, policy, require
				}
				changed, assignErr := client.SetAccountAuthenticationPolicySilo(ctx, request)
				result, err = changed.Mutation, assignErr
			}
		default:
			return fmt.Errorf("unknown operation %q", operation)
		}
	}
	fmt.Printf("state=%d readback=%t verified=%t\n", result.State, result.ReadbackComplete, result.Verified)
	if result.After != nil {
		fmt.Println(result.After.DistinguishedName)
	}
	return err
}
