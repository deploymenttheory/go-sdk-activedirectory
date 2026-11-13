// Authenticationpolicies reads by default; writes require an explicit operation.
package main

import (
	"context"
	"errors"
	"flag"
	"fmt"
	"math"
	"os"
	"time"

	ad "github.com/deploymenttheory/go-sdk-activedirectory"
	"github.com/deploymenttheory/go-sdk-activedirectory/conditions"
)

func main() {
	server := flag.String("server", "", "explicit LDAP server DNS name")
	operation := flag.String("operation", "read", "read, create, enforce, delete, assign, or clear")
	name := flag.String("name", "", "literal policy name for creation or optional exact read filter")
	policyDN := flag.String("policy-dn", "", "explicit policy DN for update/delete/assignment")
	accountDN := flag.String("account-dn", "", "explicit account DN for assign/clear")
	minutes := flag.Int64("user-tgt-minutes", 0, "explicit TGT lifetime on create; zero means no override")
	allowGroup := flag.String("allow-group-sid", "", "optional numeric group SID allowed to authenticate TO a user account using this policy")
	enforce := flag.Bool("enforced", false, "stored enforced state on create/enforce; false is audit mode")
	apply := flag.Bool("apply", false, "explicitly execute the selected write")
	flag.Parse()
	if *server == "" || (*operation != "read" && !*apply) || *minutes < 0 || *minutes > math.MaxInt64/600000000 {
		flag.Usage()
		os.Exit(2)
	}
	if err := run(*server, *operation, *name, *policyDN, *accountDN, *allowGroup, *minutes, *enforce); err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(1)
	}
}

func run(server, operation, name, policyDN, accountDN, groupSID string, minutes int64, enforced bool) (err error) {
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()
	client, err := ad.Dial(ctx, ad.Config{Endpoint: ad.Endpoint{Host: server}})
	if err != nil {
		return err
	}
	defer func() { err = errors.Join(err, client.Close()) }()
	if operation == "read" {
		query := ad.SearchOptions{}
		if name != "" {
			query.TypedFilter = ad.FilterEqual("name", ad.FilterText(name))
		}
		result, readErr := client.AuthenticationPolicies(ctx, query)
		for _, policy := range result.Policies {
			mode := "unavailable"
			if policy.Enforced != nil {
				mode = "audit"
				if *policy.Enforced {
					mode = "enforced"
				}
			}
			fmt.Printf("%s mode=%s\n", policy.DistinguishedName, mode)
		}
		fmt.Printf("complete=%t limited=%t\n", result.Observation.Complete, result.Observation.LimitReached)
		return readErr
	}
	var result ad.ObjectMutationResult
	switch operation {
	case "create":
		lifetime := ad.Interval100ns(minutes * 600000000)
		properties := ad.AuthenticationPolicyProperties{Enforced: &enforced, UserTGTLifetime: &lifetime}
		if groupSID != "" {
			sddl, compileErr := conditions.Compile(conditions.ACE{TrusteeSID: "S-1-1-0", AccessMask: 0x100, Condition: conditions.MemberOf(false, groupSID)})
			if compileErr != nil {
				return compileErr
			}
			properties.UserAllowedToAuthenticateTo = &sddl
		}
		created, createErr := client.CreateAuthenticationPolicy(ctx, ad.CreateAuthenticationPolicyRequest{Name: name, Properties: properties})
		result, err = created.Mutation, createErr
	case "enforce", "delete":
		identity, identityErr := ad.IdentityByDN(policyDN)
		if identityErr != nil {
			return identityErr
		}
		if operation == "delete" {
			result, err = client.DeleteAuthenticationPolicy(ctx, ad.DeleteAuthenticationPolicyRequest{Identity: identity})
		} else {
			updated, updateErr := client.UpdateAuthenticationPolicy(ctx, ad.UpdateAuthenticationPolicyRequest{Identity: identity, Properties: ad.AuthenticationPolicyProperties{Enforced: &enforced}})
			result, err = updated.Mutation, updateErr
		}
	case "assign", "clear":
		identity, identityErr := ad.IdentityByDN(accountDN)
		if identityErr != nil {
			return identityErr
		}
		request := ad.SetAccountAuthenticationPolicyRequest{Identity: identity, Clear: operation == "clear"}
		if !request.Clear {
			policy, identityErr := ad.IdentityByDN(policyDN)
			if identityErr != nil {
				return identityErr
			}
			request.Policy = &policy
		}
		assigned, assignErr := client.SetAccountAuthenticationPolicy(ctx, request)
		result, err = assigned.Mutation, assignErr
	default:
		return fmt.Errorf("unknown operation %q", operation)
	}
	fmt.Printf("state=%d readback=%t verified=%t\n", result.State, result.ReadbackComplete, result.Verified)
	if result.After != nil {
		fmt.Println(result.After.DistinguishedName)
	}
	return err // An error never authorizes automatic replay.
}
