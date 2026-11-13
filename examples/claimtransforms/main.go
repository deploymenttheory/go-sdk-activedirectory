// Claim transformation policy reads by default. Every write needs -apply.
package main

import (
	"context"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"os"
	"time"

	ad "github.com/deploymenttheory/go-sdk-activedirectory"
)

func main() {
	server := flag.String("server", "", "explicit LDAP endpoint")
	op := flag.String("operation", "read", "read, list, create, update, delete, link, unlink")
	dn := flag.String("dn", "", "explicit policy DN (except create/list)")
	name := flag.String("name", "", "literal name for create")
	description := flag.String("description", "", "description to set when supplied")
	rules := flag.String("rules", "", "allow-all, deny-all, allow-except, deny-except or explicit")
	exceptID := flag.String("except-id", "", "ad://ext/ claim ID for the except forms")
	rule := flag.String("rule", "", "explicit inner rule text for -rules explicit")
	trustDN := flag.String("trust-dn", "", "trustedDomain DN for link/unlink")
	direction := flag.String("direction", "", "egress or ingress; required for link/unlink")
	apply := flag.Bool("apply", false, "execute the selected write")
	flag.Parse()
	if *server == "" || (*op != "read" && *op != "list" && !*apply) {
		fmt.Fprintln(os.Stderr, "usage: -server <endpoint> [-operation read|list|create|update|delete|link|unlink] [-apply]")
		os.Exit(2)
	}

	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Minute)
	defer cancel()
	client, err := ad.Dial(ctx, ad.Config{Endpoint: ad.Endpoint{Host: *server}})
	if err != nil {
		fail(err)
	}
	defer client.Close()

	switch *op {
	case "read":
		result, err := client.ClaimTransformPolicy(ctx, identity(*dn), ad.ClaimTransformPolicyReadOptions{IncludeProtection: true})
		report(result, err)
	case "list":
		result, err := client.ClaimTransformPolicies(ctx, ad.SearchOptions{})
		report(result, err)
	case "create":
		set, err := ruleSet(*rules, *exceptID, *rule)
		if err != nil {
			fail(err)
		}
		request := ad.CreateClaimTransformPolicyRequest{Name: *name, Rules: set}
		if *description != "" {
			request.Description = description
		}
		result, err := client.CreateClaimTransformPolicy(ctx, request)
		report(result, err)
	case "update":
		set, err := ruleSet(*rules, *exceptID, *rule)
		if err != nil {
			fail(err)
		}
		request := ad.UpdateClaimTransformPolicyRequest{Identity: identity(*dn), Rules: set}
		if *description != "" {
			request.Description = description
		}
		result, err := client.UpdateClaimTransformPolicy(ctx, request)
		report(result, err)
	case "delete":
		result, err := client.DeleteClaimTransformPolicy(ctx, identity(*dn), ad.ObjectMutationOptions{})
		report(result, err)
	case "link", "unlink":
		// The direction is explicit: the TrustRole mapping the reference uses
		// has not been qualified, so this example will not guess it either.
		var chosen ad.ClaimTransformDirection
		switch *direction {
		case "egress":
			chosen = ad.ClaimTransformEgress
		case "ingress":
			chosen = ad.ClaimTransformIngress
		default:
			fail(errors.New("-direction must be egress or ingress"))
		}
		request := ad.ClaimTransformLinkRequest{Trust: identity(*trustDN), Direction: chosen}
		if *op == "link" {
			request.Policy = identity(*dn)
			result, err := client.SetClaimTransformLink(ctx, request)
			report(result, err)
		} else {
			result, err := client.ClearClaimTransformLink(ctx, request)
			report(result, err)
		}
	default:
		fail(errors.New("unknown operation " + *op))
	}
}

// ruleSet builds exactly one rule form. An empty selection writes no rules
// rather than defaulting to allow or deny.
func ruleSet(kind, exceptID, rule string) (ad.ClaimTransformRuleSet, error) {
	switch kind {
	case "":
		return ad.ClaimTransformRuleSet{}, nil
	case "allow-all":
		return ad.ClaimTransformRuleSet{AllowAll: true}, nil
	case "deny-all":
		return ad.ClaimTransformRuleSet{DenyAll: true}, nil
	case "allow-except":
		if exceptID == "" {
			return ad.ClaimTransformRuleSet{}, errors.New("-except-id is required for allow-except")
		}
		return ad.ClaimTransformRuleSet{AllowAllExcept: []string{exceptID}}, nil
	case "deny-except":
		if exceptID == "" {
			return ad.ClaimTransformRuleSet{}, errors.New("-except-id is required for deny-except")
		}
		return ad.ClaimTransformRuleSet{DenyAllExcept: []string{exceptID}}, nil
	case "explicit":
		if rule == "" {
			return ad.ClaimTransformRuleSet{}, errors.New("-rule is required for explicit")
		}
		return ad.ClaimTransformRuleSet{Rule: &rule}, nil
	default:
		return ad.ClaimTransformRuleSet{}, errors.New("unknown rules form " + kind)
	}
}

func identity(dn string) ad.Identity {
	value, err := ad.IdentityByDN(dn)
	if err != nil {
		fail(err)
	}
	return value
}

// report prints the observation even on failure: an uncertain write still
// carries the state a caller needs.
func report(result any, err error) {
	encoded, marshalErr := json.MarshalIndent(result, "", "  ")
	if marshalErr != nil {
		fail(marshalErr)
	}
	fmt.Println(string(encoded))
	if err != nil {
		fail(err)
	}
}

func fail(err error) {
	fmt.Fprintln(os.Stderr, "error:", err)
	os.Exit(1)
}
