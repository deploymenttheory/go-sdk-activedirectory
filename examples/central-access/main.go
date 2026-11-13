// Central-access reads by default. Every explicitly selected write needs -apply.
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
	"github.com/deploymenttheory/go-sdk-activedirectory/conditions"
)

func main() {
	server := flag.String("server", "", "explicit LDAP endpoint")
	kind := flag.String("kind", "rule", "rule or policy")
	op := flag.String("operation", "read", "read, list, create, update, protect, unprotect, add-member, remove-member, delete")
	dn := flag.String("dn", "", "explicit rule/policy DN (except create/list)")
	name := flag.String("name", "", "literal name for create")
	member := flag.String("member-dn", "", "explicit rule DN for member changes")
	description := flag.String("description", "", "description to set when supplied")
	current := flag.String("current-acl", "", "CurrentACL SDDL to set when supplied")
	proposed := flag.String("proposed-acl", "", "ProposedACL SDDL to set when supplied")
	condition := flag.String("condition", "", "resource condition to set when supplied")
	apply := flag.Bool("apply", false, "execute the selected write; protection can change the parent ACL")
	flag.Parse()
	if *server == "" || (*kind != "rule" && *kind != "policy") || (*op != "read" && *op != "list" && !*apply) {
		flag.Usage()
		os.Exit(2)
	}
	set := map[string]bool{}
	flag.Visit(func(f *flag.Flag) { set[f.Name] = true })
	var desc, cur, prop *string
	var expr *conditions.Expression
	if set["description"] {
		desc = description
	}
	if set["current-acl"] {
		cur = current
	}
	if set["proposed-acl"] {
		prop = proposed
	}
	if set["condition"] {
		value := conditions.Raw(*condition)
		expr = &value
	}
	if *kind == "policy" && (cur != nil || prop != nil || expr != nil) {
		fmt.Fprintln(os.Stderr, "permission fields apply to rules")
		os.Exit(2)
	}
	if err := run(*server, *kind, *op, *dn, *name, *member, desc, cur, prop, expr); err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(1)
	}
}

func run(server, kind, operation, dn, name, memberDN string, description, current, proposed *string, condition *conditions.Expression) (err error) {
	var identity ad.Identity
	if operation != "create" && operation != "list" {
		identity, err = ad.IdentityByDN(dn)
		if err != nil {
			return err
		}
	}
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()
	client, err := ad.Dial(ctx, ad.Config{Endpoint: ad.Endpoint{Host: server}})
	if err != nil {
		return err
	}
	defer func() { err = errors.Join(err, client.Close()) }()
	policy := kind == "policy"
	var result any
	switch operation {
	case "read":
		if policy {
			result, err = client.CentralAccessPolicy(ctx, identity, ad.CentralAccessReadOptions{})
		} else {
			result, err = client.CentralAccessRule(ctx, identity, ad.CentralAccessReadOptions{})
		}
	case "list":
		if policy {
			result, err = client.CentralAccessPolicies(ctx, ad.SearchOptions{}, ad.CentralAccessReferenceLimits{})
		} else {
			result, err = client.CentralAccessRules(ctx, ad.SearchOptions{}, ad.CentralAccessReferenceLimits{})
		}
	case "create":
		if policy {
			result, err = client.CreateCentralAccessPolicy(ctx, ad.CreateCentralAccessPolicyRequest{Name: name, Description: description})
		} else {
			result, err = client.CreateCentralAccessRule(ctx, ad.CreateCentralAccessRuleRequest{Name: name, Description: description, CurrentACL: current, ProposedACL: proposed, ResourceCondition: condition})
		}
	case "update", "protect", "unprotect":
		var protect *bool
		if operation != "update" {
			value := operation == "protect"
			protect = &value
		}
		if policy {
			result, err = client.UpdateCentralAccessPolicy(ctx, ad.UpdateCentralAccessPolicyRequest{Identity: identity, Description: description, ProtectedFromAccidentalDeletion: protect})
		} else {
			result, err = client.UpdateCentralAccessRule(ctx, ad.UpdateCentralAccessRuleRequest{Identity: identity, Description: description, CurrentACL: current, ProposedACL: proposed, ResourceCondition: condition, ProtectedFromAccidentalDeletion: protect})
		}
	case "add-member", "remove-member":
		if !policy {
			return fmt.Errorf("member operations require kind policy")
		}
		member, e := ad.IdentityByDN(memberDN)
		if e != nil {
			return e
		}
		request := ad.CentralAccessPolicyMembersRequest{Identity: identity, Members: []ad.Identity{member}}
		if operation == "add-member" {
			result, err = client.AddCentralAccessPolicyMembers(ctx, request)
		} else {
			result, err = client.RemoveCentralAccessPolicyMembers(ctx, request)
		}
	case "delete":
		if policy {
			result, err = client.DeleteCentralAccessPolicy(ctx, identity, ad.ObjectMutationOptions{})
		} else {
			result, err = client.DeleteCentralAccessRule(ctx, identity, ad.ObjectMutationOptions{})
		}
	default:
		return fmt.Errorf("unknown operation %q", operation)
	}
	encoder := json.NewEncoder(os.Stdout)
	encoder.SetIndent("", "  ")
	return errors.Join(err, encoder.Encode(result))
}
