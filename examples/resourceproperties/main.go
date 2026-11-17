// Resource property reads by default. Every write needs -apply.
package main

import (
	"context"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"os"
	"strings"
	"time"

	ad "github.com/deploymenttheory/go-sdk-activedirectory/activedirectory"
	adclaims "github.com/deploymenttheory/go-sdk-activedirectory/activedirectory/services/claims"
	adresourceproperties "github.com/deploymenttheory/go-sdk-activedirectory/activedirectory/services/resource_properties"
)

func main() {
	server := flag.String("server", "", "explicit LDAP endpoint")
	op := flag.String(
		"operation",
		"read",
		"read, list, read-list, list-lists, value-types, create, update, delete, create-list, delete-list, add-members, remove-members",
	)
	dn := flag.String("dn", "", "explicit object DN where the operation needs one")
	display := flag.String("display-name", "", "display name for create or update")
	description := flag.String("description", "", "description to set when supplied")
	name := flag.String("name", "", "literal name for create-list")
	valueType := flag.String("value-type", "", "value type object name, required for create")
	appliesTo := flag.String("applies-to", "", "comma-separated resource types")
	members := flag.String("members", "", "comma-separated resource property DNs")
	apply := flag.Bool("apply", false, "execute the selected write")
	flag.Parse()
	readOnly := map[string]bool{
		"read":        true,
		"list":        true,
		"read-list":   true,
		"list-lists":  true,
		"value-types": true,
	}
	if *server == "" || (!readOnly[*op] && !*apply) {
		fmt.Fprintln(os.Stderr, "usage: -server <endpoint> [-operation ...] [-apply]")
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
		// IncludeValueType resolves the referenced object so the settled
		// value type is visible, not just its DN.
		result, err := client.ResourceProperties.ResourceProperty(
			ctx,
			identity(*dn),
			adresourceproperties.ResourcePropertyReadOptions{
				IncludeValueType:  true,
				IncludeProtection: true,
			},
		)
		report(result, err)
	case "list":
		report(client.ResourceProperties.ResourceProperties(ctx, ad.SearchOptions{}))
	case "read-list":
		report(
			client.ResourceProperties.ResourcePropertyList(
				ctx,
				identity(*dn),
				adresourceproperties.ResourcePropertyReadOptions{IncludeProtection: true},
			),
		)
	case "list-lists":
		report(client.ResourceProperties.ResourcePropertyLists(ctx, ad.SearchOptions{}))
	case "value-types":
		report(client.ResourceProperties.ResourceValueTypes(ctx, ad.SearchOptions{}))
	case "create":
		if *valueType == "" {
			fail(errors.New("-value-type is required for create"))
		}
		request := adresourceproperties.CreateResourcePropertyRequest{
			DisplayName:            *display,
			ValueType:              adclaims.SchemaReference{LDAPDisplayName: *valueType},
			AppliesToResourceTypes: split(*appliesTo),
		}
		if *description != "" {
			request.Description = description
		}
		report(client.ResourceProperties.CreateResourceProperty(ctx, request))
	case "update":
		request := adresourceproperties.UpdateResourcePropertyRequest{
			Identity:               identity(*dn),
			AppliesToResourceTypes: split(*appliesTo),
		}
		if *display != "" {
			request.DisplayName = display
		}
		if *description != "" {
			request.Description = description
		}
		report(client.ResourceProperties.UpdateResourceProperty(ctx, request))
	case "delete":
		report(
			client.ResourceProperties.DeleteResourceProperty(
				ctx,
				identity(*dn),
				ad.ObjectMutationOptions{},
			),
		)
	case "create-list":
		request := adresourceproperties.CreateResourcePropertyListRequest{Name: *name}
		if *description != "" {
			request.Description = description
		}
		report(client.ResourceProperties.CreateResourcePropertyList(ctx, request))
	case "delete-list":
		report(
			client.ResourceProperties.DeleteResourcePropertyList(
				ctx,
				identity(*dn),
				ad.ObjectMutationOptions{},
			),
		)
	case "add-members", "remove-members":
		request := adresourceproperties.ResourcePropertyListMembersRequest{
			Identity: identity(*dn),
			Members:  identities(split(*members)),
		}
		if *op == "add-members" {
			report(client.ResourceProperties.AddResourcePropertyListMembers(ctx, request))
		} else {
			report(client.ResourceProperties.RemoveResourcePropertyListMembers(ctx, request))
		}
	default:
		fail(errors.New("unknown operation " + *op))
	}
}

func split(value string) []string {
	if value == "" {
		return nil
	}
	parts := strings.Split(value, ",")
	trimmed := make([]string, 0, len(parts))
	for _, part := range parts {
		if item := strings.TrimSpace(part); item != "" {
			trimmed = append(trimmed, item)
		}
	}
	return trimmed
}

func identities(values []string) []ad.Identity {
	result := make([]ad.Identity, 0, len(values))
	for _, value := range values {
		result = append(result, identity(value))
	}
	return result
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
