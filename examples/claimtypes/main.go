// Claim-type reads by default. Every explicitly selected write needs -apply.
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
	op := flag.String("operation", "read", "read, list, create, update, delete")
	dn := flag.String("dn", "", "explicit claim type DN (except create/list)")
	id := flag.String("id", "", "explicit ad://ext/ claim ID for create; generated when empty")
	display := flag.String("display-name", "", "display name for create or update")
	description := flag.String("description", "", "description to set when supplied")
	source := flag.String("source", "attribute", "attribute, certificate or transform")
	attribute := flag.String("source-attribute", "", "lDAPDisplayName of the source attribute")
	oid := flag.String("source-oid", "", "dotted-decimal OID for a certificate source")
	valueType := flag.Int64("value-type", 0, "claim value type; transform sources only")
	class := flag.String("applies-to", "", "lDAPDisplayName of a class the claim applies to")
	force := flag.Bool("force", false, "delete even when resource properties still reference the claim")
	apply := flag.Bool("apply", false, "execute the selected write")
	flag.Parse()
	if *server == "" || (*op != "read" && *op != "list" && !*apply) {
		fmt.Fprintln(os.Stderr, "usage: -server <endpoint> [-operation read|list|create|update|delete] [-apply]")
		os.Exit(2)
	}

	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Minute)
	defer cancel()
	client, err := ad.Dial(ctx, ad.Config{Endpoint: ad.Endpoint{Host: *server}})
	if err != nil {
		fail(err)
	}
	defer client.Close()

	var classes []ad.SchemaReference
	if *class != "" {
		classes = append(classes, ad.SchemaReference{LDAPDisplayName: *class})
	}

	switch *op {
	case "read":
		result, err := client.ClaimType(ctx, identity(*dn), ad.ClaimTypeReadOptions{IncludeSchema: true, IncludeProtection: true})
		report(result, err)
	case "list":
		result, err := client.ClaimTypes(ctx, ad.SearchOptions{})
		report(result, err)
	case "create":
		request := ad.CreateClaimTypeRequest{DisplayName: *display, AppliesToClasses: classes}
		if *id != "" {
			request.ID = id
		}
		if *description != "" {
			request.Description = description
		}
		request.Source, err = claimSource(*source, *attribute, *oid, *valueType)
		if err != nil {
			fail(err)
		}
		result, err := client.CreateClaimType(ctx, request)
		// A generated ID is reported even when the write is rejected or
		// uncertain, so a retry does not create a second claim.
		if result.GeneratedID != nil {
			fmt.Fprintf(os.Stderr, "generated claim ID: %s\n", *result.GeneratedID)
		}
		report(result, err)
	case "update":
		request := ad.UpdateClaimTypeRequest{Identity: identity(*dn), AppliesToClasses: classes}
		if *display != "" {
			request.DisplayName = display
		}
		if *description != "" {
			request.Description = description
		}
		if *source != "" && *attribute+*oid != "" {
			settled, err := claimSource(*source, *attribute, *oid, *valueType)
			if err != nil {
				fail(err)
			}
			request.Source = &settled
		}
		result, err := client.UpdateClaimType(ctx, request)
		report(result, err)
	case "delete":
		result, err := client.DeleteClaimType(ctx, ad.DeleteClaimTypeRequest{Identity: identity(*dn), Force: *force})
		report(result, err)
	default:
		fail(errors.New("unknown operation " + *op))
	}
}

// claimSource builds exactly one source form. ValueType is stated only for a
// transform policy; the other forms derive it from the directory.
func claimSource(kind, attribute, oid string, valueType int64) (ad.ClaimTypeSource, error) {
	switch kind {
	case "attribute":
		if attribute == "" {
			return ad.ClaimTypeSource{}, errors.New("-source-attribute is required for an attribute source")
		}
		return ad.ClaimTypeSource{Type: ad.ClaimSourceAttribute, Attribute: ad.SchemaReference{LDAPDisplayName: attribute}}, nil
	case "certificate":
		if oid == "" {
			return ad.ClaimTypeSource{}, errors.New("-source-oid is required for a certificate source")
		}
		return ad.ClaimTypeSource{Type: ad.ClaimSourceCertificate, OID: oid}, nil
	case "transform":
		if valueType == 0 {
			return ad.ClaimTypeSource{}, errors.New("-value-type is required for a transform policy source")
		}
		return ad.ClaimTypeSource{Type: ad.ClaimSourceTransform, ValueType: ad.ClaimValueType(valueType)}, nil
	default:
		return ad.ClaimTypeSource{}, errors.New("unknown source " + kind)
	}
}

func identity(dn string) ad.Identity {
	value, err := ad.IdentityByDN(dn)
	if err != nil {
		fail(err)
	}
	return value
}

// report prints the observation even when the operation failed: an uncertain
// write still carries the state a caller needs.
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
