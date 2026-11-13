// Fine-grained-policy reads by default. Writes require -apply and explicit inputs.
package main

import (
	"bytes"
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
	server := flag.String("server", "", "explicit LDAP server")
	dn := flag.String("dn", "", "PSO DN; user DN for resultant")
	op := flag.String("operation", "read", "read, list, subjects, resultant, create, update, delete, add-subjects, remove-subjects")
	name := flag.String("name", "", "literal policy name for create")
	settings := flag.String("settings", "", "JSON settings file for create/update; intervals are nonnegative 100ns ticks")
	apply := flag.Bool("apply", false, "execute the selected mutation once")
	var subjects []string
	flag.Func("subject", "explicit subject DN; repeat for multiple subjects", func(value string) error { subjects = append(subjects, value); return nil })
	flag.Parse()
	read := *op == "read" || *op == "list" || *op == "subjects" || *op == "resultant"
	if *server == "" || (*dn == "" && *op != "list" && *op != "create") || (!read && !*apply) {
		flag.Usage()
		os.Exit(2)
	}
	if err := run(*server, *dn, *op, *name, *settings, subjects); err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(1)
	}
}

func run(server, dn, operation, name, settingsPath string, subjectDNs []string) (err error) {
	var settings ad.FineGrainedPasswordPolicySettings
	if operation == "create" || operation == "update" {
		data, e := os.ReadFile(settingsPath)
		if e != nil {
			return e
		}
		decoder := json.NewDecoder(bytes.NewReader(data))
		decoder.DisallowUnknownFields()
		if e := decoder.Decode(&settings); e != nil {
			return e
		}
	}
	var identity ad.Identity
	if dn != "" {
		identity, err = ad.IdentityByDN(dn)
		if err != nil {
			return err
		}
	}
	var subjects []ad.Identity
	for _, subjectDN := range subjectDNs {
		subject, e := ad.IdentityByDN(subjectDN)
		if e != nil {
			return e
		}
		subjects = append(subjects, subject)
	}
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()
	client, err := ad.Dial(ctx, ad.Config{Endpoint: ad.Endpoint{Host: server}})
	if err != nil {
		return err
	}
	defer func() { err = errors.Join(err, client.Close()) }()
	var result any
	switch operation {
	case "read":
		result, err = client.FineGrainedPasswordPolicy(ctx, identity, ad.ResolveIdentityOptions{})
	case "list":
		result, err = client.FineGrainedPasswordPolicies(ctx, ad.SearchOptions{})
	case "subjects":
		result, err = client.FineGrainedPasswordPolicySubjects(ctx, identity, ad.FineGrainedPolicySubjectsOptions{})
	case "resultant":
		result, err = client.UserResultantPasswordPolicy(ctx, identity, ad.ResolveIdentityOptions{})
	case "create":
		result, err = client.CreateFineGrainedPasswordPolicy(ctx, ad.CreateFineGrainedPasswordPolicyRequest{Name: name, Settings: settings})
	case "update":
		result, err = client.UpdateFineGrainedPasswordPolicy(ctx, ad.UpdateFineGrainedPasswordPolicyRequest{Identity: identity, Settings: settings})
	case "delete":
		result, err = client.DeleteFineGrainedPasswordPolicy(ctx, identity, ad.ObjectMutationOptions{})
	case "add-subjects":
		result, err = client.AddFineGrainedPasswordPolicySubjects(ctx, ad.FineGrainedPolicySubjectsRequest{Identity: identity, Subjects: subjects})
	case "remove-subjects":
		result, err = client.RemoveFineGrainedPasswordPolicySubjects(ctx, ad.FineGrainedPolicySubjectsRequest{Identity: identity, Subjects: subjects})
	default:
		return fmt.Errorf("unknown operation %q", operation)
	}
	// Raw LDAP values are base64 in JSON; intervals remain exact integer ticks.
	encoded, encodeErr := json.MarshalIndent(result, "", "  ")
	if encodeErr == nil {
		fmt.Println(string(encoded))
	}
	return errors.Join(err, encodeErr)
}
