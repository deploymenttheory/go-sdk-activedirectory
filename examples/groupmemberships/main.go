// Groupmemberships enumerates direct links unless an explicit write is selected.
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
	group := flag.String("group", "", "group DN")
	member := flag.String("member", "", "member DN for add/remove")
	operation := flag.String("operation", "read", "read, add or remove")
	strict := flag.Bool("strict", false, "reject existing additions/missing deletions")
	ttl := flag.Duration("ttl", 0, "positive whole-second TTL for add; omitted means permanent")
	includeTTL := flag.Bool("include-ttl", false, "request remaining TTL on reads")
	apply := flag.Bool("apply", false, "submit the selected mutation once")
	flag.Parse()
	if *server == "" || *group == "" || (*operation != "read" && (!*apply || *member == "")) || (*ttl != 0 && *operation != "add") {
		flag.Usage()
		os.Exit(2)
	}
	if err := run(*server, *group, *member, *operation, *strict, *ttl, *includeTTL); err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(1)
	}
}

func run(server, groupDN, memberDN, operation string, strict bool, ttl time.Duration, includeTTL bool) (err error) {
	group, err := ad.IdentityByDN(groupDN)
	if err != nil {
		return err
	}
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()
	client, err := ad.Dial(ctx, ad.Config{Endpoint: ad.Endpoint{Host: server}})
	if err != nil {
		return err
	}
	defer func() { err = errors.Join(err, client.Close()) }()
	if operation == "read" {
		result, readErr := client.GroupMemberLinks(ctx, group, ad.GroupMemberLinksOptions{IncludeTTL: includeTTL})
		for _, link := range result.Members {
			fmt.Println(link.Raw)
		}
		fmt.Printf("complete=%t attribute-returned=%t ranges=%d\n", result.Complete, result.AttributeReturned, len(result.Ranges))
		return readErr
	}
	member, err := ad.IdentityByDN(memberDN)
	if err != nil {
		return err
	}
	mode := ad.GroupMembershipPermissive
	if strict {
		mode = ad.GroupMembershipStrict
	}
	var result ad.GroupMembershipMutationResult
	switch operation {
	case "add":
		request := ad.AddGroupMembersRequest{Identity: group, Members: []ad.Identity{member}, Mode: mode}
		if ttl != 0 {
			request.TimeToLive = &ttl
		}
		result, err = client.AddGroupMembers(ctx, request)
	case "remove":
		result, err = client.RemoveGroupMembers(ctx, ad.RemoveGroupMembersRequest{Identity: group, Members: []ad.Identity{member}, Mode: mode})
	default:
		return fmt.Errorf("unknown operation %q", operation)
	}
	fmt.Printf("write-state=%d readback=%t verified=%t\n", result.Mutation.State, result.Mutation.ReadbackComplete, result.Mutation.Verified)
	return err
}
