// Restoration discovers deleted objects or restores one explicitly selected GUID.
package main

import (
	"context"
	"errors"
	"flag"
	"fmt"
	"os"
	"strings"
	"time"

	ad "github.com/deploymenttheory/go-sdk-activedirectory"
)

func main() {
	server := flag.String("server", "", "explicit LDAP host")
	port := flag.Uint("port", 389, "LDAP port, including an explicit AD LDS instance port")
	operation := flag.String("operation", "discover", "discover or restore")
	base := flag.String("base", "", "discovery base or restoration partition")
	guid := flag.String("guid", "", "GUID of the disposable deleted object to restore")
	name := flag.String("new-name", "", "optional literal restored name")
	parent := flag.String("target-parent", "", "optional existing parent DN")
	limit := flag.Int("limit", 100, "discovery result limit")
	apply := flag.Bool("apply", false, "submit the explicit restoration once")
	legacy := flag.Bool("legacy", false, "explicitly permit potentially lossy tombstone reanimation")
	attributes := map[string][]ad.RawValue{}
	flag.Func("attribute", "legacy replacement name=value; repeat for multiple values", func(text string) error {
		name, value, ok := strings.Cut(text, "=")
		if !ok || name == "" {
			return errors.New("attribute must be name=value")
		}
		attributes[name] = append(attributes[name], ad.NewRawValue([]byte(value)))
		return nil
	})
	flag.Parse()
	if *server == "" || *port == 0 || *port > 65535 || (*operation != "discover" && *operation != "restore") || (*operation == "restore" && (!*apply || *guid == "")) {
		flag.Usage()
		os.Exit(2)
	}
	var newName *string
	flag.Visit(func(f *flag.Flag) {
		if f.Name == "new-name" {
			newName = name
		}
	})
	if len(attributes) != 0 && (!*legacy || *operation != "restore") {
		fmt.Fprintln(os.Stderr, "attributes require legacy restoration")
		os.Exit(2)
	}
	mode := ad.RestoreWithRecycleBin
	if *legacy {
		mode = ad.RestoreLegacyTombstone
	}
	if err := run(*server, uint16(*port), *operation, *base, *guid, newName, *parent, *limit, mode, attributes); err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(1)
	}
}

func run(server string, port uint16, operation, base, guid string, name *string, parent string, limit int, mode ad.ObjectRestoreMode, attributes map[string][]ad.RawValue) (err error) {
	request := ad.RestoreObjectRequest{NewName: name, Mode: mode, Attributes: attributes, Options: ad.ObjectMutationOptions{Partition: base}}
	if operation == "restore" {
		request.Identity, err = ad.IdentityByGUID(guid)
		if err != nil {
			return err
		}
		if parent != "" {
			request.TargetParent, err = ad.IdentityByDN(parent)
			if err != nil {
				return err
			}
		}
	}
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()
	client, err := ad.Dial(ctx, ad.Config{Endpoint: ad.Endpoint{Host: server, Port: port}})
	if err != nil {
		return err
	}
	defer func() { err = errors.Join(err, client.Close()) }()
	if operation == "restore" {
		result, err := client.RestoreObject(ctx, request)
		fmt.Printf("write-state=%d verified=%t destination=%s\n", result.Mutation.State, result.Mutation.Verified, result.Mutation.TargetDN)
		if result.Capabilities.Error != nil {
			fmt.Printf("feature-observation=%v\n", result.Capabilities.Error)
		}
		return err
	}
	result, err := client.DeletedObjects(ctx, ad.DeletedObjectQuery{Search: ad.SearchOptions{Base: base, Scope: ad.ScopeSubtree, ResultLimit: limit}, IncludeRecycled: true})
	for _, object := range result.Objects {
		id := "unknown"
		if object.GUID != nil {
			id = object.GUID.String()
		}
		fmt.Printf("guid=%s state=%d dn=%s error=%v\n", id, object.State, object.Raw.DistinguishedName, object.Error)
	}
	fmt.Printf("complete=%t limit=%t count=%d\n", result.Complete, result.Observation.LimitReached, len(result.Objects))
	return err
}
