package main

import (
	"context"
	"flag"
	"fmt"
	"log"
	"time"

	ad "github.com/deploymenttheory/go-sdk-activedirectory"
)

func main() {
	source := flag.String("source", "", "source DC FQDN")
	destination := flag.String("destination", "", "destination DC FQDN")
	partition := flag.String("partition", "", "containing naming context DN")
	object := flag.String("object", "", "source object DN")
	property := flag.String("verify", "description", "nonempty source property to compare")
	password := flag.Bool("password-only", false, "precache secrets on an RODC")
	apply := flag.Bool("apply", false, "submit the single-object replication request")
	flag.Parse()
	if !*apply {
		log.Fatal("use -apply to request replication of the selected object")
	}
	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Minute)
	defer cancel()
	c, err := ad.Dial(ctx, ad.Config{Endpoint: ad.Endpoint{Host: *destination}, Timeout: 2 * time.Minute})
	if err != nil {
		log.Fatal(err)
	}
	request := ad.SyncObjectRequest{Source: ad.Config{Endpoint: ad.Endpoint{Host: *source}, Timeout: 2 * time.Minute}, Partition: *partition, Object: ad.SyncObjectIdentity{DistinguishedName: *object}, PasswordOnly: *password}
	if !*password {
		request.Properties = []string{*property}
	}
	result, err := c.SyncObject(ctx, request)
	closeErr := c.Close()
	fmt.Printf("writeState=%d verified=%t cacheObserved=%t\n", result.State, result.Verified, result.SecretCacheObserved)
	if err != nil {
		log.Fatal(err)
	}
	if closeErr != nil {
		log.Fatal(closeErr)
	}
}
