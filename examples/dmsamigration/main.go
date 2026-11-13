// dMSA migration moves a delegated account and the account it supersedes
// through a state machine. Every transition writes two objects, so each needs
// -apply. Read the pair first.
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
	op := flag.String("operation", "start", "start, complete, undo or reset")
	dmsa := flag.String("dmsa-dn", "", "delegated managed service account DN")
	superseded := flag.String("superseded-dn", "", "DN of the account being superseded")
	partition := flag.String("partition", "", "explicit partition")
	apply := flag.Bool("apply", false, "execute the transition; it writes two objects")
	flag.Parse()
	if *server == "" || *dmsa == "" || *superseded == "" || !*apply {
		fmt.Fprintln(os.Stderr, "usage: -server <endpoint> -dmsa-dn <dn> -superseded-dn <dn> [-operation start|complete|undo|reset] -apply")
		os.Exit(2)
	}

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Minute)
	defer cancel()
	client, err := ad.Dial(ctx, ad.Config{Endpoint: ad.Endpoint{Host: *server}})
	if err != nil {
		fail(err)
	}
	defer client.Close()

	request := ad.ServiceAccountMigrationRequest{
		Identity:          identity(*dmsa),
		SupersededAccount: identity(*superseded),
		Partition:         *partition,
	}

	var result ad.ServiceAccountMigrationResult
	switch *op {
	case "start":
		result, err = client.StartServiceAccountMigration(ctx, request)
	case "complete":
		// Completing also disables the superseded account and removes its SPNs.
		result, err = client.CompleteServiceAccountMigration(ctx, request)
	case "undo":
		// Undo steps back one stage; it does not re-enable the superseded
		// account or restore its service principal names.
		result, err = client.UndoServiceAccountMigration(ctx, request)
	case "reset":
		result, err = client.ResetServiceAccountMigration(ctx, request)
	default:
		fail(errors.New("unknown operation " + *op))
	}

	encoded, marshalErr := json.MarshalIndent(result, "", "  ")
	if marshalErr != nil {
		fail(marshalErr)
	}
	fmt.Println(string(encoded))

	if result.Partial {
		// The two writes are not atomic. Nothing is compensated automatically,
		// so the pair must be reconciled before another attempt.
		fmt.Fprintln(os.Stderr, "PARTIAL: one account was written and the other was not; read the pair and choose the next transition explicitly")
	}
	if err != nil {
		fail(err)
	}
}

func identity(dn string) ad.Identity {
	value, err := ad.IdentityByDN(dn)
	if err != nil {
		fail(err)
	}
	return value
}

func fail(err error) {
	fmt.Fprintln(os.Stderr, "error:", err)
	os.Exit(1)
}
