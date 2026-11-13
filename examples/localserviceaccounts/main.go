// Local managed service account install and uninstall. These change THIS
// host's credential state, so every write needs -apply. Preview is read-only.
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
	op := flag.String("operation", "preview", "preview, install, uninstall or reset")
	dn := flag.String("dn", "", "explicit service account DN")
	partition := flag.String("partition", "", "explicit partition")
	force := flag.Bool("force", false, "standalone account associated with another computer")
	forceRemoveLocal := flag.Bool("force-remove-local", false, "allow the documented offline removal phase")
	prompt := flag.Bool("prompt-password", false, "read a standalone account password from stdin")
	apply := flag.Bool("apply", false, "execute the selected write on this host")
	flag.Parse()
	if *server == "" || *dn == "" || (*op != "preview" && !*apply) {
		fmt.Fprintln(os.Stderr, "usage: -server <endpoint> -dn <account DN> [-operation preview|install|uninstall|reset] [-apply]")
		os.Exit(2)
	}

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Minute)
	defer cancel()
	client, err := ad.Dial(ctx, ad.Config{Endpoint: ad.Endpoint{Host: *server}})
	if err != nil {
		fail(err)
	}
	defer client.Close()

	identity, err := ad.IdentityByDN(*dn)
	if err != nil {
		fail(err)
	}

	switch *op {
	case "preview", "install":
		request := ad.InstallLocalServiceAccountRequest{
			Identity:  identity,
			Partition: *partition,
			Force:     *force,
			Preview:   *op == "preview",
		}
		if *prompt {
			// The callback owns its UI. Returned bytes transfer to the SDK and
			// are erased on exit, so this must not hand back a shared buffer.
			request.PasswordPrompt = func(context.Context, ad.ServiceAccount) ([]byte, error) {
				fmt.Fprint(os.Stderr, "standalone account password: ")
				var entered string
				if _, err := fmt.Fscanln(os.Stdin, &entered); err != nil {
					return nil, err
				}
				return []byte(entered), nil
			}
		}
		report(client.InstallLocalServiceAccount(ctx, request))
	case "reset":
		// No password is taken: the host is asked to refresh the credential
		// it already holds, so the account must already be installed here.
		report(client.ResetLocalServiceAccountPassword(ctx, ad.ResetLocalServiceAccountPasswordRequest{
			Identity:  identity,
			Partition: *partition,
		}))
	case "uninstall":
		report(client.UninstallLocalServiceAccount(ctx, ad.UninstallLocalServiceAccountRequest{
			Identity:         identity,
			Partition:        *partition,
			ForceRemoveLocal: *forceRemoveLocal,
		}))
	default:
		fail(errors.New("unknown operation " + *op))
	}
}

// report prints the observation even on failure: an uncertain local outcome
// still carries the state a caller must reconcile before retrying.
func report(result ad.LocalServiceAccountResult, err error) {
	encoded, marshalErr := json.MarshalIndent(result, "", "  ")
	if marshalErr != nil {
		fail(marshalErr)
	}
	fmt.Println(string(encoded))
	if result.PartialEffectsPossible && err != nil {
		fmt.Fprintln(os.Stderr, "note: a native call was attempted; local and directory state may both have changed")
	}
	if err != nil {
		fail(err)
	}
}

func fail(err error) {
	fmt.Fprintln(os.Stderr, "error:", err)
	os.Exit(1)
}
