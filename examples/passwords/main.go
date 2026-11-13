// Passwords performs one explicitly selected operation. Password material is
// accepted only as bounded JSON on redirected stdin, never as command arguments.
package main

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"io"
	"os"
	"time"

	ad "github.com/deploymenttheory/go-sdk-activedirectory"
)

func main() {
	server := flag.String("server", "", "explicit LDAP server DNS name")
	dn := flag.String("dn", "", "explicit account DN")
	partition := flag.String("partition", "", "optional naming context")
	operation := flag.String("operation", "", "change or reset")
	apply := flag.Bool("apply", false, "explicitly execute one password operation")
	flag.Parse()
	if *server == "" || *dn == "" || (*operation != "change" && *operation != "reset") || !*apply {
		flag.Usage()
		os.Exit(2)
	}
	if err := run(*server, *dn, *partition, *operation); err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(1)
	}
}

func run(server, dn, partition, operation string) (err error) {
	info, err := os.Stdin.Stat()
	if err != nil {
		return err
	}
	if info.Mode()&os.ModeCharDevice != 0 {
		return errors.New("provide password JSON through redirected stdin; console echo input is refused")
	}
	input, err := io.ReadAll(io.LimitReader(os.Stdin, 65537))
	defer clear(input)
	if err != nil {
		return errors.New("could not read password input")
	}
	if len(input) > 65536 {
		return errors.New("password input exceeds example limit")
	}
	var secrets struct {
		OldPassword []byte `json:"oldPassword"`
		NewPassword []byte `json:"newPassword"`
	}
	defer func() { clear(secrets.OldPassword); clear(secrets.NewPassword) }()
	decoder := json.NewDecoder(bytes.NewReader(input))
	decoder.DisallowUnknownFields()
	if err := decoder.Decode(&secrets); err != nil {
		return errors.New("invalid password JSON; fields must contain base64 UTF-8 bytes")
	}
	var extra any
	if err := decoder.Decode(&extra); err != io.EOF {
		return errors.New("password input must contain exactly one JSON object")
	}
	if operation == "reset" && secrets.OldPassword != nil {
		return errors.New("reset input must omit oldPassword")
	}
	account, err := ad.IdentityByDN(dn)
	if err != nil {
		return err
	}
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()
	client, err := ad.Dial(ctx, ad.Config{Endpoint: ad.Endpoint{Host: server}, Transport: ad.TransportLDAPS})
	if err != nil {
		return err
	}
	defer func() { err = errors.Join(err, client.Close()) }()
	var result ad.PasswordResult
	if operation == "change" {
		result, err = client.ChangeAccountPassword(ctx, ad.PasswordChangeRequest{Identity: account, Partition: partition, OldPassword: secrets.OldPassword, NewPassword: secrets.NewPassword})
	} else {
		result, err = client.ResetAccountPassword(ctx, ad.PasswordResetRequest{Identity: account, Partition: partition, NewPassword: secrets.NewPassword})
	}
	fmt.Printf("write-state=%d encryption-bits=%d\n", result.State, result.Protection.CipherBits)
	return err
}
