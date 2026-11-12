package main

import (
	"context"
	"errors"
	"flag"
	"fmt"
	"io"
	"os"
	"time"

	ad "github.com/deploymenttheory/go-sdk-activedirectory"
)

func run(server string, port uint, transport, partition, bindDN string) (err error) {
	if port > 65535 {
		return errors.New("port must fit 16 bits")
	}
	config := ad.Config{
		Endpoint:       ad.Endpoint{Host: server, Port: uint16(port)},
		Authentication: ad.AuthenticationSimple, Partition: partition,
	}
	switch transport {
	case "ldaps":
		config.Transport = ad.TransportLDAPS
	case "starttls":
		config.Transport = ad.TransportStartTLS
	default:
		return errors.New("transport must be ldaps or starttls")
	}
	info, err := os.Stdin.Stat()
	if err != nil {
		return err
	}
	if info.Mode()&os.ModeCharDevice != 0 {
		return errors.New("supply exact UTF-8 password bytes through redirected stdin; interactive password echo is disabled")
	}
	password, err := io.ReadAll(io.LimitReader(os.Stdin, 65537))
	defer clear(password)
	if err != nil {
		return err
	}
	if len(password) > 65536 {
		return errors.New("password input exceeds the example's 64 KiB input limit")
	}
	config.Credentials = &ad.Credentials{Username: bindDN, Password: password}
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()
	client, err := ad.Dial(ctx, config)
	clear(password)
	config.Credentials = nil
	if err != nil {
		return err
	}
	defer func() { err = errors.Join(err, client.Close()) }()
	capabilities, err := client.Capabilities(ctx)
	if err != nil {
		return err
	}
	selected, err := client.Partition(ctx)
	if err != nil {
		return err
	}
	fmt.Println("Directory:", capabilities.Type)
	fmt.Println("Partition:", selected.DistinguishedName)
	fmt.Println("Advertised capabilities:", capabilities.OIDs)
	return nil
}

func main() {
	server := flag.String("server", "", "fully qualified LDS server hostname matching its certificate")
	port := flag.Uint("port", 0, "instance port; defaults to 636 for LDAPS or 389 for StartTLS")
	transport := flag.String("transport", "ldaps", "ldaps or starttls")
	partition := flag.String("partition", "", "naming context DN; empty requires an advertised default")
	bindDN := flag.String("bind-dn", "", "LDS principal bind DN; password is read from redirected stdin")
	flag.Parse()
	if err := run(*server, *port, *transport, *partition, *bindDN); err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(1)
	}
}
