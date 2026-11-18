// Command portabletls authenticates once over verified LDAPS or StartTLS and
// reads RootDSE. Password bytes come only from redirected stdin and are cleared.
package main

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"errors"
	"flag"
	"fmt"
	"io"
	"os"
	"time"

	ad "github.com/deploymenttheory/go-sdk-activedirectory/activedirectory"
)

func main() {
	server := flag.String("server", "", "fully qualified directory server hostname")
	port := flag.Uint("port", 0, "explicit port; zero selects the transport default")
	transport := flag.String("transport", "ldaps", "ldaps or starttls")
	username := flag.String("username", "", "explicit LDAP bind name, such as a UPN")
	caFile := flag.String("ca", "", "optional PEM file containing private trust roots")
	flag.Parse()
	if err := run(*server, *port, *transport, *username, *caFile); err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(1)
	}
}

func run(server string, port uint, transport, username, caFile string) (err error) {
	if port > 65535 || username == "" {
		return fmt.Errorf("%w: a username and valid port are required", ad.ErrInvalidConfig)
	}
	selected := ad.TransportLDAPS
	switch transport {
	case "ldaps":
	case "starttls":
		selected = ad.TransportStartTLS
	default:
		return fmt.Errorf("%w: transport must be ldaps or starttls", ad.ErrInvalidConfig)
	}
	endpoint := ad.Endpoint{Host: server, Port: uint16(port)}
	if err := (ad.Config{Endpoint: endpoint}).Validate(); err != nil {
		return err
	}
	var roots *x509.CertPool
	if caFile != "" {
		pem, readErr := os.ReadFile(caFile)
		if readErr != nil {
			return fmt.Errorf("read public CA roots: %w", readErr)
		}
		roots = x509.NewCertPool()
		if !roots.AppendCertsFromPEM(pem) {
			return fmt.Errorf("%w: CA file contains no PEM certificates", ad.ErrInvalidConfig)
		}
	}
	info, err := os.Stdin.Stat()
	if err != nil {
		return fmt.Errorf("inspect password input: %w", err)
	}
	if info.Mode()&os.ModeCharDevice != 0 {
		return fmt.Errorf("%w: supply exact password bytes through redirected stdin; interactive echo is disabled", ad.ErrInvalidConfig)
	}
	password, err := io.ReadAll(io.LimitReader(os.Stdin, 65537))
	defer clear(password)
	if err != nil {
		return fmt.Errorf("read password input: %w", err)
	}
	if len(password) > 65536 {
		return fmt.Errorf("%w: password input exceeds the example's 64 KiB limit", ad.ErrInvalidConfig)
	}
	options := ad.Config{
		Backend: ad.BackendPortable, Endpoint: endpoint, Transport: selected,
		Authentication: ad.AuthenticationSimple,
		Credentials:    &ad.Credentials{Username: username, Password: password},
		TLS:            &ad.TLSOptions{RootCAs: roots},
	}
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()
	client, err := ad.Dial(ctx, options)
	clear(password)
	options.Credentials = nil
	if err != nil {
		return err
	}
	defer func() { err = errors.Join(err, client.Close()) }()
	protection, err := client.Protection(ctx)
	if err != nil {
		return err
	}
	if !protection.Complete || !protection.TLSVerified || protection.TLSVersion < tls.VersionTLS12 || protection.CipherBits < 128 {
		return ad.ErrTLSNegotiation
	}
	root, err := client.Directory.RootDSE(ctx, ad.RootDSEOptions{})
	if err != nil {
		return err
	}
	if err := root.Capabilities().RequireADDS("portable TLS example"); err != nil {
		return err
	}
	fmt.Printf("Verified %s, %s, %d-bit cipher\n",
		tls.VersionName(protection.TLSVersion), tls.CipherSuiteName(protection.TLSCipherSuite), protection.CipherBits)
	if root.DNSHostName != nil {
		fmt.Println("Server:", *root.DNSHostName)
	}
	return nil
}
