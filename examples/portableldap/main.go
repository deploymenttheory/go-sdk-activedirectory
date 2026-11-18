package main

import (
	"context"
	"crypto/x509"
	"errors"
	"flag"
	"fmt"
	"io"
	"os"
	"time"

	ad "github.com/deploymenttheory/go-sdk-activedirectory/activedirectory"
)

func run(server, username, transport, caFile string, port uint) (err error) {
	if port > 65535 {
		return errors.New("port exceeds 65535")
	}
	options := ad.Config{
		Backend: ad.BackendPortable, Endpoint: ad.Endpoint{Host: server, Port: uint16(port)},
		Authentication: ad.AuthenticationSimple, Transport: ad.TransportLDAPS, Timeout: 10 * time.Second,
	}
	switch transport {
	case "ldaps":
	case "starttls":
		options.Transport = ad.TransportStartTLS
	default:
		return errors.New("transport must be ldaps or starttls")
	}
	if caFile != "" {
		pem, err := os.ReadFile(caFile)
		if err != nil {
			return err
		}
		roots := x509.NewCertPool()
		if !roots.AppendCertsFromPEM(pem) {
			return errors.New("CA file contains no PEM certificate")
		}
		options.TLS = &ad.TLSOptions{RootCAs: roots}
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
	options.Credentials = &ad.Credentials{Username: username, Password: password}
	ctx, cancel := context.WithTimeout(context.Background(), 20*time.Second)
	defer cancel()
	client, err := ad.Dial(ctx, options)
	clear(password)
	options.Credentials = nil
	if err != nil {
		return err
	}
	defer func() { err = errors.Join(err, client.Close()) }()
	protection, err := client.Directory.Protection(ctx)
	if err != nil || !protection.Complete {
		return errors.Join(err, ad.ErrIncompleteResult)
	}
	fmt.Printf("Verified TLS: %t, version: 0x%04x, cipher: 0x%04x, bits: %d\n",
		protection.TLSVerified, protection.TLSVersion, protection.TLSCipherSuite, protection.CipherBits)
	root, err := client.Directory.RootDSE(ctx, ad.RootDSEOptions{})
	if err != nil {
		return err
	}
	if root.DNSHostName != nil {
		fmt.Println("Server:", *root.DNSHostName)
	}
	fmt.Println("Naming contexts:", root.NamingContexts)
	return nil
}

func main() {
	server := flag.String("server", "", "fully qualified LDAP server hostname")
	port := flag.Uint("port", 0, "explicit port; zero uses the selected transport's standard port")
	username := flag.String("username", "", "explicit LDAP bind name; exact password bytes are read from redirected stdin")
	transport := flag.String("transport", "ldaps", "ldaps or starttls")
	caFile := flag.String("ca", "", "PEM CA file; empty uses system roots")
	flag.Parse()
	if err := run(*server, *username, *transport, *caFile, *port); err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(1)
	}
}
