// tls-peer is a bounded, test-only LDAP TLS fixture. It is not an LDAP server.
package main

import (
	"context"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"io"
	"os"
	"os/signal"
	"path/filepath"
)

var errArguments = errors.New("invalid fixture arguments")

func main() {
	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt)
	defer stop()
	if err := run(ctx, os.Args[1:]); err != nil {
		// Never print input, PEM content, or network error text.
		_, _ = fmt.Fprintln(os.Stderr, "tls-peer: fixture failed")
		os.Exit(1)
	}
}

func run(ctx context.Context, args []string) error {
	if len(args) == 0 {
		return errArguments
	}
	switch args[0] {
	case "generate":
		fs := flag.NewFlagSet("generate", flag.ContinueOnError)
		fs.SetOutput(io.Discard)
		dir := fs.String("dir", "", "new owned fixture directory")
		server := fs.String("server", "", "owned lab FQDN")
		if err := fs.Parse(args[1:]); err != nil || fs.NArg() != 0 {
			return errArguments
		}
		return generateCertificates(*dir, *server)
	case "serve":
		return serve(ctx, args[1:])
	default:
		return errArguments
	}
}

// Publish a complete JSON file atomically without replacing an existing path.
// A hard link in the same directory supplies create-new semantics on Windows
// and Unix. Both files contain only public fixture metadata.
func publishJSON(path string, value any) error {
	data, err := json.MarshalIndent(value, "", "  ")
	if err != nil {
		return fmt.Errorf("encode fixture metadata: %w", err)
	}
	file, err := os.CreateTemp(filepath.Dir(path), ".tls-peer-*.json")
	if err != nil {
		return fmt.Errorf("create metadata: %w", err)
	}
	temporary := file.Name()
	defer func() { _ = os.Remove(temporary) }()
	_, writeErr := file.Write(append(data, '\n'))
	closeErr := file.Close()
	if err := errors.Join(writeErr, closeErr); err != nil {
		return fmt.Errorf("write metadata: %w", err)
	}
	if err := os.Link(temporary, path); err != nil {
		return fmt.Errorf("publish metadata: %w", err)
	}
	return nil
}
