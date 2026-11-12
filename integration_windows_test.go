//go:build windows && (amd64 || arm64)

package activedirectory

import (
	"context"
	"encoding/json"
	"errors"
	"os"
	"strings"
	"testing"
	"time"
)

// The lab runner supplies a fixed server and private result path. Ordinary unit
// test runs never discover a domain, contact a server, or write this artifact.
func TestRootDSELab(t *testing.T) {
	server := os.Getenv("ADSDK_LDAP_SERVER")
	if server == "" {
		t.Skip("requires an explicitly configured isolated AD lab")
	}
	ctx, cancel := context.WithTimeout(context.Background(), 60*time.Second)
	defer cancel()
	config := Config{Endpoint: Endpoint{Host: server}, Timeout: 5 * time.Second}
	client, err := Dial(ctx, config)
	if err != nil {
		t.Fatal(err)
	}
	defer client.Close()
	first, err := client.RootDSE(ctx, RootDSEOptions{})
	if err != nil {
		t.Fatal(err)
	}
	if first.DNSHostName == nil || !strings.EqualFold(*first.DNSHostName, server) {
		t.Fatal("read did not return the explicitly selected server")
	}
	if first.DefaultNamingContext == nil || first.CurrentTime == nil || first.DomainFunctionality == nil || len(first.SupportedCapabilities) == 0 {
		t.Fatal("typed RootDSE projection is incomplete")
	}
	selected, err := client.RootDSE(ctx, RootDSEOptions{Properties: []string{"supportedExtension"}})
	if err != nil {
		t.Fatal(err)
	}
	if len(selected.Attributes["supportedextension"]) == 0 {
		t.Fatal("selected operational property missing")
	}
	all, err := client.RootDSE(ctx, RootDSEOptions{Properties: []string{"*"}})
	if err != nil {
		t.Fatal(err)
	}
	if len(all.Attributes) < len(first.Attributes) {
		t.Fatal("wildcard lost explicit default properties")
	}
	if err := client.Close(); err != nil {
		t.Fatal(err)
	}
	if _, err := client.RootDSE(ctx, RootDSEOptions{}); !errors.Is(err, ErrClosed) {
		t.Fatalf("read after close: %v", err)
	}
	for i := 0; i < 10; i++ {
		connection, err := Dial(ctx, config)
		if err != nil {
			t.Fatal(err)
		}
		_, readErr := connection.RootDSE(ctx, RootDSEOptions{})
		closeErr := connection.Close()
		if err := errors.Join(readErr, closeErr); err != nil {
			t.Fatalf("open/read/close iteration %d: %v", i, err)
		}
	}
	// An unused TCP port on the explicitly selected lab server gives a bounded
	// native connection failure without DNS discovery or external networking.
	failedConfig := config
	failedConfig.Endpoint.Port = 1
	failedConfig.Timeout = time.Second
	started := time.Now()
	failed, failure := Dial(ctx, failedConfig)
	if failed != nil {
		_ = failed.Close()
		t.Fatal("unexpected LDAP service on lab port 1")
	}
	var native *LDAPError
	if !errors.As(failure, &native) {
		t.Fatalf("native endpoint failure was lost: %v", failure)
	}
	if time.Since(started) > 5*time.Second {
		t.Fatal("invalid endpoint exceeded the observed connect bound")
	}
	artifact := map[string]any{
		"passed": true, "server": server, "attributes": first.Attributes, "selected_attributes": selected.Attributes,
		"wildcard_attribute_count": len(all.Attributes), "repeated_open_read_close": 10, "invalid_endpoint_ldap_code": native.Code,
		"invalid_endpoint_elapsed_ms": time.Since(started).Milliseconds(),
	}
	path := os.Getenv("ADSDK_LDAP_RESULT")
	if path != "" {
		data, err := json.MarshalIndent(artifact, "", "  ")
		if err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(path, append(data, '\n'), 0600); err != nil {
			t.Fatal(err)
		}
	}
}
