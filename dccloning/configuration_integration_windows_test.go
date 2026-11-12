//go:build windows && (amd64 || arm64)

package dccloning

import (
	"context"
	"encoding/json"
	"os"
	"testing"
)

// This opt-in test writes a real clone configuration on a disposable source DC.
// The lab owner must prepare application inclusions/group membership and restore
// the owned configuration afterward. It never joins/groups/reboots/clones a VM.
func TestIntegrationCloneConfiguration(t *testing.T) {
	path := os.Getenv("ADSDK_CLONE_CONFIG_OPTIONS")
	if path == "" {
		t.Skip("set ADSDK_CLONE_CONFIG_OPTIONS to a disposable profile's ConfigOptions JSON")
	}
	if os.Getenv("ADSDK_CLONE_CONFIG_WRITE") != "1" {
		t.Fatal("ADSDK_CLONE_CONFIG_WRITE=1 is required for explicit file publication")
	}
	data, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	var options ConfigOptions
	if err := json.Unmarshal(data, &options); err != nil {
		t.Fatal(err)
	}
	if options.Offline {
		t.Fatal("integration qualification requires online checks")
	}
	if options.Directory == "" {
		t.Fatal("integration fixture must explicitly select its owned supported output directory")
	}
	r, err := GenerateConfig(context.Background(), options)
	encoded, encodeErr := json.Marshal(r)
	if encodeErr != nil {
		t.Fatal(encodeErr)
	}
	t.Log(string(encoded))
	if err != nil {
		t.Fatal(err)
	}
	if r.Outcome != Written || !r.Prerequisites.Complete || r.ChecksSkipped {
		t.Fatalf("incomplete preparation: %#v", r)
	}
	actual, err := os.ReadFile(r.Path)
	if err != nil {
		t.Fatal(err)
	}
	want, err := EncodeCloneConfiguration(options.Configuration)
	if err != nil {
		t.Fatal(err)
	}
	if string(actual) != string(want) {
		t.Fatal("published configuration differs from validated request")
	}
}
