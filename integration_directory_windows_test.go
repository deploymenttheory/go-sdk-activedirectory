//go:build windows && (amd64 || arm64)

package activedirectory

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"os"
	"runtime"
	"strings"
	"testing"
	"time"
)

// The outer reference harness supplies these paths only inside an owned run.
// This test never starts PowerShell, verifies a receipt's provenance, creates a
// trust, or operates a VM. Ordinary go test invocations skip it.
func TestDirectoryProjectionLab(t *testing.T) {
	path := os.Getenv("ADSDK_DIRECTORY_REFERENCE")
	if path == "" {
		t.Skip("requires the opt-in isolated directory reference harness")
	}
	resultPath := os.Getenv("ADSDK_DIRECTORY_RESULT")
	runID := os.Getenv("ADSDK_DIRECTORY_RUN_ID")
	wantHash := os.Getenv("ADSDK_DIRECTORY_REFERENCE_SHA256")
	if resultPath == "" || runID == "" || len(wantHash) != 64 {
		t.Fatal("reference path, SHA256, run identity and fresh result path are required")
	}
	artifact := struct {
		SchemaVersion        int                 `json:"schema_version"`
		Scope                string              `json:"scope"`
		RunID                string              `json:"run_id"`
		FixtureID            string              `json:"fixture_id"`
		Profile              string              `json:"profile"`
		Server               string              `json:"server"`
		SDKRevision          string              `json:"sdk_revision"`
		ReferenceSHA256      string              `json:"reference_sha256"`
		BinarySHA256         string              `json:"binary_sha256"`
		RuntimeOS            string              `json:"runtime_os"`
		RuntimeArchitecture  string              `json:"runtime_architecture"`
		Started              time.Time           `json:"started"`
		Finished             time.Time           `json:"finished"`
		Passed               bool                `json:"passed"`
		FullTicketComplete   bool                `json:"full_ticket_complete"`
		ProvenanceVerified   bool                `json:"reference_provenance_verified"`
		FailureStage         string              `json:"failure_stage,omitempty"`
		AllocationsRemaining map[string]int      `json:"native_allocations_remaining"`
		Comparison           directoryComparison `json:"comparison"`
	}{SchemaVersion: 1, Scope: "directory-projection-differential", RunID: runID, RuntimeOS: runtime.GOOS, RuntimeArchitecture: runtime.GOARCH, Started: time.Now().UTC()}
	stage := "reference-input"
	defer func() {
		artifact.Finished = time.Now().UTC()
		if t.Failed() {
			artifact.Passed = false
			artifact.FailureStage = stage
		}
		data, err := json.MarshalIndent(artifact, "", "  ")
		if err != nil {
			t.Error("cannot encode native artifact")
			return
		}
		file, err := os.OpenFile(resultPath, os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0600)
		if err != nil {
			t.Error("cannot create fresh native artifact")
			return
		}
		_, writeErr := file.Write(append(data, '\n'))
		closeErr := file.Close()
		if writeErr != nil || closeErr != nil {
			t.Error("cannot finish native artifact")
		}
	}()
	file, err := os.Open(path)
	if err != nil {
		t.Fatal("cannot read reference artifact")
	}
	data, err := io.ReadAll(io.LimitReader(file, 8*1024*1024+1))
	closeErr := file.Close()
	if err != nil || closeErr != nil || len(data) > 8*1024*1024 {
		t.Fatal("invalid or oversized reference artifact")
	}
	digest := sha256.Sum256(data)
	artifact.ReferenceSHA256 = hex.EncodeToString(digest[:])
	if !strings.EqualFold(artifact.ReferenceSHA256, wantHash) {
		t.Fatal("reference hash mismatch")
	}
	var ref directoryReference
	if err := json.Unmarshal(data, &ref); err != nil {
		t.Fatal("reference JSON is invalid")
	}
	if ref.RunID != runID || ref.Passed == nil || !*ref.Passed {
		t.Fatal("reference run identity or collection status mismatch")
	}
	if err := validateDirectoryReference(ref); err != nil {
		t.Fatalf("reference profile: %v", err)
	}
	// Normalize collection ordering using the same ordinal implementation on
	// both sides; PowerShell and Go can otherwise order supplementary Unicode
	// differently. Binary values remain case-sensitive.
	normalized := directoryFacts{}
	for key, values := range ref.Facts {
		lower := strings.ToLower(key)
		if _, exists := normalized[lower]; exists {
			t.Fatal("case-ambiguous reference fact keys")
		}
		putFact(normalized, lower, values...)
	}
	ref.Facts = normalized
	artifact.FixtureID, artifact.Profile, artifact.Server, artifact.SDKRevision = ref.FixtureID, ref.Profile, ref.Server, ref.SDKRevision
	stage = "binary-identity"
	executable, err := os.Executable()
	if err != nil {
		t.Fatal("cannot identify test binary")
	}
	binary, err := os.Open(executable)
	if err != nil {
		t.Fatal("cannot hash test binary")
	}
	hash := sha256.New()
	_, err = io.Copy(hash, binary)
	closeErr = binary.Close()
	if err != nil || closeErr != nil {
		t.Fatal("cannot finish test binary hash")
	}
	artifact.BinarySHA256 = hex.EncodeToString(hash.Sum(nil))
	ctx, cancel := context.WithTimeout(context.Background(), 8*time.Minute)
	defer cancel()
	stage = "native-dial"
	client, err := Dial(ctx, Config{Endpoint: Endpoint{Host: ref.Server, Port: 389}, Timeout: 30 * time.Second})
	if err != nil {
		t.Fatal("native directory dial failed")
	}
	defer client.Close()
	var counts searchNativeCounts
	client.session.(*ldapSession).api = countedSearchAPI(&counts)
	stage = "projection-comparison"
	artifact.Comparison = compareDirectoryWithReference(ctx, client, ref)
	if !artifact.Comparison.passed() {
		t.Error("directory projection comparison failed; inspect check names and mismatch keys in the artifact")
	}
	if !t.Failed() {
		stage = "native-cleanup"
	}
	closeErr = client.Close()
	artifact.Comparison.check("client-close", closeErr == nil, closeErr)
	if closeErr != nil {
		t.Error("native client cleanup failed")
	}
	artifact.AllocationsRemaining = map[string]int{"messages": counts.messages, "request_controls": counts.controls, "response_controls": counts.controlSets, "cookies": counts.cookies, "values": counts.values, "names": counts.names, "attribute_cursors": counts.cursors}
	if counts != (searchNativeCounts{}) {
		t.Error("native allocations remain after comparison")
	}
	artifact.Comparison.check("native-allocation-balance", counts == (searchNativeCounts{}), nil)
	artifact.Passed = !t.Failed() && artifact.Comparison.passed()
	if artifact.Passed {
		stage = "complete"
	}
	t.Log(fmt.Sprintf("projection comparison profile=%s; full ticket qualification remains incomplete", ref.Profile))
}
