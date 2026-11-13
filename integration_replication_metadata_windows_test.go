//go:build windows && (amd64 || arm64)

package activedirectory

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"io"
	"os"
	"os/user"
	"reflect"
	"runtime"
	"strings"
	"testing"
	"time"
)

// The externally prepared fixture and reference are opt-in inputs. This test
// does not launch PowerShell, perform AD writes, or operate a lab/VM. Run the
// reference collector and this test as the same isolated-fixture identity.
func TestReplicationMetadataReferenceLab(t *testing.T) {
	path := os.Getenv("ADSDK_METADATA_REFERENCE")
	if path == "" {
		t.Skip("requires an isolated metadata reference fixture")
	}
	resultPath := os.Getenv("ADSDK_METADATA_RESULT")
	runID := os.Getenv("ADSDK_METADATA_RUN_ID")
	expectedHash := os.Getenv("ADSDK_METADATA_REFERENCE_SHA256")
	if resultPath == "" || runID == "" || len(expectedHash) != 64 {
		t.Fatal("fresh result path, run ID and reference SHA256 are required")
	}
	var reference metadataReference
	var counts searchNativeCounts
	artifact := struct {
		RunID, FixtureID, Phase, Server, ServerVersion, ModuleVersion, ReferenceSHA256 string
		RuntimeOS, RuntimeArchitecture                                                 string
		Started, Finished                                                              time.Time
		Passed, FullTicketComplete, ProvenanceVerified                                 bool
		NativeAllocationsRemaining                                                     map[string]int
		ObservationError                                                               string
		Attributes                                                                     *ReplicationAttributeMetadataResult `json:",omitempty"`
		Vectors                                                                        *ReplicationVectorsResult           `json:",omitempty"`
	}{RunID: runID, RuntimeOS: runtime.GOOS, RuntimeArchitecture: runtime.GOARCH, Started: time.Now().UTC()}
	defer func() {
		artifact.Finished = time.Now().UTC()
		artifact.Passed = !t.Failed()
		artifact.NativeAllocationsRemaining = map[string]int{"controls": counts.controls, "control_sets": counts.controlSets, "cookies": counts.cookies, "messages": counts.messages, "values": counts.values, "names": counts.names, "cursors": counts.cursors}
		payload, err := json.MarshalIndent(artifact, "", "  ")
		if err != nil {
			t.Error(err)
			return
		}
		file, err := os.OpenFile(resultPath, os.O_CREATE|os.O_EXCL|os.O_WRONLY, 0600)
		if err != nil {
			t.Error(err)
			return
		}
		_, writeErr := file.Write(append(payload, '\n'))
		closeErr := file.Close()
		if err := errors.Join(writeErr, closeErr); err != nil {
			t.Error(err)
		}
	}()
	file, err := os.Open(path)
	if err != nil {
		t.Fatal(err)
	}
	payload, readErr := io.ReadAll(io.LimitReader(file, 8*1024*1024+1))
	closeErr := file.Close()
	if err = errors.Join(readErr, closeErr); err != nil || len(payload) > 8*1024*1024 {
		t.Fatal("invalid or oversized reference")
	}
	digest := sha256.Sum256(payload)
	artifact.ReferenceSHA256 = hex.EncodeToString(digest[:])
	if !strings.EqualFold(artifact.ReferenceSHA256, expectedHash) {
		t.Fatal("reference hash mismatch")
	}
	decoder := json.NewDecoder(bytes.NewReader(payload))
	decoder.DisallowUnknownFields()
	if err := decoder.Decode(&reference); err != nil {
		t.Fatal(err)
	}
	if err := decoder.Decode(new(any)); err != io.EOF {
		t.Fatal("trailing reference content")
	}
	if err := validateMetadataReference(reference); err != nil {
		t.Fatal(err)
	}
	if reference.RunID != runID {
		t.Fatal("run ID mismatch")
	}
	identity, err := user.Current()
	if err != nil || !strings.EqualFold(identity.Uid, reference.IdentitySID) {
		t.Fatal("reference and SDK must run under the same Windows identity")
	}
	artifact.FixtureID = reference.FixtureID
	artifact.Phase = reference.Phase
	artifact.Server = reference.Server
	artifact.ServerVersion = reference.ServerVersion
	artifact.ModuleVersion = reference.ModuleVersion
	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Minute)
	defer cancel()
	config := Config{Endpoint: Endpoint{Host: reference.Server, Port: reference.Port}}
	dial := func(ctx context.Context, config Config) (*Client, error) {
		session, err := dialWithAPI(ctx, config, countedSearchAPI(&counts))
		if err != nil {
			return nil, err
		}
		return newClient(config, session), nil
	}
	var observedErr error
	var complete bool
	var count int
	if reference.Kind == "attributes" {
		query := ReplicationAttributeMetadataQuery{ObjectDN: reference.ObjectDN, Properties: reference.Properties, IncludeLinkedValues: reference.IncludeLinkedValues, IncludeDeletedObjects: reference.IncludeDeletedObjects, IncludeDeactivatedLinks: reference.IncludeDeletedObjects && reference.IncludeLinkedValues}
		result, err := readReplicationAttributeMetadata(ctx, config, query, dial)
		observedErr = err
		complete = result.Complete
		artifact.Attributes = &result
		if len(result.Servers) != 1 {
			t.Fatal("target result missing")
		}
		facts := metadataAttributeFacts(result.Servers[0])
		count = len(facts)
		if reference.ExpectedOutcome == "success" && !reflect.DeepEqual(metadataCanonical(facts), metadataCanonical(reference.Stamps)) {
			t.Error("attribute/link stamps differ from the same-server reference")
		}
	} else {
		result, err := readReplicationVectors(ctx, config, ReplicationVectorQuery{PartitionDNs: []string{reference.PartitionDN}}, dial)
		observedErr = err
		complete = result.Complete
		artifact.Vectors = &result
		if len(result.Servers) != 1 || len(result.Servers[0].Partitions) != 1 {
			t.Fatal("server/partition result missing")
		}
		facts := metadataCursorFacts(result.Servers[0].Partitions[0])
		count = len(facts)
		if reference.ExpectedOutcome == "success" && !reflect.DeepEqual(metadataCanonical(facts), metadataCanonical(reference.Cursors)) {
			t.Error("vector watermarks differ from the same-server reference")
		}
	}
	if observedErr != nil {
		artifact.ObservationError = observedErr.Error()
	}
	switch reference.ExpectedOutcome {
	case "success":
		if observedErr != nil || !complete || count == 0 {
			t.Errorf("reference succeeded but SDK is incomplete: %v", observedErr)
		}
	case "failure":
		if observedErr == nil || complete {
			t.Error("expected native failure")
		}
		found := false
		for _, code := range reference.ExpectedLDAPCodes {
			if hasLDAPCode(observedErr, code) {
				found = true
			}
		}
		if !found {
			t.Errorf("expected LDAP codes %v not retained: %v", reference.ExpectedLDAPCodes, observedErr)
		}
	case "unavailable":
		if !errors.Is(observedErr, ErrIncompleteResult) || complete || count != 0 {
			t.Error("omitted metadata was presented as a complete collection")
		}
	}
	if counts != (searchNativeCounts{}) {
		t.Errorf("native allocations remain: %+v", counts)
	}
}
