//go:build integration && windows && (amd64 || arm64)

package activedirectory

import (
	"context"
	"encoding/json"
	"errors"
	"os"
	"runtime"
	"strconv"
	"strings"
	"testing"
	"time"
)

// This test never provisions fixtures, changes policy, or retries a write.
// Run only under the existing lab's ownership/deadline/evidence process.
func TestSyncObjectLab(t *testing.T) {
	if os.Getenv("AD_OBJECT_SYNC_LAB_ALLOW_CHANGES") != "disposable-object" {
		t.Skip("set AD_OBJECT_SYNC_LAB_ALLOW_CHANGES=disposable-object")
	}
	endpoint := func(prefix string) Endpoint {
		port, err := strconv.ParseUint(os.Getenv(prefix+"_PORT"), 10, 16)
		if err != nil || port == 0 {
			t.Fatal(prefix + "_PORT must be explicit")
		}
		return Endpoint{Host: os.Getenv(prefix), Port: uint16(port)}
	}
	source := Config{Endpoint: endpoint("AD_OBJECT_SYNC_LAB_SOURCE"), Timeout: 2 * time.Minute}
	destination := Config{Endpoint: endpoint("AD_OBJECT_SYNC_LAB_DESTINATION"), Timeout: 2 * time.Minute}
	passwordText := os.Getenv("AD_OBJECT_SYNC_LAB_PASSWORD_ONLY")
	if passwordText != "" && passwordText != "1" {
		t.Fatal("PASSWORD_ONLY must be empty or 1")
	}
	request := SyncObjectRequest{Source: source, Partition: os.Getenv("AD_OBJECT_SYNC_LAB_PARTITION"), Object: SyncObjectIdentity{DistinguishedName: os.Getenv("AD_OBJECT_SYNC_LAB_OBJECT")}, PasswordOnly: passwordText == "1"}
	if !request.PasswordOnly {
		request.Properties = strings.Split(os.Getenv("AD_OBJECT_SYNC_LAB_PROPERTIES"), ",")
	}
	if err := request.Validate(); err != nil {
		t.Fatal(err)
	}
	if err := destination.Validate(); err != nil {
		t.Fatal(err)
	}
	expectedText := os.Getenv("AD_OBJECT_SYNC_LAB_EXPECT")
	states := map[string]ObjectSyncWriteState{"accepted": ObjectSyncAccepted, "not-attempted": ObjectSyncNotAttempted, "rejected": ObjectSyncRejected, "uncertain": ObjectSyncUncertain}
	expected, ok := states[expectedText]
	if !ok {
		t.Fatal("EXPECT must explicitly name accepted, not-attempted, rejected, or uncertain")
	}
	revision, runID := os.Getenv("AD_OBJECT_SYNC_LAB_REVISION"), os.Getenv("AD_OBJECT_SYNC_LAB_RUN_ID")
	if len(revision) != 40 || runID == "" {
		t.Fatal("REVISION (full tested source SHA) and RUN_ID required")
	}
	var reference *syncObjectReference
	if path := os.Getenv("AD_OBJECT_SYNC_LAB_REFERENCE"); path != "" {
		data, err := os.ReadFile(path)
		if err != nil {
			t.Fatal(err)
		}
		reference = new(syncObjectReference)
		if err = json.Unmarshal(data, reference); err != nil {
			t.Fatal(err)
		}
		if err = reference.validate(source.Endpoint, destination.Endpoint, request, revision, runID); err != nil {
			t.Fatal(err)
		}
	}
	// Reserve a fresh evidence file before any native work. Never overwrite proof.
	output, err := os.OpenFile(os.Getenv("AD_OBJECT_SYNC_LAB_OUTPUT"), os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0600)
	if err != nil {
		t.Fatal(err)
	}
	defer output.Close()
	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Minute)
	defer cancel()
	c, err := Dial(ctx, destination)
	if err != nil {
		t.Fatal(err)
	}
	result, syncErr := c.SyncObject(ctx, request)
	closeErr := c.Close()
	evidence := struct {
		Schema      int              `json:"schema"`
		Revision    string           `json:"revision"`
		RunID       string           `json:"run_id"`
		ObservedUTC time.Time        `json:"observed_utc"`
		Runtime     string           `json:"runtime"`
		Result      SyncObjectResult `json:"result"`
		Error       string           `json:"error"`
	}{1, revision, runID, time.Now().UTC(), runtime.Version() + " " + runtime.GOOS + "/" + runtime.GOARCH, result, ""}
	if joined := errors.Join(syncErr, closeErr); joined != nil {
		evidence.Error = joined.Error()
	}
	if err = json.NewEncoder(output).Encode(evidence); err != nil {
		t.Fatal(err)
	}
	if result.State != expected {
		t.Fatalf("write state=%d expected=%d error=%v", result.State, expected, syncErr)
	}
	if expected == ObjectSyncAccepted && (syncErr != nil || !result.Verified) {
		t.Fatalf("accepted but unverified: %v", syncErr)
	}
	if expected != ObjectSyncAccepted && syncErr == nil {
		t.Fatal("negative case returned no error")
	}
	if closeErr != nil {
		t.Fatal(closeErr)
	}
	if reference != nil {
		if request.PasswordOnly && reference.SecretCacheObserved != result.SecretCacheObserved {
			t.Fatal("reference secret cache observation differs")
		}
		if !syncValuesEqual([][]byte{reference.Destination.GUID}, [][]byte{syncGUID(result.DestinationObject)}) {
			t.Fatal("reference destination GUID differs")
		}
		for property, want := range reference.Destination.Attributes {
			got, state := result.DestinationObject.Attribute(property)
			if state != AttributePresent || !syncValuesEqual(want, got) {
				t.Fatal("reference property differs: " + property)
			}
		}
	}
}
