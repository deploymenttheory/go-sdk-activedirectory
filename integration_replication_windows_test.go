//go:build windows && (amd64 || arm64)

package activedirectory

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"testing"
	"time"
)

// Opt-in, read-only collection against an already provisioned owned DC pair.
// No PowerShell, child process, fixture mutation, VM operation or credential
// creation occurs here. The outer runner owns before/native/after sequencing.
func TestReplicationDiagnosticsLab(t *testing.T) {
	path := os.Getenv("ADSDK_REPLICATION_REFERENCE")
	if path == "" {
		t.Skip("requires the explicit owned DC-pair reference run")
	}
	referenceFile, err := os.Open(path)
	if err != nil {
		t.Fatal("cannot open replication reference")
	}
	data, readErr := io.ReadAll(io.LimitReader(referenceFile, 8*1024*1024+1))
	if errors.Join(readErr, referenceFile.Close()) != nil || len(data) > 8*1024*1024 {
		t.Fatal("cannot read bounded replication reference")
	}
	digest := sha256.Sum256(data)
	if !strings.EqualFold(hex.EncodeToString(digest[:]), os.Getenv("ADSDK_REPLICATION_REFERENCE_SHA256")) {
		t.Fatal("replication reference hash mismatch")
	}
	var reference struct {
		SchemaVersion    int      `json:"schema_version"`
		Purpose          string   `json:"purpose"`
		Phase            string   `json:"phase"`
		Passed           bool     `json:"passed"`
		RunID            string   `json:"run_id"`
		FixtureID        string   `json:"fixture_id"`
		SDKRevision      string   `json:"sdk_revision"`
		BinarySHA256     string   `json:"binary_sha256"`
		ClientComputer   string   `json:"client_computer"`
		DomainDNS        string   `json:"domain_dns"`
		DomainDN         string   `json:"domain_dn"`
		DomainGUIDBinary string   `json:"domain_guid_binary"`
		Servers          []string `json:"servers"`
	}
	if err = json.Unmarshal(data, &reference); err != nil {
		t.Fatal("invalid reference JSON")
	}
	host, err := os.Hostname()
	if err != nil {
		t.Fatal("cannot identify collector")
	}
	if reference.SchemaVersion != 1 || reference.Purpose != "go-sdk-activedirectory-replication-reference" || reference.Phase != "before" || !reference.Passed || reference.RunID != os.Getenv("ADSDK_REPLICATION_RUN_ID") || reference.DomainDNS != "ad.sdk.test" || reference.DomainDN == "" || !strings.EqualFold(reference.ClientComputer, host) || len(reference.Servers) != 2 || strings.EqualFold(reference.Servers[0], reference.Servers[1]) {
		t.Fatal("reference run/collector/owned-domain identity mismatch")
	}
	if revision, err := hex.DecodeString(reference.SDKRevision); err != nil || len(revision) != 20 {
		t.Fatal("invalid source commit pin")
	}
	if filepath.Base(filepath.Dir(path)) != reference.RunID || filepath.Base(path) != "replication-before.json" {
		t.Fatal("reference path is outside the named run")
	}
	for _, server := range reference.Servers {
		if !strings.EqualFold(server, "adsdk25dc1.ad.sdk.test") && !strings.EqualFold(server, "adsdk25dc2.ad.sdk.test") {
			t.Fatal("unowned replication target")
		}
	}
	executable, err := os.Executable()
	if err != nil {
		t.Fatal("cannot identify test binary")
	}
	file, err := os.Open(executable)
	if err != nil {
		t.Fatal("cannot hash test binary")
	}
	hash := sha256.New()
	_, readErr = io.Copy(hash, file)
	closeErr := file.Close()
	if readErr != nil || closeErr != nil || !strings.EqualFold(hex.EncodeToString(hash.Sum(nil)), reference.BinarySHA256) {
		t.Fatal("native test binary pin mismatch")
	}
	artifact := struct {
		SchemaVersion      int                    `json:"schema_version"`
		Purpose            string                 `json:"purpose"`
		RunID              string                 `json:"run_id"`
		FixtureID          string                 `json:"fixture_id"`
		SDKRevision        string                 `json:"sdk_revision"`
		BinarySHA256       string                 `json:"binary_sha256"`
		ReferenceSHA256    string                 `json:"reference_sha256"`
		OS                 string                 `json:"runtime_os"`
		Architecture       string                 `json:"runtime_architecture"`
		Started            time.Time              `json:"started"`
		Finished           time.Time              `json:"finished"`
		Passed             bool                   `json:"passed"`
		FullTicketComplete bool                   `json:"full_ticket_complete"`
		ProvenanceVerified bool                   `json:"source_provenance_verified"`
		Servers            []string               `json:"servers"`
		Records            []replicationLabServer `json:"records"`
		FailureStage       string                 `json:"failure_stage,omitempty"`
	}{SchemaVersion: 1, Purpose: "go-sdk-activedirectory-replication-native", RunID: reference.RunID, FixtureID: reference.FixtureID, SDKRevision: reference.SDKRevision, BinarySHA256: reference.BinarySHA256, ReferenceSHA256: hex.EncodeToString(digest[:]), OS: runtime.GOOS, Architecture: runtime.GOARCH, Started: time.Now().UTC(), Servers: reference.Servers, Records: []replicationLabServer{}}
	stage := "identity-preflight"
	defer func() {
		artifact.Finished = time.Now().UTC()
		artifact.Passed = !t.Failed()
		if t.Failed() {
			artifact.FailureStage = stage
		}
		encoded, err := json.MarshalIndent(artifact, "", "  ")
		if err != nil {
			t.Error("cannot encode native replication artifact")
			return
		}
		result, err := os.OpenFile(filepath.Join(filepath.Dir(path), "replication-native.json"), os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0600)
		if err != nil {
			t.Error("cannot create fresh native replication artifact")
			return
		}
		_, writeErr := result.Write(append(encoded, '\n'))
		if errors.Join(writeErr, result.Close()) != nil {
			t.Error("cannot finish native replication artifact")
		}
	}()
	ctx, cancel := context.WithTimeout(context.Background(), 3*time.Minute)
	defer cancel()
	for _, server := range reference.Servers {
		config := Config{Endpoint: Endpoint{Host: server}, Timeout: 20 * time.Second}
		if err := replicationLabIdentity(ctx, config, reference.DomainDN, reference.DomainGUIDBinary); err != nil {
			t.Fatal("native DC/domain identity preflight failed")
		}
	}
	stage = "native-diagnostics"
	for _, server := range reference.Servers {
		config := Config{Endpoint: Endpoint{Host: server}, Timeout: 20 * time.Second}
		row := replicationLabServer{Server: server, Partners: []replicationLabPartner{}, Failures: []replicationLabFailure{}, Queue: []replicationLabOperation{}, Errors: map[string]string{}}
		partners, partnerErr := ReadReplicationPartners(ctx, config, ReplicationPartnerQuery{Direction: ReplicationBoth})
		if partnerErr != nil {
			row.Errors["partners"] = partnerErr.Error()
		}
		if partnerErr != nil || !partners.Complete || len(partners.Servers) != 1 {
			t.Error("native partner query incomplete")
		}
		if len(partners.Servers) == 1 {
			row.Partners = replicationLabPartners(partners.Servers[0].Partners)
		}
		failures, failureErr := ReadReplicationFailures(ctx, config, ReplicationFailureQuery{})
		if failureErr != nil {
			row.Errors["failures"] = failureErr.Error()
		}
		if failureErr != nil || !failures.Complete || len(failures.Servers) != 1 {
			t.Error("native failure query incomplete")
		}
		if len(failures.Servers) == 1 {
			row.Failures = replicationLabFailures(failures.Servers[0].Failures)
		}
		queue, queueErr := ReadReplicationQueue(ctx, config, ReplicationQueueQuery{})
		if queueErr != nil {
			row.Errors["queue"] = queueErr.Error()
		}
		if queueErr != nil || !queue.Complete || len(queue.Servers) != 1 {
			t.Error("native queue query incomplete")
		}
		if len(queue.Servers) == 1 {
			row.Queue = replicationLabQueue(queue.Servers[0].Operations)
			row.QueueStarted = replicationLabNumber(queue.Servers[0].CurrentOperationStarted.Ticks)
		}
		artifact.Records = append(artifact.Records, row)
	}
}

func replicationLabIdentity(ctx context.Context, config Config, domainDN, wantGUID string) (err error) {
	client, err := Dial(ctx, config)
	if err != nil {
		return err
	}
	defer func() { err = errors.Join(err, client.Close()) }()
	root, err := client.RootDSE(ctx, RootDSEOptions{})
	if err != nil {
		return err
	}
	if root.Capabilities().Type != DirectoryADDS || root.DNSHostName == nil || !strings.EqualFold(*root.DNSHostName, config.Endpoint.Host) || root.DefaultNamingContext == nil || !strings.EqualFold(*root.DefaultNamingContext, domainDN) {
		return ErrInvalidResult
	}
	result, err := client.Search(ctx, SearchOptions{Base: domainDN, Scope: ScopeBase, Filter: "(objectClass=domainDNS)", Properties: []string{"objectGUID"}})
	if err != nil {
		return err
	}
	if !result.Complete || len(result.Objects) != 1 {
		return ErrIncompleteResult
	}
	values, state := result.Objects[0].Attribute("objectGUID")
	if state != AttributePresent || len(values) != 1 || len(values[0]) != 16 || !strings.EqualFold(hex.EncodeToString(values[0]), wantGUID) {
		return fmt.Errorf("%w: domain GUID mismatch", ErrInvalidResult)
	}
	return nil
}
