//go:build windows && (amd64 || arm64)

package activedirectory

import (
	"context"
	"encoding/json"
	"os"
	"runtime"
	"strings"
	"testing"
	"time"
)

// endpointCheck is one named observation. Both the satisfied and the refused
// halves of the scenario are recorded, because the coverage contract requires
// passing evidence for a success and a failure identifier.
type endpointCheck struct {
	Name     string `json:"name"`
	Passed   bool   `json:"passed"`
	Detail   string `json:"detail,omitempty"`
	Observed string `json:"observed,omitempty"`
}

// The outer reference harness supplies these endpoints only inside an owned
// run. This test never starts PowerShell, mutates the directory, or operates a
// VM. Ordinary go test invocations skip it.
//
// It qualifies Get-ADDomain's endpoint-and-partition scenario: that an explicit
// server is honoured rather than silently replaced by the DC locator, that an
// explicit partition is read as requested, and that an absent partition and an
// unavailable endpoint are refused with an actionable error instead of being
// answered from an arbitrary directory.
func TestDirectoryEndpointAndPartitionLab(t *testing.T) {
	primary := os.Getenv("ADSDK_DIRECTORY_ENDPOINT_PRIMARY")
	if primary == "" {
		t.Skip("requires the opt-in isolated directory endpoint harness")
	}
	secondary := os.Getenv("ADSDK_DIRECTORY_ENDPOINT_SECONDARY")
	resultPath := os.Getenv("ADSDK_DIRECTORY_ENDPOINT_RESULT")
	runID := os.Getenv("ADSDK_DIRECTORY_ENDPOINT_RUN_ID")
	if secondary == "" || resultPath == "" || runID == "" {
		t.Fatal("two distinct endpoints, a run identity and a fresh result path are required")
	}
	if strings.EqualFold(primary, secondary) {
		t.Fatal("the two endpoints must be distinct controllers")
	}
	artifact := struct {
		SchemaVersion        int             `json:"schema_version"`
		Scope                string          `json:"scope"`
		RunID                string          `json:"run_id"`
		Primary              string          `json:"primary_endpoint"`
		Secondary            string          `json:"secondary_endpoint"`
		RuntimeOS            string          `json:"runtime_os"`
		RuntimeArchitecture  string          `json:"runtime_architecture"`
		Started              time.Time       `json:"started"`
		Finished             time.Time       `json:"finished"`
		Passed               bool            `json:"passed"`
		FullTicketComplete   bool            `json:"full_ticket_complete"`
		FailureStage         string          `json:"failure_stage,omitempty"`
		Checks               []endpointCheck `json:"checks"`
		AllocationsRemaining map[string]int  `json:"native_allocations_remaining"`
	}{
		SchemaVersion: 1, Scope: "directory-endpoint-and-partition", RunID: runID,
		Primary: primary, Secondary: secondary, RuntimeOS: runtime.GOOS,
		RuntimeArchitecture: runtime.GOARCH, Started: time.Now().UTC(),
		Checks: []endpointCheck{},
	}
	stage := "start"
	record := func(name string, passed bool, detail, observed string) {
		// detail states the condition that would have failed the check, so it
		// is only meaningful when the check did fail. Recording it on a passing
		// check would make the artifact read as if the fault had occurred.
		if passed {
			detail = ""
		}
		artifact.Checks = append(artifact.Checks, endpointCheck{name, passed, detail, observed})
		if !passed {
			t.Errorf("%s: %s", name, detail)
		}
	}
	defer func() {
		artifact.Finished = time.Now().UTC()
		artifact.Passed = !t.Failed()
		if t.Failed() {
			artifact.FailureStage = stage
		}
		data, err := json.MarshalIndent(artifact, "", "  ")
		if err != nil {
			t.Error("cannot encode endpoint artifact")
			return
		}
		file, err := os.OpenFile(resultPath, os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0600)
		if err != nil {
			t.Error("cannot create fresh endpoint artifact")
			return
		}
		_, writeErr := file.Write(append(data, '\n'))
		if closeErr := file.Close(); writeErr != nil || closeErr != nil {
			t.Error("cannot finish endpoint artifact")
		}
	}()

	ctx, cancel := context.WithTimeout(context.Background(), 6*time.Minute)
	defer cancel()

	// connectedServer dials one endpoint and reports which controller actually
	// answered, so a silent substitution cannot pass as a success.
	connectedServer := func(host string) (string, int, error) {
		client, err := Dial(ctx, Config{Endpoint: Endpoint{Host: host, Port: 389}, Timeout: 30 * time.Second})
		if err != nil {
			return "", 0, err
		}
		var counts searchNativeCounts
		client.session.(*ldapSession).api = countedSearchAPI(&counts)
		connected, err := client.Directory().DomainController(ctx, DomainControllerOptions{})
		closeErr := client.Close()
		if err == nil && closeErr == nil && !connected.Observation.Complete {
			err = ErrInvalidResult
		}
		if closeErr != nil {
			err = closeErr
		}
		return connected.Controller.Server.DistinguishedName, countsTotal(counts), err
	}

	stage = "explicit-endpoint-selection"
	primaryDN, primaryLeaked, err := connectedServer(primary)
	record("primary-endpoint-answers", err == nil && primaryDN != "",
		describeEndpointFailure(err), primaryDN)
	record("primary-allocations-balanced", primaryLeaked == 0,
		"native allocations remained after a satisfied read", "")

	secondaryDN, secondaryLeaked, err := connectedServer(secondary)
	record("secondary-endpoint-answers", err == nil && secondaryDN != "",
		describeEndpointFailure(err), secondaryDN)
	record("secondary-allocations-balanced", secondaryLeaked == 0,
		"native allocations remained after a satisfied read", "")

	// The decisive observation for this scenario: two explicit endpoints must
	// be answered by two different controllers. One DN for both would mean the
	// requested target was silently replaced.
	record("explicit-endpoint-not-replaced",
		primaryDN != "" && secondaryDN != "" && !strings.EqualFold(primaryDN, secondaryDN),
		"both endpoints were answered by the same controller", primaryDN+" | "+secondaryDN)

	stage = "partition-selection"
	client, err := Dial(ctx, Config{Endpoint: Endpoint{Host: primary, Port: 389}, Timeout: 30 * time.Second})
	if err != nil {
		t.Fatal("native directory dial failed")
	}
	var counts searchNativeCounts
	client.session.(*ldapSession).api = countedSearchAPI(&counts)
	directory := client.Directory()

	deflt, err := directory.Domain(ctx, DomainOptions{})
	record("default-partition-read", err == nil && deflt.Observation.Complete,
		describeEndpointFailure(err), deflt.Raw.DistinguishedName)

	if deflt.Raw.DistinguishedName != "" {
		explicit, err := directory.Domain(ctx, DomainOptions{DistinguishedName: deflt.Raw.DistinguishedName})
		record("explicit-partition-read",
			err == nil && explicit.Observation.Complete &&
				strings.EqualFold(explicit.Raw.DistinguishedName, deflt.Raw.DistinguishedName),
			describeEndpointFailure(err), explicit.Raw.DistinguishedName)
	}

	// The failure half of the scenario. An absent partition must not be
	// answered from the default naming context.
	absent, err := directory.Domain(ctx, DomainOptions{DistinguishedName: "DC=absent,DC=invalid"})
	refused := err != nil || !absent.Observation.Complete
	record("absent-partition-refused", refused,
		"an absent partition was reported as a complete observation", describeEndpointFailure(err))
	record("absent-partition-not-substituted",
		absent.Raw.DistinguishedName == "" ||
			!strings.EqualFold(absent.Raw.DistinguishedName, deflt.Raw.DistinguishedName),
		"an absent partition was answered with the default domain", absent.Raw.DistinguishedName)

	closeErr := client.Close()
	record("client-close", closeErr == nil, describeEndpointFailure(closeErr), "")
	record("partition-allocations-balanced", countsTotal(counts) == 0,
		"native allocations remained after satisfied and refused partition reads", "")
	artifact.AllocationsRemaining = map[string]int{
		"messages": counts.messages, "request_controls": counts.controls,
		"response_controls": counts.controlSets, "cookies": counts.cookies,
		"values": counts.values, "names": counts.names, "attribute_cursors": counts.cursors,
	}

	// An unavailable endpoint must fail rather than be resolved to a reachable
	// controller. LDAP_OPT_AREC_EXCLUSIVE is set precisely to stop the DC
	// locator answering for an endpoint the caller did not ask for.
	stage = "unavailable-endpoint"
	unreachable, err := Dial(ctx, Config{Endpoint: Endpoint{Host: primary, Port: 3899}, Timeout: 10 * time.Second})
	if err == nil {
		_ = unreachable.Close()
	}
	record("unavailable-endpoint-refused", err != nil,
		"a closed port produced a usable session", describeEndpointFailure(err))

	if !t.Failed() {
		stage = "complete"
	}
	t.Logf("endpoint and partition qualification on %s and %s; full ticket qualification remains incomplete", primary, secondary)
}

// countsTotal collapses the native allocation counters so a leak on any one of
// them fails the observation.
func countsTotal(c searchNativeCounts) int {
	return c.messages + c.controls + c.controlSets + c.cookies + c.values + c.names + c.cursors
}

// describeEndpointFailure never reproduces directory content or credentials; it
// records only the error's own text, which the SDK already redacts.
func describeEndpointFailure(err error) string {
	if err == nil {
		return ""
	}
	return err.Error()
}
