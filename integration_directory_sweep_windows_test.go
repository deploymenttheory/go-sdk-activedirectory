//go:build windows && (amd64 || arm64)

package activedirectory

import (
	"context"
	"encoding/json"
	"fmt"
	"os"
	"runtime"
	"strings"
	"testing"
	"time"
)

// sweepTarget is one operation's read, reduced to the shape every paged read in
// this SDK shares: SearchOptions in, a SearchResult observation out. Adding an
// operation to the endpoint-and-partition sweep is a table row, not a test.
type sweepTarget struct {
	cmdlet string
	// domainScoped separates the two base families this SDK actually has.
	// A domain-scoped read defaults to the default naming context and accepts
	// any base the caller chooses inside it. A container-scoped read pins its
	// own container in the configuration partition and refuses a base outside
	// it, so an explicit domain base is not applicable and a mismatched base is
	// refused by the SDK rather than by the directory. Both are legitimate
	// refusals of a naming context the operation does not serve.
	domainScoped bool
	read         func(context.Context, *Client, SearchOptions) (SearchResult, error)
}

func endpointSweepTargets() []sweepTarget {
	return []sweepTarget{
		{"Get-ADObject", true, func(ctx context.Context, c *Client, o SearchOptions) (SearchResult, error) {
			return c.Search(ctx, o)
		}},
		{"Get-ADUser", true, func(ctx context.Context, c *Client, o SearchOptions) (SearchResult, error) {
			r, err := c.Users(ctx, o)
			return r.Observation, err
		}},
		{"Get-ADComputer", true, func(ctx context.Context, c *Client, o SearchOptions) (SearchResult, error) {
			r, err := c.Computers(ctx, o)
			return r.Observation, err
		}},
		{"Get-ADGroup", true, func(ctx context.Context, c *Client, o SearchOptions) (SearchResult, error) {
			r, err := c.Groups(ctx, o)
			return r.Observation, err
		}},
		{"Get-ADOrganizationalUnit", true, func(ctx context.Context, c *Client, o SearchOptions) (SearchResult, error) {
			r, err := c.OrganizationalUnits(ctx, o)
			return r.Observation, err
		}},
		{"Get-ADServiceAccount", true, func(ctx context.Context, c *Client, o SearchOptions) (SearchResult, error) {
			r, err := c.ServiceAccounts(ctx, o)
			return r.Observation, err
		}},
		{"Get-ADClaimType", false, func(ctx context.Context, c *Client, o SearchOptions) (SearchResult, error) {
			r, err := c.ClaimTypes(ctx, o)
			return r.Observation, err
		}},
		{"Get-ADClaimTransformPolicy", false, func(ctx context.Context, c *Client, o SearchOptions) (SearchResult, error) {
			r, err := c.ClaimTransformPolicies(ctx, o)
			return r.Observation, err
		}},
		{"Get-ADResourceProperty", false, func(ctx context.Context, c *Client, o SearchOptions) (SearchResult, error) {
			r, err := c.ResourceProperties(ctx, o)
			return r.Observation, err
		}},
		{"Get-ADResourcePropertyList", false, func(ctx context.Context, c *Client, o SearchOptions) (SearchResult, error) {
			r, err := c.ResourcePropertyLists(ctx, o)
			return r.Observation, err
		}},
		{"Get-ADResourcePropertyValueType", false, func(ctx context.Context, c *Client, o SearchOptions) (SearchResult, error) {
			r, err := c.ResourceValueTypes(ctx, o)
			return r.Observation, err
		}},
		{"Get-ADAuthenticationPolicy", false, func(ctx context.Context, c *Client, o SearchOptions) (SearchResult, error) {
			r, err := c.AuthenticationPolicies(ctx, o)
			return r.Observation, err
		}},
		{"Get-ADReplicationConnection", false, func(ctx context.Context, c *Client, o SearchOptions) (SearchResult, error) {
			r, err := c.ReplicationConnections(ctx, o)
			return r.Observation, err
		}},
	}
}

// sweepObservation is one operation's endpoint-and-partition result. Each field
// is a distinct observation rather than an aggregate, so a reader can see which
// half of the scenario a failure came from, and every read carries the reason it
// did not complete.
type sweepObservation struct {
	Cmdlet                 string `json:"cmdlet"`
	DomainScoped           bool   `json:"domain_scoped"`
	PrimaryDefaultRead     bool   `json:"primary_default_read"`
	PrimaryDetail          string `json:"primary_detail,omitempty"`
	SecondaryDefaultRead   bool   `json:"secondary_default_read"`
	SecondaryDetail        string `json:"secondary_detail,omitempty"`
	ExplicitBaseRead       *bool  `json:"explicit_base_read"`
	ExplicitDetail         string `json:"explicit_detail,omitempty"`
	MismatchedBaseRefused  bool   `json:"mismatched_base_refused"`
	MismatchedBaseNoObject bool   `json:"mismatched_base_returned_nothing"`
	RefusalDetail          string `json:"refusal_detail,omitempty"`
	AllocationsRemaining   int    `json:"native_allocations_remaining"`
	Passed                 bool   `json:"passed"`
}

// sweepDetail reports why a read did not complete, distinguishing an error from
// a search the server simply did not finish. It records only the error's own
// text, which the SDK already redacts.
func sweepDetail(err error, result SearchResult) string {
	switch {
	case err != nil:
		return err.Error()
	case !result.Complete && result.LimitReached:
		return "incomplete: caller limit reached"
	case !result.Complete:
		return "incomplete: server did not end the search"
	}
	return ""
}

func sweepAllocations(c searchNativeCounts) int {
	return c.messages + c.controls + c.controlSets + c.cookies + c.values + c.names + c.cursors
}

func sweepStatus(complete bool, err error) string {
	switch {
	case err != nil:
		return "error(" + err.Error() + ")"
	case !complete:
		return "incomplete"
	}
	return "complete"
}

// The outer harness supplies these endpoints only inside an owned run. This
// test never starts PowerShell, mutates the directory, or operates a VM; every
// call is a paged read. Ordinary go test invocations skip it.
//
// It qualifies the endpoint-and-partition scenario across every operation in
// the table, observing both halves the coverage contract requires: the
// documented default and an explicit endpoint honoured, against a naming
// context the operation does not serve and an unavailable endpoint, neither of
// which may be silently replaced.
//
// Each operation is observed on its own freshly dialled session. That is how a
// caller scopes a client, and it is the shape that qualified
// Get-ADDomain/endpoint-and-partition. A long-lived session is recorded
// separately by longLivedSessionProbe rather than designed around silently: an
// earlier run of this sweep saw every read on long-lived sessions refused as
// closed, after that session's own first read had succeeded.
func TestDirectoryEndpointSweepLab(t *testing.T) {
	primary := os.Getenv("ADSDK_SWEEP_PRIMARY")
	if primary == "" {
		t.Skip("requires the opt-in isolated directory sweep harness")
	}
	secondary := os.Getenv("ADSDK_SWEEP_SECONDARY")
	resultPath := os.Getenv("ADSDK_SWEEP_RESULT")
	runID := os.Getenv("ADSDK_SWEEP_RUN_ID")
	if secondary == "" || resultPath == "" || runID == "" {
		t.Fatal("two distinct endpoints, a run identity and a fresh result path are required")
	}
	if strings.EqualFold(primary, secondary) {
		t.Fatal("the two endpoints must be distinct controllers")
	}
	const absentBase = "DC=absent,DC=invalid"
	artifact := struct {
		SchemaVersion       int                `json:"schema_version"`
		Scope               string             `json:"scope"`
		RunID               string             `json:"run_id"`
		Primary             string             `json:"primary_endpoint"`
		Secondary           string             `json:"secondary_endpoint"`
		AbsentBase          string             `json:"absent_base"`
		RuntimeOS           string             `json:"runtime_os"`
		RuntimeArchitecture string             `json:"runtime_architecture"`
		Started             time.Time          `json:"started"`
		Finished            time.Time          `json:"finished"`
		Passed              bool               `json:"passed"`
		FullTicketComplete  bool               `json:"full_ticket_complete"`
		FailureStage        string             `json:"failure_stage,omitempty"`
		PrimaryController   string             `json:"primary_controller_dn"`
		SecondaryController string             `json:"secondary_controller_dn"`
		EndpointNotReplaced bool               `json:"explicit_endpoint_not_replaced"`
		UnavailableRefused  bool               `json:"unavailable_endpoint_refused"`
		UnavailableDetail   string             `json:"unavailable_endpoint_detail,omitempty"`
		LongLivedProbe      string             `json:"long_lived_session_probe,omitempty"`
		Operations          []sweepObservation `json:"operations"`
	}{
		SchemaVersion: 1, Scope: "directory-endpoint-and-partition-sweep", RunID: runID,
		Primary: primary, Secondary: secondary, AbsentBase: absentBase,
		RuntimeOS: runtime.GOOS, RuntimeArchitecture: runtime.GOARCH,
		Started: time.Now().UTC(), Operations: []sweepObservation{},
	}
	stage := "start"
	// FailureStage records where the run first went wrong. Reading the
	// then-current stage at defer time names the last stage reached instead,
	// which points a reader at the wrong place.
	failedAt := ""
	fail := func(format string, args ...any) {
		if failedAt == "" {
			failedAt = stage
		}
		t.Errorf(format, args...)
	}
	defer func() {
		artifact.Finished = time.Now().UTC()
		artifact.Passed = !t.Failed()
		if t.Failed() {
			artifact.FailureStage = failedAt
		}
		data, err := json.MarshalIndent(artifact, "", "  ")
		if err != nil {
			t.Error("cannot encode sweep artifact")
			return
		}
		file, err := os.OpenFile(resultPath, os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0600)
		if err != nil {
			t.Error("cannot create fresh sweep artifact")
			return
		}
		_, writeErr := file.Write(append(data, '\n'))
		if closeErr := file.Close(); writeErr != nil || closeErr != nil {
			t.Error("cannot finish sweep artifact")
		}
	}()

	ctx, cancel := context.WithTimeout(context.Background(), 15*time.Minute)
	defer cancel()

	// withSession dials one endpoint, runs the observations against it, and
	// closes it. The allocation total is returned so a leak is attributed to
	// the session that caused it.
	withSession := func(host string, fn func(*Client)) (int, error) {
		client, err := Dial(ctx, Config{Endpoint: Endpoint{Host: host, Port: 389}, Timeout: 30 * time.Second})
		if err != nil {
			return 0, err
		}
		var counts searchNativeCounts
		client.session.(*ldapSession).api = countedSearchAPI(&counts)
		if fn != nil {
			fn(client)
		}
		closeErr := client.Close()
		return sweepAllocations(counts), closeErr
	}

	// Which controller actually answered each endpoint. Two explicit endpoints
	// answered by one controller would mean the DC locator replaced a target
	// the caller named, which LDAP_OPT_AREC_EXCLUSIVE exists to prevent.
	stage = "endpoint-identity"
	defaultNC := ""
	connected := func(host string) string {
		dn := ""
		leaked, err := withSession(host, func(c *Client) {
			result, readErr := c.Directory().DomainController(ctx, DomainControllerOptions{})
			if readErr != nil || !result.Observation.Complete {
				fail("%s did not report its connected controller: %v", host, readErr)
				return
			}
			dn = result.Controller.Server.DistinguishedName
			if root := result.Observation.RootDSE; root.DefaultNamingContext != nil && defaultNC == "" {
				defaultNC = *root.DefaultNamingContext
			}
		})
		if err != nil {
			fail("%s session failed: %v", host, err)
		}
		if leaked != 0 {
			fail("%s left %d native allocations after its controller read", host, leaked)
		}
		return dn
	}
	artifact.PrimaryController = connected(primary)
	artifact.SecondaryController = connected(secondary)
	artifact.EndpointNotReplaced = artifact.PrimaryController != "" &&
		artifact.SecondaryController != "" &&
		!strings.EqualFold(artifact.PrimaryController, artifact.SecondaryController)
	if !artifact.EndpointNotReplaced {
		fail("two explicit endpoints were answered by the same controller")
	}
	if defaultNC == "" {
		fail("no connection reported a default naming context")
	}

	stage = "operation-sweep"
	for _, target := range endpointSweepTargets() {
		o := sweepObservation{Cmdlet: target.cmdlet, DomainScoped: target.domainScoped}

		// Documented default, explicit base and a refused naming context, all
		// on one session for this operation.
		//
		// No ResultLimit is set. A caller's limit stops retrieval with
		// LimitReached and leaves Complete false with a nil error, so bounding
		// the result count here would report a busy container as an incomplete
		// read. PageSize still exercises paging; Complete then means the server
		// ended the search.
		leaked, err := withSession(primary, func(c *Client) {
			result, readErr := target.read(ctx, c, SearchOptions{PageSize: 16})
			o.PrimaryDefaultRead = readErr == nil && result.Complete
			o.PrimaryDetail = sweepDetail(readErr, result)

			if target.domainScoped && defaultNC != "" {
				result, readErr = target.read(ctx, c, SearchOptions{Base: defaultNC, PageSize: 16})
				explicit := readErr == nil && result.Complete
				o.ExplicitBaseRead = &explicit
				o.ExplicitDetail = sweepDetail(readErr, result)
			}

			// The failure half: a naming context this operation does not serve
			// must be refused, and must not be answered from the operation's
			// own container instead.
			result, readErr = target.read(ctx, c, SearchOptions{Base: absentBase, PageSize: 16})
			o.MismatchedBaseRefused = readErr != nil || !result.Complete
			o.MismatchedBaseNoObject = len(result.Objects) == 0
			o.RefusalDetail = sweepDetail(readErr, result)
		})
		if err != nil {
			o.PrimaryDetail = "session: " + err.Error()
		}
		o.AllocationsRemaining = leaked

		// The same operation's documented default on the other endpoint.
		if _, err := withSession(secondary, func(c *Client) {
			result, readErr := target.read(ctx, c, SearchOptions{PageSize: 16})
			o.SecondaryDefaultRead = readErr == nil && result.Complete
			o.SecondaryDetail = sweepDetail(readErr, result)
		}); err != nil {
			o.SecondaryDetail = "session: " + err.Error()
		}

		o.Passed = o.PrimaryDefaultRead && o.SecondaryDefaultRead &&
			(o.ExplicitBaseRead == nil || *o.ExplicitBaseRead) &&
			o.MismatchedBaseRefused && o.MismatchedBaseNoObject &&
			o.AllocationsRemaining == 0
		if !o.Passed {
			fail("%s: endpoint and partition observation incomplete: %+v", target.cmdlet, o)
		}
		artifact.Operations = append(artifact.Operations, o)
	}

	// An unavailable endpoint must fail rather than resolve to a reachable one.
	stage = "unavailable-endpoint"
	unreachable, err := Dial(ctx, Config{Endpoint: Endpoint{Host: primary, Port: 3899}, Timeout: 10 * time.Second})
	if err == nil {
		_ = unreachable.Close()
		fail("a closed port produced a usable session")
	} else {
		artifact.UnavailableDetail = err.Error()
	}
	artifact.UnavailableRefused = err != nil

	// Observed, not asserted. Nothing in the SDK cancels a client lifetime
	// except Close, which TestClientLifetimeSurvivesCompletedReads covers, so
	// this records what the lab does without failing the qualification on it.
	stage = "long-lived-session-probe"
	artifact.LongLivedProbe = longLivedSessionProbe(ctx, primary)

	if !t.Failed() {
		stage = "complete"
	}
	t.Logf("endpoint and partition sweep over %d operations on %s and %s; full ticket qualification remains incomplete",
		len(artifact.Operations), primary, secondary)
}

// longLivedSessionProbe holds one session open across several reads and reports
// what happened, in order. It asserts nothing.
func longLivedSessionProbe(ctx context.Context, host string) string {
	client, err := Dial(ctx, Config{Endpoint: Endpoint{Host: host, Port: 389}, Timeout: 30 * time.Second})
	if err != nil {
		return "dial=error(" + err.Error() + ")"
	}
	defer func() { _ = client.Close() }()
	var counts searchNativeCounts
	client.session.(*ldapSession).api = countedSearchAPI(&counts)
	report := make([]string, 0, 5)
	result, readErr := client.Directory().DomainController(ctx, DomainControllerOptions{})
	report = append(report, "controller-read="+sweepStatus(result.Observation.Complete, readErr))
	for i := range 3 {
		search, searchErr := client.Search(ctx, SearchOptions{Base: "", PageSize: 16})
		report = append(report, fmt.Sprintf("search%d=%s", i+1, sweepStatus(search.Complete, searchErr)))
	}
	report = append(report, fmt.Sprintf("allocations=%d", sweepAllocations(counts)))
	return strings.Join(report, "; ")
}
