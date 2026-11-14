//go:build windows && (amd64 || arm64)

package activedirectory

import (
	"context"
	"encoding/json"
	"errors"
	"os"
	"runtime"
	"strings"
	"testing"
	"time"
)

// queryObservation is one operation's query-scope-paging-and-filters result.
// Each field is a separate observation so a reader can see which part of the
// scenario a failure came from.
type queryObservation struct {
	Cmdlet string `json:"cmdlet"`
	// TypedObjects and StringObjects are the counts each query dialect
	// returned for the same question. They must agree.
	TypedRead          bool   `json:"typed_filter_read"`
	TypedObjects       int    `json:"typed_filter_objects"`
	StringRead         bool   `json:"string_filter_read"`
	StringObjects      int    `json:"string_filter_objects"`
	DialectsAgree      bool   `json:"query_dialects_agree"`
	EmptyResult        bool   `json:"empty_result_completes"`
	PagedRead          bool   `json:"paged_read_completes"`
	PagedObjects       int    `json:"paged_read_objects"`
	PagesNotTruncated  bool   `json:"pages_not_truncated"`
	LimitHonoured      bool   `json:"caller_limit_honoured"`
	LimitObjects       int    `json:"caller_limit_objects"`
	CancelRefused      bool   `json:"cancelled_read_retains_error"`
	CancelDetail       string `json:"cancelled_read_detail,omitempty"`
	LiteralNotInjected bool   `json:"filter_literal_not_injected"`
	LiteralDetail      string `json:"filter_literal_detail,omitempty"`
	// Observable records whether the lab held enough objects under this
	// operation's container to observe paging and a caller limit at all. An
	// operation with fewer than two is reported and excluded rather than
	// passed on checks that cannot fail.
	Observable      bool   `json:"observable"`
	BaseObjects     int    `json:"base_scope_objects"`
	OneLevelObjects int    `json:"one_level_scope_objects"`
	ScopesOrdered   bool   `json:"scopes_widen_monotonically"`
	Allocations     int    `json:"native_allocations_remaining"`
	Detail          string `json:"detail,omitempty"`
	Passed          bool   `json:"passed"`
}

// qualifies keeps the whole scenario in one testable place. Every observation
// is load-bearing; an aggregation that silently became permissive would make a
// future run report success regardless of what the directory did.
func (o queryObservation) qualifies() bool {
	return o.Observable && o.TypedRead && o.StringRead && o.DialectsAgree &&
		o.EmptyResult && o.PagedRead && o.PagesNotTruncated && o.LimitHonoured &&
		o.CancelRefused && o.LiteralNotInjected && o.ScopesOrdered &&
		o.Allocations == 0
}

// The outer harness supplies the endpoint only inside an owned run. This test
// never starts PowerShell, mutates the directory, or operates a VM; every call
// is a paged read. Ordinary go test invocations skip it.
//
// It qualifies query-scope-paging-and-filters across the same operation table
// the endpoint sweep uses. Both halves the coverage contract needs are
// observed: the supported query dialects, paging and an empty result against a
// caller limit that stops retrieval, a cancelled read, and a literal that must
// not be able to inject a filter.
func TestDirectoryQuerySweepLab(t *testing.T) {
	endpoint := os.Getenv("ADSDK_QUERY_ENDPOINT")
	if endpoint == "" {
		t.Skip("requires the opt-in isolated directory query harness")
	}
	resultPath := os.Getenv("ADSDK_QUERY_RESULT")
	runID := os.Getenv("ADSDK_QUERY_RUN_ID")
	if resultPath == "" || runID == "" {
		t.Fatal("an endpoint, a run identity and a fresh result path are required")
	}
	artifact := struct {
		SchemaVersion       int                `json:"schema_version"`
		Scope               string             `json:"scope"`
		RunID               string             `json:"run_id"`
		Endpoint            string             `json:"endpoint"`
		RuntimeOS           string             `json:"runtime_os"`
		RuntimeArchitecture string             `json:"runtime_architecture"`
		Started             time.Time          `json:"started"`
		Finished            time.Time          `json:"finished"`
		Passed              bool               `json:"passed"`
		FullTicketComplete  bool               `json:"full_ticket_complete"`
		FailureStage        string             `json:"failure_stage,omitempty"`
		Operations          []queryObservation `json:"operations"`
	}{
		SchemaVersion: 1, Scope: "directory-query-scope-paging-and-filters", RunID: runID,
		Endpoint: endpoint, RuntimeOS: runtime.GOOS, RuntimeArchitecture: runtime.GOARCH,
		Started: time.Now().UTC(), Operations: []queryObservation{},
	}
	stage := "start"
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
			t.Error("cannot encode query artifact")
			return
		}
		file, err := os.OpenFile(resultPath, os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0600)
		if err != nil {
			t.Error("cannot create fresh query artifact")
			return
		}
		_, writeErr := file.Write(append(data, '\n'))
		if closeErr := file.Close(); writeErr != nil || closeErr != nil {
			t.Error("cannot finish query artifact")
		}
	}()

	ctx, cancel := context.WithTimeout(context.Background(), 15*time.Minute)
	defer cancel()

	withSession := func(fn func(*Client)) (int, error) {
		client, err := Dial(ctx, Config{Endpoint: Endpoint{Host: endpoint, Port: 389}, Timeout: 30 * time.Second})
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

	stage = "default-naming-context"
	defaultNC := ""
	if _, err := withSession(func(c *Client) {
		root, readErr := c.RootDSE(ctx, RootDSEOptions{})
		if readErr != nil {
			fail("cannot read the default naming context: %v", readErr)
			return
		}
		if root.DefaultNamingContext != nil {
			defaultNC = *root.DefaultNamingContext
		}
	}); err != nil {
		t.Fatal("native dial failed")
	}
	if defaultNC == "" {
		t.Fatal("the connection did not report a default naming context")
	}

	stage = "operation-sweep"
	for _, target := range endpointSweepTargets() {
		o := queryObservation{Cmdlet: target.cmdlet}

		// A base that every read in the table can serve. The generic object
		// read has no documented default base and the domain root carries
		// subordinate naming contexts whose references are reported rather
		// than chased, so it reads the Users container as a subtree.
		// Scope is always explicit. The typed plural reads default an empty
		// base to the default naming context but never set Scope, so the
		// caller's zero value leaves it at ScopeBase and an unscoped call reads
		// only the partition head — no error, no objects. The container-scoped
		// reads set their own scope and ignore this.
		base := SearchOptions{PageSize: 256}
		if target.domainScoped {
			// A domain-scoped read is given the Users container as a subtree.
			// The domain root cannot be used: it holds three subordinate naming
			// contexts whose references this SDK reports rather than chases, so
			// a whole-domain subtree read is deliberately incomplete. The
			// container has no subordinate context beneath it.
			base = SearchOptions{Base: "CN=Users," + defaultNC, Scope: ScopeSubtree, PageSize: 256}
		}
		with := func(mutate func(*SearchOptions)) SearchOptions {
			options := base
			mutate(&options)
			return options
		}

		leaked, err := withSession(func(c *Client) {
			// Dialect one: a typed filter, built from values rather than text.
			typed, readErr := target.read(ctx, c, with(func(o *SearchOptions) {
				o.TypedFilter = FilterPresent("objectClass")
			}))
			o.TypedRead = readErr == nil && typed.Complete
			o.TypedObjects = len(typed.Objects)
			if readErr != nil {
				o.Detail = "typed: " + readErr.Error()
			}

			// Dialect two: the same question as an LDAP filter string. The two
			// dialects must answer identically.
			text, readErr := target.read(ctx, c, with(func(o *SearchOptions) {
				o.Filter = "(objectClass=*)"
			}))
			o.StringRead = readErr == nil && text.Complete
			o.StringObjects = len(text.Objects)
			o.DialectsAgree = o.TypedRead && o.StringRead && o.TypedObjects == o.StringObjects
			if readErr != nil {
				o.Detail += " string: " + readErr.Error()
			}

			// An empty result is a successful read, not a failure.
			empty, readErr := target.read(ctx, c, with(func(o *SearchOptions) {
				o.TypedFilter = FilterEqual("description", FilterText("no-object-carries-this-value-9f51cb95"))
			}))
			o.EmptyResult = readErr == nil && empty.Complete && len(empty.Objects) == 0

			// One object per page must reach the same total: pages are not
			// truncated and intermediate empty pages are followed.
			paged, readErr := target.read(ctx, c, with(func(o *SearchOptions) {
				o.TypedFilter, o.PageSize = FilterPresent("objectClass"), 1
			}))
			o.PagedRead = readErr == nil && paged.Complete
			o.PagedObjects = len(paged.Objects)
			o.PagesNotTruncated = o.PagedRead && o.TypedRead && o.PagedObjects == o.TypedObjects

			// A caller limit stops retrieval with LimitReached, Complete false
			// and a nil error. That is a satisfied bound, not an incomplete
			// read, and it must return exactly the requested count.
			limited, readErr := target.read(ctx, c, with(func(o *SearchOptions) {
				o.TypedFilter, o.PageSize, o.ResultLimit = FilterPresent("objectClass"), 16, 1
			}))
			o.LimitObjects = len(limited.Objects)
			o.LimitHonoured = readErr == nil && limited.LimitReached && !limited.Complete &&
				o.LimitObjects == 1
			if o.TypedObjects < 2 {
				// With fewer than two objects the server ends the search before
				// the bound is reached, so the limit cannot be observed here.
				o.LimitHonoured = readErr == nil && (limited.LimitReached || limited.Complete)
			}

			// A cancelled read must report the cancellation rather than return
			// a quietly short result. An already-cancelled context makes this
			// deterministic; mid-read cancellation would be a race.
			cancelled, stop := context.WithCancel(ctx)
			stop()
			refused, readErr := target.read(cancelled, c, with(func(o *SearchOptions) {
				o.TypedFilter = FilterPresent("objectClass")
			}))
			o.CancelRefused = readErr != nil && !refused.Complete
			if readErr != nil {
				o.CancelDetail = readErr.Error()
				o.CancelRefused = o.CancelRefused &&
					(errors.Is(readErr, context.Canceled) || strings.Contains(readErr.Error(), "cancel"))
			}

			// Scope is part of this scenario where it is offered. Widening it
			// must never return fewer objects.
			scopeProbes := []struct {
				scope SearchScope
				into  *int
			}{{ScopeBase, &o.BaseObjects}, {ScopeOneLevel, &o.OneLevelObjects}}
			if !target.domainScoped {
				// A container-scoped read pins its own scope, so there is no
				// caller scope to vary and the ordering holds trivially.
				scopeProbes = nil
				o.BaseObjects, o.OneLevelObjects = 0, 0
			}
			for _, probe := range scopeProbes {
				scoped, scopeErr := target.read(ctx, c, with(func(o *SearchOptions) {
					o.TypedFilter, o.Scope = FilterPresent("objectClass"), probe.scope
				}))
				if scopeErr == nil {
					*probe.into = len(scoped.Objects)
				}
			}
			o.ScopesOrdered = o.BaseObjects <= o.OneLevelObjects &&
				o.OneLevelObjects <= o.TypedObjects

			// A literal carrying filter syntax must be escaped, not parsed. If
			// it were injected the read would either error as malformed or
			// match everything; escaped, it simply matches nothing.
			injected, readErr := target.read(ctx, c, with(func(o *SearchOptions) {
				o.TypedFilter = FilterEqual("description", FilterText("x)(objectClass=*"))
			}))
			o.LiteralNotInjected = readErr == nil && injected.Complete && len(injected.Objects) == 0
			if readErr != nil {
				o.LiteralDetail = readErr.Error()
			}
		})
		if err != nil {
			o.Detail += " session: " + err.Error()
		}
		o.Allocations = leaked
		// Two objects are the minimum that lets one-per-page paging and a
		// limit of one be distinguished from a complete read.
		o.Observable = o.TypedObjects >= 2
		o.Passed = o.qualifies()
		switch {
		case !o.Observable:
			// Not a failure of the SDK: the lab holds too little under this
			// operation's container to observe paging or a limit. Recorded so
			// the artifact cannot be read as evidence for it.
			t.Logf("%s: only %d object(s) available; paging and limit not observable",
				target.cmdlet, o.TypedObjects)
		case !o.Passed:
			fail("%s: query observation incomplete: %+v", target.cmdlet, o)
		}
		artifact.Operations = append(artifact.Operations, o)
	}

	if !t.Failed() {
		stage = "complete"
	}
	t.Logf("query scope, paging and filter sweep over %d operations on %s; full ticket qualification remains incomplete",
		len(artifact.Operations), endpoint)
}
