//go:build windows && (amd64 || arm64)

package acceptance

import (
	"context"
	"encoding/json"
	"fmt"
	"os"
	"runtime"
	"strings"
	"testing"
	"time"

	adengine "github.com/deploymenttheory/go-sdk-activedirectory/activedirectory/internal/engine"
	admodel "github.com/deploymenttheory/go-sdk-activedirectory/activedirectory/internal/model"
	adservice_authentication_policies "github.com/deploymenttheory/go-sdk-activedirectory/activedirectory/services/authentication_policies"
	adservice_claims "github.com/deploymenttheory/go-sdk-activedirectory/activedirectory/services/claims"
	adservice_computers "github.com/deploymenttheory/go-sdk-activedirectory/activedirectory/services/computers"
	adservice_groups "github.com/deploymenttheory/go-sdk-activedirectory/activedirectory/services/groups"
	adservice_organizational_units "github.com/deploymenttheory/go-sdk-activedirectory/activedirectory/services/organizational_units"
	adservice_replication "github.com/deploymenttheory/go-sdk-activedirectory/activedirectory/services/replication"
	adservice_resource_properties "github.com/deploymenttheory/go-sdk-activedirectory/activedirectory/services/resource_properties"
	adservice_service_accounts "github.com/deploymenttheory/go-sdk-activedirectory/activedirectory/services/service_accounts"
	adservice_users "github.com/deploymenttheory/go-sdk-activedirectory/activedirectory/services/users"
)

// sweepTarget is one operation's read, reduced to the shape every paged read in
// this SDK shares: SearchOptions in, a SearchResult observation out. Adding an
// operation to the endpoint-and-partition sweep is a table row, not a test.
type InternalSweepTarget struct {
	InternalCmdlet string
	// domainScoped separates the two base families this SDK actually has.
	// A domain-scoped read defaults to the default naming context and accepts
	// any base the caller chooses inside it. A container-scoped read pins its
	// own container in the configuration partition and refuses a base outside
	// it, so an explicit domain base is not applicable and a mismatched base is
	// refused by the SDK rather than by the directory. Both are legitimate
	// refusals of a naming context the operation does not serve.
	InternalDomainScoped bool
	// suppliesOwnBase is false only for the generic object read. Every typed
	// read defaults an empty base to the default naming context and sets its
	// own subtree scope, but Client.Search takes the caller's options as given:
	// an empty base with the default base scope reads the RootDSE, which
	// returns one object and no paging control. The SDK then retires the
	// connection rather than reuse an uncertain server cursor, so that one
	// mistake also closes the session.
	//
	// Its base here is the domain's Users container rather than the domain
	// root. The root holds three subordinate naming contexts — configuration,
	// DomainDnsZones and ForestDnsZones — and a subtree read of it returns
	// references to them, which this SDK reports rather than chases because
	// LDAP_OPT_REFERRALS is off. That is correct and deliberate, and belongs to
	// referral handling rather than to endpoint and partition selection, so the
	// sweep reads a plain container with no subordinate context beneath it.
	InternalSuppliesOwnBase bool
	InternalRead            func(context.Context, *adengine.Client, admodel.SearchOptions) (admodel.SearchResult, error)
}

func InternalEndpointSweepTargets() []InternalSweepTarget {
	return []InternalSweepTarget{
		{
			"Get-ADObject",
			true,
			false,
			func(ctx context.Context, c *adengine.Client, o admodel.SearchOptions) (admodel.SearchResult, error) {
				return c.Search(ctx, o)
			},
		},
		{
			"Get-ADUser",
			true,
			true,
			func(ctx context.Context, c *adengine.Client, o admodel.SearchOptions) (admodel.SearchResult, error) {
				r, err := adservice_users.New(c).Users(ctx, o)
				return r.Observation, err
			},
		},
		{
			"Get-ADComputer",
			true,
			true,
			func(ctx context.Context, c *adengine.Client, o admodel.SearchOptions) (admodel.SearchResult, error) {
				r, err := adservice_computers.New(c).Computers(ctx, o)
				return r.Observation, err
			},
		},
		{
			"Get-ADGroup",
			true,
			true,
			func(ctx context.Context, c *adengine.Client, o admodel.SearchOptions) (admodel.SearchResult, error) {
				r, err := adservice_groups.New(c).Groups(ctx, o)
				return r.Observation, err
			},
		},
		{
			"Get-ADOrganizationalUnit",
			true,
			true,
			func(ctx context.Context, c *adengine.Client, o admodel.SearchOptions) (admodel.SearchResult, error) {
				r, err := adservice_organizational_units.New(c).OrganizationalUnits(ctx, o)
				return r.Observation, err
			},
		},
		{
			"Get-ADServiceAccount",
			true,
			true,
			func(ctx context.Context, c *adengine.Client, o admodel.SearchOptions) (admodel.SearchResult, error) {
				r, err := adservice_service_accounts.New(c).ServiceAccounts(ctx, o)
				return r.Observation, err
			},
		},
		{
			"Get-ADClaimType",
			false,
			true,
			func(ctx context.Context, c *adengine.Client, o admodel.SearchOptions) (admodel.SearchResult, error) {
				r, err := adservice_claims.New(c).ClaimTypes(ctx, o)
				return r.Observation, err
			},
		},
		{
			"Get-ADClaimTransformPolicy",
			false,
			true,
			func(ctx context.Context, c *adengine.Client, o admodel.SearchOptions) (admodel.SearchResult, error) {
				r, err := adservice_claims.New(c).ClaimTransformPolicies(ctx, o)
				return r.Observation, err
			},
		},
		{
			"Get-ADResourceProperty",
			false,
			true,
			func(ctx context.Context, c *adengine.Client, o admodel.SearchOptions) (admodel.SearchResult, error) {
				r, err := adservice_resource_properties.New(c).ResourceProperties(ctx, o)
				return r.Observation, err
			},
		},
		{
			"Get-ADResourcePropertyList",
			false,
			true,
			func(ctx context.Context, c *adengine.Client, o admodel.SearchOptions) (admodel.SearchResult, error) {
				r, err := adservice_resource_properties.New(c).ResourcePropertyLists(ctx, o)
				return r.Observation, err
			},
		},
		{
			"Get-ADResourcePropertyValueType",
			false,
			true,
			func(ctx context.Context, c *adengine.Client, o admodel.SearchOptions) (admodel.SearchResult, error) {
				r, err := adservice_resource_properties.New(c).ResourceValueTypes(ctx, o)
				return r.Observation, err
			},
		},
		{
			"Get-ADAuthenticationPolicy",
			false,
			true,
			func(ctx context.Context, c *adengine.Client, o admodel.SearchOptions) (admodel.SearchResult, error) {
				r, err := adservice_authentication_policies.New(c).AuthenticationPolicies(ctx, o)
				return r.Observation, err
			},
		},
		{
			"Get-ADReplicationConnection",
			false,
			true,
			func(ctx context.Context, c *adengine.Client, o admodel.SearchOptions) (admodel.SearchResult, error) {
				r, err := adservice_replication.New(c).ReplicationConnections(ctx, o)
				return r.Observation, err
			},
		},
	}
}

// sweepObservation is one operation's endpoint-and-partition result. Each field
// is a distinct observation rather than an aggregate, so a reader can see which
// half of the scenario a failure came from, and every read carries the reason it
// did not complete.
type InternalSweepObservation struct {
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
func InternalSweepDetail(err error, result admodel.SearchResult) string {
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

// qualifies is the whole scenario in one place: both halves must hold and the
// session must not leak. It is a method so the aggregation can be tested
// directly; an aggregation that silently became permissive would make every
// future sweep pass regardless of what the directory did.
func (o InternalSweepObservation) InternalQualifies() bool {
	explicitHeld := o.ExplicitBaseRead == nil || *o.ExplicitBaseRead
	return o.PrimaryDefaultRead && o.SecondaryDefaultRead && explicitHeld &&
		o.MismatchedBaseRefused && o.MismatchedBaseNoObject &&
		o.AllocationsRemaining == 0
}

func InternalSweepAllocations(c InternalSearchNativeCounts) int {
	return c.InternalMessages + c.InternalControls + c.InternalControlSets + c.InternalCookies + c.InternalValues + c.InternalNames + c.InternalCursors
}

func InternalSweepStatus(complete bool, err error) string {
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
		SchemaVersion       int                        `json:"schema_version"`
		Scope               string                     `json:"scope"`
		RunID               string                     `json:"run_id"`
		Primary             string                     `json:"primary_endpoint"`
		Secondary           string                     `json:"secondary_endpoint"`
		AbsentBase          string                     `json:"absent_base"`
		RuntimeOS           string                     `json:"runtime_os"`
		RuntimeArchitecture string                     `json:"runtime_architecture"`
		Started             time.Time                  `json:"started"`
		Finished            time.Time                  `json:"finished"`
		Passed              bool                       `json:"passed"`
		FullTicketComplete  bool                       `json:"full_ticket_complete"`
		FailureStage        string                     `json:"failure_stage,omitempty"`
		PrimaryController   string                     `json:"primary_controller_dn"`
		SecondaryController string                     `json:"secondary_controller_dn"`
		EndpointNotReplaced bool                       `json:"explicit_endpoint_not_replaced"`
		UnavailableRefused  bool                       `json:"unavailable_endpoint_refused"`
		UnavailableDetail   string                     `json:"unavailable_endpoint_detail,omitempty"`
		LongLivedProbe      string                     `json:"long_lived_session_probe,omitempty"`
		Operations          []InternalSweepObservation `json:"operations"`
	}{
		SchemaVersion: 1, Scope: "directory-endpoint-and-partition-sweep", RunID: runID,
		Primary: primary, Secondary: secondary, AbsentBase: absentBase,
		RuntimeOS: runtime.GOOS, RuntimeArchitecture: runtime.GOARCH,
		Started: time.Now().UTC(), Operations: []InternalSweepObservation{},
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
		file, err := os.OpenFile(resultPath, os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0o600)
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
	withSession := func(host string, fn func(*adengine.Client)) (int, error) {
		client, err := adengine.Dial(
			ctx,
			admodel.Config{
				Endpoint: admodel.Endpoint{Host: host, Port: 389},
				Timeout:  30 * time.Second,
			},
		)
		if err != nil {
			return 0, err
		}
		var counts InternalSearchNativeCounts
		(*adengine.InternalClientSessionPointer(client)).(*adengine.InternalLdapSession).InternalApi = InternalCountedSearchAPI(
			&counts,
		)
		if fn != nil {
			fn(client)
		}
		closeErr := client.Close()
		return InternalSweepAllocations(counts), closeErr
	}

	// Which controller actually answered each endpoint. Two explicit endpoints
	// answered by one controller would mean the DC locator replaced a target
	// the caller named, which LDAP_OPT_AREC_EXCLUSIVE exists to prevent.
	stage = "endpoint-identity"
	defaultNC := ""
	connected := func(host string) string {
		dn := ""
		leaked, err := withSession(host, func(c *adengine.Client) {
			result, readErr := c.Directory().
				DomainController(ctx, admodel.DomainControllerOptions{})
			if readErr != nil || !result.Observation.Complete {
				fail("%s did not report its connected controller: %v", host, readErr)
				return
			}
			dn = result.Controller.Server.DistinguishedName
			if root := result.Observation.RootDSE; root.DefaultNamingContext != nil &&
				defaultNC == "" {
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
	for _, target := range InternalEndpointSweepTargets() {
		o := InternalSweepObservation{
			Cmdlet:       target.InternalCmdlet,
			DomainScoped: target.InternalDomainScoped,
		}

		// Documented default, explicit base and a refused naming context, all
		// on one session for this operation.
		//
		// No ResultLimit is set. A caller's limit stops retrieval with
		// LimitReached and leaves Complete false with a nil error, so bounding
		// the result count here would report a busy container as an incomplete
		// read. PageSize still exercises paging; Complete then means the server
		// ended the search.
		defaultOptions := admodel.SearchOptions{PageSize: 16}
		explicitOptions := admodel.SearchOptions{Base: defaultNC, PageSize: 16}
		absentOptions := admodel.SearchOptions{Base: absentBase, PageSize: 16}
		if !target.InternalSuppliesOwnBase {
			container := "CN=Users," + defaultNC
			defaultOptions = admodel.SearchOptions{
				Base:     container,
				Scope:    admodel.ScopeSubtree,
				PageSize: 16,
			}
			explicitOptions = defaultOptions
			absentOptions.Scope = admodel.ScopeSubtree
		}

		leaked, err := withSession(primary, func(c *adengine.Client) {
			result, readErr := target.InternalRead(ctx, c, defaultOptions)
			o.PrimaryDefaultRead = readErr == nil && result.Complete
			o.PrimaryDetail = InternalSweepDetail(readErr, result)

			if target.InternalDomainScoped && defaultNC != "" {
				result, readErr = target.InternalRead(ctx, c, explicitOptions)
				explicit := readErr == nil && result.Complete
				o.ExplicitBaseRead = &explicit
				o.ExplicitDetail = InternalSweepDetail(readErr, result)
			}

			// The failure half: a naming context this operation does not serve
			// must be refused, and must not be answered from the operation's
			// own container instead.
			result, readErr = target.InternalRead(ctx, c, absentOptions)
			o.MismatchedBaseRefused = readErr != nil || !result.Complete
			o.MismatchedBaseNoObject = len(result.Objects) == 0
			o.RefusalDetail = InternalSweepDetail(readErr, result)
		})
		if err != nil {
			o.PrimaryDetail = "session: " + err.Error()
		}
		o.AllocationsRemaining = leaked

		// The same operation's documented default on the other endpoint.
		if _, err := withSession(secondary, func(c *adengine.Client) {
			result, readErr := target.InternalRead(ctx, c, defaultOptions)
			o.SecondaryDefaultRead = readErr == nil && result.Complete
			o.SecondaryDetail = InternalSweepDetail(readErr, result)
		}); err != nil {
			o.SecondaryDetail = "session: " + err.Error()
		}

		o.Passed = o.InternalQualifies()
		if !o.Passed {
			fail("%s: endpoint and partition observation incomplete: %+v", target.InternalCmdlet, o)
		}
		artifact.Operations = append(artifact.Operations, o)
	}

	// An unavailable endpoint must fail rather than resolve to a reachable one.
	stage = "unavailable-endpoint"
	unreachable, err := adengine.Dial(
		ctx,
		admodel.Config{
			Endpoint: admodel.Endpoint{Host: primary, Port: 3899},
			Timeout:  10 * time.Second,
		},
	)
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
	artifact.LongLivedProbe = InternalLongLivedSessionProbe(ctx, primary)

	if !t.Failed() {
		stage = "complete"
	}
	t.Logf(
		"endpoint and partition sweep over %d operations on %s and %s; full ticket qualification remains incomplete",
		len(artifact.Operations),
		primary,
		secondary,
	)
}

// longLivedSessionProbe holds one session open across several reads and reports
// what happened, in order. It asserts nothing.
func InternalLongLivedSessionProbe(ctx context.Context, host string) string {
	client, err := adengine.Dial(
		ctx,
		admodel.Config{
			Endpoint: admodel.Endpoint{Host: host, Port: 389},
			Timeout:  30 * time.Second,
		},
	)
	if err != nil {
		return "dial=error(" + err.Error() + ")"
	}
	defer func() { _ = client.Close() }()
	var counts InternalSearchNativeCounts
	(*adengine.InternalClientSessionPointer(client)).(*adengine.InternalLdapSession).InternalApi = InternalCountedSearchAPI(
		&counts,
	)
	report := make([]string, 0, 5)
	result, readErr := client.Directory().DomainController(ctx, admodel.DomainControllerOptions{})
	report = append(
		report,
		"controller-read="+InternalSweepStatus(result.Observation.Complete, readErr),
	)
	for i := range 3 {
		search, searchErr := adservice_users.New(client).
			Users(ctx, admodel.SearchOptions{PageSize: 16})
		report = append(
			report,
			fmt.Sprintf(
				"read%d=%s",
				i+1,
				InternalSweepStatus(search.Observation.Complete, searchErr),
			),
		)
	}
	report = append(report, fmt.Sprintf("allocations=%d", InternalSweepAllocations(counts)))
	return strings.Join(report, "; ")
}
