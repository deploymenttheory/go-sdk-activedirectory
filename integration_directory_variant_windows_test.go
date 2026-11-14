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

// A parameter set — a variant in the coverage contract — is a distinct way of
// invoking one operation, and the contract asks for a satisfied invocation and
// a refusal for each. The other lab harnesses iterate behavior scenarios, which
// say what the directory must do but nothing about which parameters asked the
// question, so no run has ever observed a parameter set as such. This harness
// observes the parameter sets themselves.
//
// Get-ADObject has three, and each lands on a different SDK entry point rather
// than on one shared read signature:
//
//	Filter (Default)  Client.Search with SearchOptions.TypedFilter, a filter
//	                  composed from values that can never become syntax.
//	LdapFilter        Client.Search with SearchOptions.Filter, raw LDAP text
//	                  passed to the directory as written.
//	Identity          Client.ResolveIdentity, which selects one object by an
//	                  explicit identity instead of searching for a set.
//
// A row therefore carries its own invocations. That is what lets the table grow
// to other operations: Get-ADUser's three parameter sets are the same three
// ideas reached through Client.Users and Client.User, and an operation whose
// sole parameter set is Default is a row with one invocation of its own.

// variantInputs is what this run of the lab actually exposed. A row states what
// it needs from this, and a row whose needs are unmet is recorded and excluded
// rather than passed: a parameter set nothing could be observed against is not
// evidence that it works.
type variantInputs struct {
	defaultNC string
	// container is the base every searching parameter set reads. The domain
	// root is unusable: it holds subordinate naming contexts whose continuation
	// references make a subtree read of it deliberately incomplete, so a plain
	// container with nothing subordinate beneath it is used instead.
	container string
	// presentDN and presentGUID are one object discovered beneath container.
	// Every satisfied invocation here selects that same object through its own
	// parameter set, so the three sets are observed answering one question.
	// The GUID is the raw objectGUID octets as the directory returned them,
	// which is what both filter dialects assert against.
	presentDN   string
	presentGUID []byte
	// absentGUID is a well-formed identity that names nothing.
	absentGUID string
}

// The two filter refusals, named so the harness's own unit tests can check
// where each one is refused rather than checking a copy of the text.
//
// An attribute description cannot contain spaces, so the typed set cannot
// compose a filter from this and refuses before any search is started. Raw
// text is never composed, so an unterminated filter passes this SDK's input
// validation unchanged and only the directory can reject it.
const (
	variantUncomposableAttribute = "not an attribute description"
	variantUnterminatedFilter    = "(objectClass="
)

// variantOutcome is one invocation reduced to what a parameter set can be
// judged on: how many objects it selected, whether the invocation finished,
// which single object it selected where it selects one, and its error.
type variantOutcome struct {
	objects  int
	complete bool
	selected string
	err      error
}

// variantTarget is one operation's one parameter set. Both halves the coverage
// contract requires are row data, because a refusal that is not specific to the
// parameter set would qualify the set without exercising it: a raw filter
// cannot be refused for being an uncomposable typed filter, and an identity
// cannot be refused for bad LDAP grammar.
type variantTarget struct {
	cmdlet  string
	variant string
	// The contract's own test identifiers for this parameter set, carried
	// rather than derived from the name, so the table can be checked against
	// coverage/inventory.json instead of trusting a slug rule.
	successTest string
	failureTest string
	// requires reports why this row cannot be observed in this run, or "" when
	// it can.
	requires func(variantInputs) string
	// satisfied invokes the parameter set the way its own parameters document.
	// satisfiedHolds decides whether the outcome is this parameter set
	// selecting what it was asked for, rather than merely not erroring.
	satisfied      func(context.Context, *Client, variantInputs) variantOutcome
	satisfiedHolds func(variantInputs, variantOutcome) bool
	// refused invokes the same parameter set in a way only it can be refused.
	// refusalHolds decides whether the refusal observed is this parameter set's
	// own refusal and not some other failure that happened to occur.
	refused      func(context.Context, *Client, variantInputs) variantOutcome
	refusalHolds func(variantInputs, variantOutcome) bool
}

// variantSearch runs one search and reduces it. The single-object case records
// which object was selected; a set-returning invocation leaves it empty rather
// than naming an arbitrary member.
func variantSearch(ctx context.Context, c *Client, options SearchOptions) variantOutcome {
	result, err := c.Search(ctx, options)
	outcome := variantOutcome{objects: len(result.Objects), complete: result.Complete, err: err}
	if len(result.Objects) == 1 {
		outcome.selected = result.Objects[0].DistinguishedName
	}
	return outcome
}

// variantResolve runs one identity resolution and reduces it. Candidates rather
// than Object is the count, so an ambiguous resolution is visible as two
// objects instead of as a missing one.
func variantResolve(ctx context.Context, c *Client, identity Identity, err error,
	options ResolveIdentityOptions) variantOutcome {
	if err != nil {
		return variantOutcome{err: err}
	}
	result, resolveErr := c.ResolveIdentity(ctx, identity, options)
	outcome := variantOutcome{objects: len(result.Candidates), complete: result.Complete, err: resolveErr}
	if result.Object != nil {
		outcome.selected = result.Object.DistinguishedName
	}
	return outcome
}

// variantSelectsPresentObject is the satisfied half for every parameter set
// that selects the one object this run discovered. Exactly one object, that
// object, and an invocation the directory finished. Nothing here is satisfied
// by a read that merely failed to error.
func variantSelectsPresentObject(in variantInputs, out variantOutcome) bool {
	return out.err == nil && out.complete && out.objects == 1 &&
		in.presentDN != "" && strings.EqualFold(out.selected, in.presentDN)
}

// variantNeedsPresentObject is the observability rule for the rows that select
// a discovered object: without one, neither half of the parameter set can be
// observed at all.
func variantNeedsPresentObject(in variantInputs) string {
	switch {
	case in.container == "":
		return "no container base was established for this run"
	case in.presentDN == "" || len(in.presentGUID) == 0:
		return "no readable object carrying an objectGUID was found beneath the container"
	}
	return ""
}

func objectVariantTargets() []variantTarget {
	return []variantTarget{
		{
			cmdlet:      "Get-ADObject",
			variant:     "Filter (Default)",
			successTest: "Get-ADObject/filter-default/success",
			failureTest: "Get-ADObject/filter-default/failure",
			requires:    variantNeedsPresentObject,
			satisfied: func(ctx context.Context, c *Client, in variantInputs) variantOutcome {
				// Scope is always explicit. Client.Search takes the caller's
				// options as given, and the zero scope reads only the base;
				// an empty base would read the RootDSE unpageably.
				//
				// The assertion is composed from the returned objectGUID
				// octets, which is the whole point of this parameter set: a
				// binary value reaches the directory escaped, never as syntax.
				return variantSearch(ctx, c, SearchOptions{
					Base: in.container, Scope: ScopeSubtree, PageSize: 16,
					TypedFilter: FilterEqual("objectGUID", FilterBytes(in.presentGUID)),
				})
			},
			satisfiedHolds: variantSelectsPresentObject,
			refused: func(ctx context.Context, c *Client, in variantInputs) variantOutcome {
				// Only this parameter set is handed a composed filter, and only
				// it can fail to compose one. An invalid attribute description
				// is refused while the filter is being built, so no search
				// reaches the directory at all — a refusal the raw-text set
				// cannot produce, because raw text is never composed.
				return variantSearch(ctx, c, SearchOptions{
					Base: in.container, Scope: ScopeSubtree, PageSize: 16,
					TypedFilter: FilterPresent(variantUncomposableAttribute),
				})
			},
			refusalHolds: func(_ variantInputs, out variantOutcome) bool {
				return out.err != nil && !out.complete && out.objects == 0 &&
					errors.Is(out.err, ErrInvalidFilter)
			},
		},
		{
			cmdlet:      "Get-ADObject",
			variant:     "LdapFilter",
			successTest: "Get-ADObject/ldapfilter/success",
			failureTest: "Get-ADObject/ldapfilter/failure",
			requires:    variantNeedsPresentObject,
			satisfied: func(ctx context.Context, c *Client, in variantInputs) variantOutcome {
				// The same question as raw LDAP text, with the octets escaped
				// the way this SDK's own identity searches escape them. Both
				// dialects must select the one object.
				return variantSearch(ctx, c, SearchOptions{
					Base: in.container, Scope: ScopeSubtree, PageSize: 16,
					Filter: "(objectGUID=" + identityBinaryLiteral(in.presentGUID) + ")",
				})
			},
			satisfiedHolds: variantSelectsPresentObject,
			refused: func(ctx context.Context, c *Client, in variantInputs) variantOutcome {
				// Raw text is passed to the directory as written, so the
				// refusal belongs to the directory: an unterminated filter is
				// rejected by the native search rather than by this SDK. That
				// is the opposite half of the typed set's refusal, which never
				// reaches the wire.
				return variantSearch(ctx, c, SearchOptions{
					Base: in.container, Scope: ScopeSubtree, PageSize: 16,
					Filter: variantUnterminatedFilter,
				})
			},
			refusalHolds: func(_ variantInputs, out variantOutcome) bool {
				var searchErr *SearchError
				return out.err != nil && !out.complete && out.objects == 0 &&
					errors.As(out.err, &searchErr) && !errors.Is(out.err, ErrInvalidFilter)
			},
		},
		{
			cmdlet:      "Get-ADObject",
			variant:     "Identity",
			successTest: "Get-ADObject/identity/success",
			failureTest: "Get-ADObject/identity/failure",
			requires: func(in variantInputs) string {
				if reason := variantNeedsPresentObject(in); reason != "" {
					return reason
				}
				if in.absentGUID == "" {
					return "no absent identity was established for this run"
				}
				return ""
			},
			satisfied: func(ctx context.Context, c *Client, in variantInputs) variantOutcome {
				// This parameter set takes no filter, base or scope: it selects
				// one object by an explicit identity, and the SDK never guesses
				// which form the text is.
				identity, err := IdentityByDN(in.presentDN)
				return variantResolve(ctx, c, identity, err, ResolveIdentityOptions{})
			},
			satisfiedHolds: variantSelectsPresentObject,
			refused: func(ctx context.Context, c *Client, in variantInputs) variantOutcome {
				// An absent identity, in the form that makes the refusal this
				// parameter set's own. A distinguished name is read at base
				// scope, so an absent one is refused by the directory as a
				// failed search; a GUID is searched for, so an absent one is a
				// completed search that selected nothing — the "no matching
				// object" refusal, which must not become an arbitrary object.
				identity, err := IdentityByGUID(in.absentGUID)
				return variantResolve(ctx, c, identity, err, ResolveIdentityOptions{})
			},
			refusalHolds: func(_ variantInputs, out variantOutcome) bool {
				return out.err != nil && !out.complete && out.objects == 0 &&
					errors.Is(out.err, ErrDirectoryObjectNotFound)
			},
		},
	}
}

// variantObservation is one parameter set's result. Each field is a separate
// observation rather than an aggregate, so a reader can see which half of the
// contract a failure came from, and every invocation carries its own detail.
type variantObservation struct {
	Cmdlet      string `json:"cmdlet"`
	Variant     string `json:"variant"`
	SuccessTest string `json:"success_test"`
	FailureTest string `json:"failure_test"`
	// Observable records whether this run exposed what the parameter set needs.
	// An unobservable row is reported and excluded, never passed.
	Observable       bool   `json:"observable"`
	ObservableDetail string `json:"observable_detail,omitempty"`
	// The satisfied half: the parameter set invoked as documented, selecting
	// what it was asked for.
	SatisfiedRead     bool   `json:"satisfied_invocation"`
	SatisfiedObjects  int    `json:"satisfied_objects"`
	SatisfiedSelected bool   `json:"satisfied_selected_requested_object"`
	SatisfiedDetail   string `json:"satisfied_detail,omitempty"`
	// The refusal half: a refusal that belongs to this parameter set, returning
	// no object.
	RefusalObserved bool   `json:"refusal_observed"`
	RefusalObjects  int    `json:"refusal_objects"`
	RefusalSpecific bool   `json:"refusal_specific_to_parameter_set"`
	RefusalDetail   string `json:"refusal_detail,omitempty"`
	Allocations     int    `json:"native_allocations_remaining"`
	Passed          bool   `json:"passed"`
}

// qualifies keeps the whole parameter-set claim in one testable place. Every
// observation is load-bearing: an aggregation that silently became permissive
// would make a future run report success regardless of what the directory did,
// and the artifact would read as evidence for 253 unverified parameter sets.
func (o variantObservation) qualifies() bool {
	return o.Observable &&
		o.SatisfiedRead && o.SatisfiedObjects > 0 && o.SatisfiedSelected &&
		o.RefusalObserved && o.RefusalObjects == 0 && o.RefusalSpecific &&
		o.Allocations == 0
}

// variantDetail reports why an invocation did not complete, distinguishing an
// error from an invocation the directory simply did not finish. It records only
// the error's own text, which the SDK already redacts.
func variantDetail(out variantOutcome) string {
	switch {
	case out.err != nil:
		return out.err.Error()
	case !out.complete:
		return "incomplete: the invocation did not finish"
	}
	return ""
}

// The outer harness supplies the endpoint only inside an owned run. This test
// never starts PowerShell, mutates the directory, or operates a VM; every call
// is a read. Ordinary go test invocations skip it.
//
// It qualifies parameter-set variants rather than behavior scenarios. For each
// row both halves the coverage contract names are observed: the parameter set
// invoked as documented, selecting the object it was asked for, and a refusal
// that only that parameter set can produce. A row the run cannot observe is
// recorded and excluded.
func TestDirectoryVariantSweepLab(t *testing.T) {
	endpoint := os.Getenv("ADSDK_VARIANT_ENDPOINT")
	if endpoint == "" {
		t.Skip("requires the opt-in isolated directory variant harness")
	}
	resultPath := os.Getenv("ADSDK_VARIANT_RESULT")
	runID := os.Getenv("ADSDK_VARIANT_RUN_ID")
	if resultPath == "" || runID == "" {
		t.Fatal("an endpoint, a run identity and a fresh result path are required")
	}
	// A well-formed identity no directory object carries. It is a fixed literal
	// rather than a generated one so the artifact names exactly what was asked
	// for; nothing in Active Directory assigns a GUID from this value.
	const absentGUID = "9f51cb95-7f3a-4d1e-8c26-0b7a5e4d3c21"

	artifact := struct {
		SchemaVersion       int                  `json:"schema_version"`
		Scope               string               `json:"scope"`
		RunID               string               `json:"run_id"`
		Endpoint            string               `json:"endpoint"`
		RuntimeOS           string               `json:"runtime_os"`
		RuntimeArchitecture string               `json:"runtime_architecture"`
		Started             time.Time            `json:"started"`
		Finished            time.Time            `json:"finished"`
		Passed              bool                 `json:"passed"`
		FullTicketComplete  bool                 `json:"full_ticket_complete"`
		FailureStage        string               `json:"failure_stage,omitempty"`
		Container           string               `json:"container_base,omitempty"`
		SelectedObject      string               `json:"selected_object_dn,omitempty"`
		SelectedGUID        string               `json:"selected_object_guid,omitempty"`
		AbsentGUID          string               `json:"absent_identity_guid"`
		Observed            int                  `json:"variants_observed"`
		Excluded            int                  `json:"variants_excluded"`
		Variants            []variantObservation `json:"variants"`
	}{
		SchemaVersion: 1, Scope: "directory-parameter-set-variants", RunID: runID,
		Endpoint: endpoint, RuntimeOS: runtime.GOOS, RuntimeArchitecture: runtime.GOARCH,
		AbsentGUID: absentGUID, Started: time.Now().UTC(),
		Variants: []variantObservation{},
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
			t.Error("cannot encode variant artifact")
			return
		}
		file, err := os.OpenFile(resultPath, os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0600)
		if err != nil {
			t.Error("cannot create fresh variant artifact")
			return
		}
		_, writeErr := file.Write(append(data, '\n'))
		if closeErr := file.Close(); writeErr != nil || closeErr != nil {
			t.Error("cannot finish variant artifact")
		}
	}()

	ctx, cancel := context.WithTimeout(context.Background(), 15*time.Minute)
	defer cancel()

	// Each parameter set is observed on its own freshly dialled session, which
	// is how a caller scopes a client, and the allocation total is returned so
	// a leak is attributed to the row that caused it.
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
	inputs := variantInputs{absentGUID: absentGUID}
	if _, err := withSession(func(c *Client) {
		root, readErr := c.RootDSE(ctx, RootDSEOptions{})
		if readErr != nil {
			fail("cannot read the default naming context: %v", readErr)
			return
		}
		if root.DefaultNamingContext != nil {
			inputs.defaultNC = *root.DefaultNamingContext
		}
	}); err != nil {
		t.Fatal("native dial failed")
	}
	if inputs.defaultNC == "" {
		t.Fatal("the connection did not report a default naming context")
	}
	inputs.container = "CN=Users," + inputs.defaultNC
	artifact.Container = inputs.container

	// One object every parameter set will be asked to select. It is discovered
	// rather than configured, so this harness needs no fixture of its own; the
	// container's immediate children are read, because a subtree read is not
	// needed to find one object and the object must exist for any row to be
	// observable at all.
	stage = "select-object"
	leaked, err := withSession(func(c *Client) {
		found, readErr := c.Search(ctx, SearchOptions{
			Base: inputs.container, Scope: ScopeOneLevel, PageSize: 8, ResultLimit: 1,
			TypedFilter: FilterPresent("objectGUID"),
		})
		if readErr != nil {
			fail("cannot select an object beneath %s: %v", inputs.container, readErr)
			return
		}
		if len(found.Objects) == 0 {
			// Not a failure of the SDK. Recorded, and every row will exclude
			// itself below rather than pass on checks that cannot fail.
			t.Logf("no object was readable beneath %s", inputs.container)
			return
		}
		object := found.Objects[0]
		values, state := object.Attribute("objectGUID")
		if state != AttributePresent || len(values) != 1 {
			t.Logf("the selected object did not return a single objectGUID value")
			return
		}
		inputs.presentDN, inputs.presentGUID = object.DistinguishedName, values[0]
		if guid, convertErr := GUIDFromBytes(values[0]); convertErr == nil {
			artifact.SelectedGUID = guid.String()
		}
	})
	if err != nil {
		fail("the object selection session failed: %v", err)
	}
	if leaked != 0 {
		fail("object selection left %d native allocations", leaked)
	}
	artifact.SelectedObject = inputs.presentDN

	stage = "parameter-set-sweep"
	for _, target := range objectVariantTargets() {
		o := variantObservation{
			Cmdlet: target.cmdlet, Variant: target.variant,
			SuccessTest: target.successTest, FailureTest: target.failureTest,
		}
		if reason := target.requires(inputs); reason != "" {
			// Excluded, not passed: the artifact must not be readable as
			// evidence for a parameter set nothing was observed against.
			o.ObservableDetail = reason
			artifact.Excluded++
			artifact.Variants = append(artifact.Variants, o)
			t.Logf("%s/%s: not observable: %s", target.cmdlet, target.variant, reason)
			continue
		}
		o.Observable = true

		leaked, sessionErr := withSession(func(c *Client) {
			satisfied := target.satisfied(ctx, c, inputs)
			o.SatisfiedRead = satisfied.err == nil && satisfied.complete
			o.SatisfiedObjects = satisfied.objects
			o.SatisfiedSelected = target.satisfiedHolds(inputs, satisfied)
			o.SatisfiedDetail = variantDetail(satisfied)

			refused := target.refused(ctx, c, inputs)
			o.RefusalObserved = refused.err != nil && !refused.complete
			o.RefusalObjects = refused.objects
			o.RefusalSpecific = target.refusalHolds(inputs, refused)
			o.RefusalDetail = variantDetail(refused)
		})
		if sessionErr != nil {
			o.SatisfiedDetail += " session: " + sessionErr.Error()
		}
		o.Allocations = leaked
		o.Passed = o.qualifies()
		if !o.Passed {
			fail("%s/%s: parameter-set observation incomplete: %+v", target.cmdlet, target.variant, o)
		} else {
			artifact.Observed++
		}
		artifact.Variants = append(artifact.Variants, o)
	}

	// A run in which nothing was observable is not evidence for anything, and
	// without this it would report success for having found no work to do.
	if artifact.Observed == 0 {
		fail("no parameter set was observed in this run")
	}

	if !t.Failed() {
		stage = "complete"
	}
	t.Logf("parameter-set sweep over %d variants on %s: %d observed, %d excluded; full ticket qualification remains incomplete",
		len(artifact.Variants), endpoint, artifact.Observed, artifact.Excluded)
}
