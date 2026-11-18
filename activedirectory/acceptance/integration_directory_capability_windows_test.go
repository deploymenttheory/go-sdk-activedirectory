//go:build windows && (amd64 || arm64)

package acceptance

import (
	"context"
	"encoding/json"
	"errors"
	"os"
	"runtime"
	"testing"
	"time"

	adengine "github.com/deploymenttheory/go-sdk-activedirectory/activedirectory/internal/engine"
	admodel "github.com/deploymenttheory/go-sdk-activedirectory/activedirectory/internal/model"
)

// capabilityObservation is one operation's capability-errors-and-resource-lifetime
// result. The supported and unsupported directories are recorded separately, as
// are the repeated calls and the error raised after native resources were taken.
type InternalCapabilityObservation struct {
	Cmdlet string `json:"cmdlet"`
	// HasPrerequisite is false for the generic object read, which deliberately
	// carries no directory-type prerequisite: Client.Search submits whatever
	// the caller asked for. There is no capability refusal to observe, so the
	// operation is recorded and excluded rather than failed.
	HasPrerequisite bool `json:"has_directory_prerequisite"`
	// Supported is the operation against the real AD DS endpoint.
	Supported       bool   `json:"supported_capability_read"`
	SupportedDetail string `json:"supported_capability_detail,omitempty"`
	// Unsupported is the same operation against a directory advertising no
	// capability at all, which must be refused with an actionable error rather
	// than attempted.
	UnsupportedRefused bool   `json:"unsupported_capability_refused"`
	UnsupportedKind    string `json:"unsupported_capability_error_kind,omitempty"`
	UnsupportedDetail  string `json:"unsupported_capability_detail,omitempty"`
	// RepeatedCalls reads three times on one session, which must behave
	// identically each time.
	RepeatedCalls int `json:"repeated_calls_completed"`
	// NativeErrorAfterResources asks for a naming context the server does not
	// hold, so the failure arrives after the search has taken native
	// resources. Those must still be released.
	NativeErrorRaised    bool   `json:"native_error_after_resources"`
	NativeErrorDetail    string `json:"native_error_detail,omitempty"`
	AllocationsSupported int    `json:"allocations_remaining_supported"`
	AllocationsFailed    int    `json:"allocations_remaining_after_failure"`
	CloseIdempotent      bool   `json:"close_idempotent"`
	Passed               bool   `json:"passed"`
}

// qualifies requires both halves, release on both paths, and that repeated
// calls behaved the same. Three repeats is the minimum that distinguishes a
// reusable session from one that happened to survive a second call.
func (o InternalCapabilityObservation) InternalQualifies() bool {
	return o.HasPrerequisite && o.Supported && o.UnsupportedRefused && o.RepeatedCalls == 3 &&
		o.NativeErrorRaised && o.AllocationsSupported == 0 &&
		o.AllocationsFailed == 0 && o.CloseIdempotent
}

// InternalCapabilityErrorKind records the most precise refusal first. The typed
// contract is pinned separately by directory_capability_contract_test.go; legacy
// sentinel cases remain observable here so reports expose any weaker refusal
// rather than flattening every unsupported error into the same result.
func InternalCapabilityErrorKind(err error) string {
	var capability *admodel.DirectoryCapabilityError
	switch {
	case err == nil:
		return ""
	case errors.As(err, &capability):
		return "DirectoryCapabilityError"
	case errors.Is(err, admodel.ErrUnsupportedDirectory):
		return "ErrUnsupportedDirectory"
	case errors.Is(err, admodel.ErrUserCapability):
		return "ErrUserCapability"
	case errors.Is(err, admodel.ErrUnsupported):
		return "ErrUnsupported"
	}
	return "other"
}

// The outer harness supplies the endpoint only inside an owned run. This test
// performs no directory mutation; every call is a paged read. The unsupported
// directory is a loopback fixture started in this process, so no second server
// is required. Ordinary go test invocations skip it.
//
// It qualifies capability-errors-and-resource-lifetime across the sweep table:
// a supported directory against one advertising no capability, repeated calls,
// and a native error raised after resources were taken, with every allocation
// released on both paths.
func TestDirectoryCapabilitySweepLab(t *testing.T) {
	endpoint := os.Getenv("ADSDK_CAPABILITY_ENDPOINT")
	if endpoint == "" {
		t.Skip("requires the opt-in isolated directory capability harness")
	}
	resultPath := os.Getenv("ADSDK_CAPABILITY_RESULT")
	runID := os.Getenv("ADSDK_CAPABILITY_RUN_ID")
	if resultPath == "" || runID == "" {
		t.Fatal("an endpoint, a run identity and a fresh result path are required")
	}
	const absentBase = "DC=absent,DC=invalid"
	artifact := struct {
		SchemaVersion       int                             `json:"schema_version"`
		Scope               string                          `json:"scope"`
		RunID               string                          `json:"run_id"`
		Endpoint            string                          `json:"endpoint"`
		RuntimeOS           string                          `json:"runtime_os"`
		RuntimeArchitecture string                          `json:"runtime_architecture"`
		Started             time.Time                       `json:"started"`
		Finished            time.Time                       `json:"finished"`
		Passed              bool                            `json:"passed"`
		FullTicketComplete  bool                            `json:"full_ticket_complete"`
		FailureStage        string                          `json:"failure_stage,omitempty"`
		UnsupportedSource   string                          `json:"unsupported_directory_source"`
		Operations          []InternalCapabilityObservation `json:"operations"`
	}{
		SchemaVersion:       1,
		Scope:               "directory-capability-errors-and-resource-lifetime",
		RunID:               runID,
		Endpoint:            endpoint,
		RuntimeOS:           runtime.GOOS,
		RuntimeArchitecture: runtime.GOARCH,
		Started:             time.Now().UTC(),
		UnsupportedSource: "in-process loopback LDAP fixture advertising no supportedCapabilities, " +
			"read by real WinLDAP over a real socket",
		Operations: []InternalCapabilityObservation{},
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
			t.Error("cannot encode capability artifact")
			return
		}
		file, err := os.OpenFile(resultPath, os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0o600)
		if err != nil {
			t.Error("cannot create fresh capability artifact")
			return
		}
		_, writeErr := file.Write(append(data, '\n'))
		if closeErr := file.Close(); writeErr != nil || closeErr != nil {
			t.Error("cannot finish capability artifact")
		}
	}()

	ctx, cancel := context.WithTimeout(context.Background(), 15*time.Minute)
	defer cancel()

	stage = "default-naming-context"
	defaultNC := ""
	probe, err := adengine.Dial(
		ctx,
		admodel.Config{
			Endpoint: admodel.Endpoint{Host: endpoint, Port: 389},
			Timeout:  30 * time.Second,
		},
	)
	if err != nil {
		t.Fatal("native dial failed")
	}
	if root, rootErr := probe.RootDSE(
		ctx,
		admodel.RootDSEOptions{},
	); rootErr == nil &&
		root.DefaultNamingContext != nil {
		defaultNC = *root.DefaultNamingContext
	}
	if closeErr := probe.Close(); closeErr != nil || defaultNC == "" {
		t.Fatal("the connection did not report a default naming context")
	}

	stage = "operation-sweep"
	for _, target := range InternalEndpointSweepTargets() {
		o := InternalCapabilityObservation{
			Cmdlet:          target.InternalCmdlet,
			HasPrerequisite: target.InternalCmdlet != "Get-ADObject",
		}
		options := admodel.SearchOptions{PageSize: 64}
		if target.InternalDomainScoped {
			options = admodel.SearchOptions{
				Base:     "CN=Users," + defaultNC,
				Scope:    admodel.ScopeSubtree,
				PageSize: 64,
			}
		}

		// The supported directory: one session, a satisfied read, two more
		// repeats, a failure after resources were taken, and an idempotent
		// close. Every stage shares the one allocation counter.
		client, dialErr := adengine.Dial(
			ctx,
			admodel.Config{
				Endpoint: admodel.Endpoint{Host: endpoint, Port: 389},
				Timeout:  30 * time.Second,
			},
		)
		if dialErr != nil {
			o.SupportedDetail = "dial: " + dialErr.Error()
		} else {
			var counts InternalSearchNativeCounts
			(*adengine.InternalClientSessionPointer(client)).(*adengine.InternalLdapSession).InternalApi = InternalCountedSearchAPI(
				&counts,
			)
			for range 3 {
				result, readErr := target.InternalRead(ctx, client, options)
				if readErr == nil && result.Complete {
					o.RepeatedCalls++
					continue
				}
				o.SupportedDetail = InternalSweepDetail(readErr, result)
			}
			o.Supported = o.RepeatedCalls > 0
			o.AllocationsSupported = InternalSweepAllocations(counts)

			// A naming context the server does not hold. The search is
			// submitted, so native resources are taken before it fails.
			failing := options
			failing.Base = absentBase
			result, readErr := target.InternalRead(ctx, client, failing)
			o.NativeErrorRaised = readErr != nil || !result.Complete
			o.NativeErrorDetail = InternalSweepDetail(readErr, result)
			o.AllocationsFailed = InternalSweepAllocations(counts)

			first := client.Close()
			second := client.Close()
			o.CloseIdempotent = first == nil && second == nil
		}

		// The unsupported directory. A loopback fixture advertising no
		// capability at all is read by the same real WinLDAP, so the refusal
		// comes from the SDK's own prerequisite rather than from a transport
		// failure. One base read is enough: the capability check precedes any
		// search, which is itself the point.
		fixture := InternalNewSearchWireFixture(
			t,
			[]InternalSearchWirePage{{InternalBaseRead: true}},
		)
		var fixtureCounts InternalSearchNativeCounts
		unsupported := InternalSearchWireClient(
			t,
			fixture,
			InternalCountedSearchAPI(&fixtureCounts),
		)
		result, readErr := target.InternalRead(
			ctx,
			unsupported,
			admodel.SearchOptions{PageSize: 16},
		)
		o.UnsupportedRefused = readErr != nil && !result.Complete
		o.UnsupportedKind = InternalCapabilityErrorKind(readErr)
		if readErr != nil {
			o.UnsupportedDetail = readErr.Error()
		}
		if o.UnsupportedKind == "other" || o.UnsupportedKind == "" {
			// Refused, but not for a capability reason: that is a different
			// observation and must not count.
			o.UnsupportedRefused = false
		}

		o.Passed = o.InternalQualifies()
		switch {
		case !o.HasPrerequisite:
			t.Logf(
				"%s: no directory-type prerequisite by design; capability refusal not observable",
				target.InternalCmdlet,
			)
		case !o.Passed:
			fail("%s: capability observation incomplete: %+v", target.InternalCmdlet, o)
		}
		artifact.Operations = append(artifact.Operations, o)
	}

	if !t.Failed() {
		stage = "complete"
	}
	t.Logf(
		"capability and resource lifetime sweep over %d operations on %s; full ticket qualification remains incomplete",
		len(artifact.Operations),
		endpoint,
	)
}
