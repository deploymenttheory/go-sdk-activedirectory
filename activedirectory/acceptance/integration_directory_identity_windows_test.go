//go:build windows && (amd64 || arm64)

package acceptance

import (
	"context"
	"encoding/json"
	"os"
	"runtime"
	"strings"
	"testing"
	"time"

	adengine "github.com/deploymenttheory/go-sdk-activedirectory/activedirectory/internal/engine"
	admodel "github.com/deploymenttheory/go-sdk-activedirectory/activedirectory/internal/model"
	adservice_computers "github.com/deploymenttheory/go-sdk-activedirectory/activedirectory/services/computers"
	adservice_groups "github.com/deploymenttheory/go-sdk-activedirectory/activedirectory/services/groups"
	adservice_organizational_units "github.com/deploymenttheory/go-sdk-activedirectory/activedirectory/services/organizational_units"
	adservice_users "github.com/deploymenttheory/go-sdk-activedirectory/activedirectory/services/users"
)

// identityForms is one fixture object and the identity forms it actually
// carries. A form the object does not have is absent rather than empty, so the
// qualification cannot be handed an identity the reference does not document
// for that object — an organizational unit has no security identifier and no
// account name.
type InternalIdentityForms struct {
	DN      string `json:"dn"`
	GUID    string `json:"guid"`
	SID     string `json:"sid,omitempty"`
	Account string `json:"account,omitempty"`
}

type InternalIdentityFixture struct {
	SchemaVersion int                   `json:"schema_version"`
	RunID         string                `json:"run_id"`
	Server        string                `json:"server"`
	Marker        string                `json:"marker"`
	OU            InternalIdentityForms `json:"ou"`
	UnicodeUser   InternalIdentityForms `json:"unicode_user"`
	EscapedUser   InternalIdentityForms `json:"escaped_user"`
	EscapedGroup  InternalIdentityForms `json:"escaped_group"`
	Computer      InternalIdentityForms `json:"computer"`
	MissingGUID   string                `json:"missing_guid"`
}

// identityResolution records one form's outcome. The resolved GUID is kept so a
// form that resolved the *wrong* object is distinguishable from one that failed.
type InternalIdentityResolution struct {
	Form     string `json:"form"`
	Resolved bool   `json:"resolved"`
	SameAs   bool   `json:"same_object"`
	GUID     string `json:"resolved_guid,omitempty"`
	Detail   string `json:"detail,omitempty"`
	// ScopedResolved repeats the same lookup with Partition narrowed to the
	// fixture's own container. It isolates whether a form is broken or merely
	// unable to search the default naming context.
	ScopedResolved bool   `json:"narrowed_partition_resolved"`
	ScopedSameAs   bool   `json:"narrowed_partition_same_object"`
	ScopedDetail   string `json:"narrowed_partition_detail,omitempty"`
}

type InternalIdentityObservation struct {
	Cmdlet string `json:"cmdlet"`
	Object string `json:"fixture"`
	// Forms is every documented form for this fixture, each resolved
	// independently and compared against the fixture's own GUID.
	Forms []InternalIdentityResolution `json:"forms"`
	// UnsupportedRefused covers forms the fixture carries that this operation
	// does not document. Each must be refused rather than resolved.
	UnsupportedRefused []InternalIdentityResolution `json:"unsupported_forms_refused"`
	// WrongClassRefused resolves an identity of the wrong object class, which
	// must fail rather than return a different object.
	WrongClassRefused bool   `json:"wrong_class_refused"`
	WrongClassDetail  string `json:"wrong_class_detail,omitempty"`
	MissingRefused    bool   `json:"missing_object_refused"`
	MissingDetail     string `json:"missing_object_detail,omitempty"`
	Allocations       int    `json:"native_allocations_remaining"`
	Passed            bool   `json:"passed"`
}

// qualifies requires every documented form to resolve the same object, and both
// refusals to hold. A fixture with no form would pass vacuously, so at least
// two are required: no object here carries fewer than a DN and a GUID.
func (o InternalIdentityObservation) InternalQualifies() bool {
	if len(o.Forms) < 2 {
		return false
	}
	for _, form := range o.Forms {
		if !form.Resolved || !form.SameAs {
			return false
		}
	}
	for _, form := range o.UnsupportedRefused {
		if form.Resolved {
			return false
		}
	}
	return o.WrongClassRefused && o.MissingRefused && o.Allocations == 0
}

// identityTarget is one operation's single-object read, reduced to the shape
// every such read in this SDK shares.
type InternalIdentityTarget struct {
	InternalCmdlet string
	// accepts names the identity forms this operation documents. A form the
	// fixture carries but the operation does not accept must be refused, not
	// resolved: the scenario asks that supported forms resolve the same object
	// "where documented", and that unsupported ones fail.
	InternalAccepts map[string]bool
	InternalFixture func(InternalIdentityFixture) (string, InternalIdentityForms)
	InternalRead    func(context.Context, *adengine.Client, admodel.Identity, admodel.ResolveIdentityOptions) (string, error)
}

// containerOf returns a distinguished name's parent, respecting escaped commas
// so a fixture with an escaped common name is not split in the wrong place.
func InternalContainerOf(dn string) string {
	escaped := false
	for i, r := range dn {
		switch {
		case escaped:
			escaped = false
		case r == 0x5c: // backslash, the DN escape character
			escaped = true
		case r == ',':
			return dn[i+1:]
		}
	}
	return ""
}

func InternalIdentitySweepTargets() []InternalIdentityTarget {
	// Each read reports the GUID through the SDK's own rendering rather than a
	// byte order reconstructed here.
	text := func(g *admodel.GUID) string {
		if g == nil {
			return ""
		}
		return g.String()
	}
	return []InternalIdentityTarget{
		{
			"Get-ADUser",
			map[string]bool{"dn": true, "guid": true, "sid": true, "account": true},
			func(f InternalIdentityFixture) (string, InternalIdentityForms) { return "unicode_user", f.UnicodeUser },
			func(ctx context.Context, c *adengine.Client, id admodel.Identity, o admodel.ResolveIdentityOptions) (string, error) {
				r, err := adservice_users.New(c).User(ctx, id, o)
				if r.User == nil {
					return "", err
				}
				return text(r.User.GUID), err
			},
		},
		{
			"Get-ADGroup",
			map[string]bool{"dn": true, "guid": true, "sid": true, "account": true},
			func(f InternalIdentityFixture) (string, InternalIdentityForms) {
				return "escaped_group", f.EscapedGroup
			},
			func(ctx context.Context, c *adengine.Client, id admodel.Identity, o admodel.ResolveIdentityOptions) (string, error) {
				r, err := adservice_groups.New(c).Group(ctx, id, o)
				if r.Group == nil {
					return "", err
				}
				return text(r.Group.GUID), err
			},
		},
		{
			"Get-ADComputer",
			map[string]bool{"dn": true, "guid": true, "sid": true, "account": true},
			func(f InternalIdentityFixture) (string, InternalIdentityForms) { return "computer", f.Computer },
			func(ctx context.Context, c *adengine.Client, id admodel.Identity, o admodel.ResolveIdentityOptions) (string, error) {
				r, err := adservice_computers.New(c).Computer(ctx, id, o)
				if r.Computer == nil {
					return "", err
				}
				return text(r.Computer.GUID), err
			},
		},
		{
			"Get-ADOrganizationalUnit",
			map[string]bool{"dn": true, "guid": true},
			func(f InternalIdentityFixture) (string, InternalIdentityForms) { return "ou", f.OU },
			func(ctx context.Context, c *adengine.Client, id admodel.Identity, o admodel.ResolveIdentityOptions) (string, error) {
				r, err := adservice_organizational_units.New(c).OrganizationalUnit(ctx, id, o)
				if r.Unit == nil {
					return "", err
				}
				return text(r.Unit.GUID), err
			},
		},
		{
			"Get-ADObject",
			map[string]bool{"dn": true, "guid": true},
			func(f InternalIdentityFixture) (string, InternalIdentityForms) { return "escaped_user", f.EscapedUser },
			func(ctx context.Context, c *adengine.Client, id admodel.Identity, o admodel.ResolveIdentityOptions) (string, error) {
				r, err := c.ResolveIdentity(ctx, id, o)
				if r.Object == nil {
					return "", err
				}
				values, state := r.Object.Attribute("objectGUID")
				if state != admodel.AttributePresent || len(values) != 1 {
					return "", err
				}
				guid, convertErr := admodel.GUIDFromBytes(values[0])
				if convertErr != nil {
					return "", err
				}
				return guid.String(), err
			},
		},
	}
}

// The outer harness creates the fixtures and names them in a file only inside
// an owned run. This test performs no directory mutation; every call resolves
// one identity. Ordinary go test invocations skip it.
//
// It qualifies identity-forms-and-scope: each documented form of a fixture must
// resolve that same fixture, including a common name carrying supplementary
// Unicode and one whose comma and plus must be escaped in a distinguished name,
// while a wrong object class and a missing object are refused without selecting
// an arbitrary object.
func TestDirectoryIdentitySweepLab(t *testing.T) {
	fixturePath := os.Getenv("ADSDK_IDENTITY_FIXTURE")
	if fixturePath == "" {
		t.Skip("requires the opt-in isolated directory identity harness")
	}
	resultPath := os.Getenv("ADSDK_IDENTITY_RESULT")
	runID := os.Getenv("ADSDK_IDENTITY_RUN_ID")
	if resultPath == "" || runID == "" {
		t.Fatal("a run identity and a fresh result path are required")
	}
	data, err := os.ReadFile(fixturePath)
	if err != nil {
		t.Fatal("cannot read the identity fixture")
	}
	if len(data) >= 3 && string(data[:3]) == "\xef\xbb\xbf" {
		data = data[3:]
	}
	var fixture InternalIdentityFixture
	if err := json.Unmarshal(data, &fixture); err != nil {
		t.Fatal("invalid identity fixture encoding")
	}
	if fixture.SchemaVersion != 1 || fixture.RunID != runID ||
		!strings.HasSuffix(strings.ToLower(fixture.Server), ".ad.sdk.test") ||
		!strings.HasPrefix(fixture.Marker, "ad-sdk-identity:") ||
		!strings.HasPrefix(fixture.OU.DN, "OU=ADSDK-Identity-") {
		t.Fatal("identity fixture is outside the isolated lab namespace")
	}
	// The point of the fixture is the awkward names; a plain one would make the
	// qualification claim more than it observed.
	if fixture.UnicodeUser.DN == "" ||
		len(fixture.UnicodeUser.DN) == len([]rune(fixture.UnicodeUser.DN)) {
		t.Fatal("the unicode fixture does not carry non-ASCII text")
	}
	if !strings.Contains(fixture.EscapedUser.DN, "\\,") ||
		!strings.Contains(fixture.EscapedGroup.DN, "\\,") {
		t.Fatal("the escaped fixtures do not carry an escaped distinguished name")
	}

	artifact := struct {
		SchemaVersion       int                           `json:"schema_version"`
		Scope               string                        `json:"scope"`
		RunID               string                        `json:"run_id"`
		Endpoint            string                        `json:"endpoint"`
		RuntimeOS           string                        `json:"runtime_os"`
		RuntimeArchitecture string                        `json:"runtime_architecture"`
		Started             time.Time                     `json:"started"`
		Finished            time.Time                     `json:"finished"`
		Passed              bool                          `json:"passed"`
		FullTicketComplete  bool                          `json:"full_ticket_complete"`
		FailureStage        string                        `json:"failure_stage,omitempty"`
		Operations          []InternalIdentityObservation `json:"operations"`
	}{
		SchemaVersion: 1, Scope: "directory-identity-forms-and-scope", RunID: runID,
		Endpoint: fixture.Server, RuntimeOS: runtime.GOOS, RuntimeArchitecture: runtime.GOARCH,
		Started: time.Now().UTC(), Operations: []InternalIdentityObservation{},
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
		encoded, err := json.MarshalIndent(artifact, "", "  ")
		if err != nil {
			t.Error("cannot encode identity artifact")
			return
		}
		file, err := os.OpenFile(resultPath, os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0o600)
		if err != nil {
			t.Error("cannot create fresh identity artifact")
			return
		}
		_, writeErr := file.Write(append(encoded, '\n'))
		if closeErr := file.Close(); writeErr != nil || closeErr != nil {
			t.Error("cannot finish identity artifact")
		}
	}()

	ctx, cancel := context.WithTimeout(context.Background(), 15*time.Minute)
	defer cancel()

	withSession := func(fn func(*adengine.Client)) (int, error) {
		client, err := adengine.Dial(
			ctx,
			admodel.Config{
				Endpoint: admodel.Endpoint{Host: fixture.Server, Port: 389},
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

	stage = "operation-sweep"
	for _, target := range InternalIdentitySweepTargets() {
		name, forms := target.InternalFixture(fixture)
		o := InternalIdentityObservation{
			Cmdlet: target.InternalCmdlet,
			Object: name,
			Forms:  []InternalIdentityResolution{},
		}

		// Only the forms this object carries, built through the public
		// constructors so an unsupported form is rejected before any call.
		candidates := []struct {
			InternalForm  string
			InternalValue string
			InternalBuild func(string) (admodel.Identity, error)
		}{
			{"dn", forms.DN, admodel.IdentityByDN},
			{"guid", forms.GUID, admodel.IdentityByGUID},
			{"sid", forms.SID, admodel.IdentityBySID},
			{"account", forms.Account, admodel.IdentityByAccountName},
		}
		leaked, sessionErr := withSession(func(c *adengine.Client) {
			for _, candidate := range candidates {
				if candidate.InternalValue == "" {
					continue
				}
				resolution := InternalIdentityResolution{Form: candidate.InternalForm}
				identity, buildErr := candidate.InternalBuild(candidate.InternalValue)
				if buildErr != nil {
					resolution.Detail = "construct: " + buildErr.Error()
					o.Forms = append(o.Forms, resolution)
					continue
				}
				if !target.InternalAccepts[candidate.InternalForm] {
					// Not documented for this operation: it must be refused.
					guid, readErr := target.InternalRead(
						ctx,
						c,
						identity,
						admodel.ResolveIdentityOptions{},
					)
					resolution.Resolved = readErr == nil && guid != ""
					resolution.GUID = guid
					if readErr != nil {
						resolution.Detail = readErr.Error()
					}
					o.UnsupportedRefused = append(o.UnsupportedRefused, resolution)
					continue
				}
				guid, readErr := target.InternalRead(
					ctx,
					c,
					identity,
					admodel.ResolveIdentityOptions{},
				)
				resolution.Resolved = readErr == nil && guid != ""
				resolution.GUID = guid
				resolution.SameAs = strings.EqualFold(guid, forms.GUID)
				if readErr != nil {
					resolution.Detail = readErr.Error()
				}
				// Repeat with the search narrowed to the fixture's container.
				if container := InternalContainerOf(forms.DN); container != "" {
					scoped, scopedErr := target.InternalRead(
						ctx,
						c,
						identity,
						admodel.ResolveIdentityOptions{Partition: container},
					)
					resolution.ScopedResolved = scopedErr == nil && scoped != ""
					resolution.ScopedSameAs = strings.EqualFold(scoped, forms.GUID)
					if scopedErr != nil {
						resolution.ScopedDetail = scopedErr.Error()
					}
				}
				o.Forms = append(o.Forms, resolution)
			}

			// A wrong class must be refused. Every target reads a class other
			// than the organizational unit, so the unit's own identity is the
			// mismatch; the unit itself is given a user instead.
			wrong := fixture.OU.DN
			if target.InternalCmdlet == "Get-ADOrganizationalUnit" {
				wrong = fixture.UnicodeUser.DN
			}
			if target.InternalCmdlet == "Get-ADObject" {
				// The generic read accepts any class by design, so the
				// mismatch it must refuse is a malformed identity instead.
				wrong = ""
				if _, buildErr := admodel.IdentityByDN(
					"this is not a distinguished name",
				); buildErr != nil {
					o.WrongClassRefused = true
					o.WrongClassDetail = "construct: " + buildErr.Error()
				}
			}
			if wrong != "" {
				identity, buildErr := admodel.IdentityByDN(wrong)
				if buildErr != nil {
					o.WrongClassDetail = "construct: " + buildErr.Error()
					o.WrongClassRefused = true
				} else {
					guid, readErr := target.InternalRead(
						ctx,
						c,
						identity,
						admodel.ResolveIdentityOptions{},
					)
					o.WrongClassRefused = readErr != nil || guid == ""
					if readErr != nil {
						o.WrongClassDetail = readErr.Error()
					} else if guid != "" {
						o.WrongClassDetail = "resolved " + guid
					}
				}
			}

			// A syntactically valid identity that names nothing must fail
			// rather than select some other object.
			identity, buildErr := admodel.IdentityByGUID(fixture.MissingGUID)
			if buildErr != nil {
				o.MissingDetail = "construct: " + buildErr.Error()
			} else {
				guid, readErr := target.InternalRead(
					ctx,
					c,
					identity,
					admodel.ResolveIdentityOptions{},
				)
				o.MissingRefused = readErr != nil || guid == ""
				if readErr != nil {
					o.MissingDetail = readErr.Error()
				} else if guid != "" {
					o.MissingDetail = "resolved " + guid
				}
			}
		})
		if sessionErr != nil {
			o.MissingDetail += " session: " + sessionErr.Error()
		}
		o.Allocations = leaked
		o.Passed = o.InternalQualifies()
		if !o.Passed {
			fail("%s: identity observation incomplete: %+v", target.InternalCmdlet, o)
		}
		artifact.Operations = append(artifact.Operations, o)
	}

	if !t.Failed() {
		stage = "complete"
	}
	t.Logf(
		"identity form sweep over %d operations on %s; full ticket qualification remains incomplete",
		len(artifact.Operations),
		fixture.Server,
	)
}
