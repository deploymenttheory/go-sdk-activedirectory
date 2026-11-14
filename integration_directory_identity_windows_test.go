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

// identityForms is one fixture object and the identity forms it actually
// carries. A form the object does not have is absent rather than empty, so the
// qualification cannot be handed an identity the reference does not document
// for that object — an organizational unit has no security identifier and no
// account name.
type identityForms struct {
	DN      string `json:"dn"`
	GUID    string `json:"guid"`
	SID     string `json:"sid,omitempty"`
	Account string `json:"account,omitempty"`
}

type identityFixture struct {
	SchemaVersion int           `json:"schema_version"`
	RunID         string        `json:"run_id"`
	Server        string        `json:"server"`
	Marker        string        `json:"marker"`
	OU            identityForms `json:"ou"`
	UnicodeUser   identityForms `json:"unicode_user"`
	EscapedUser   identityForms `json:"escaped_user"`
	EscapedGroup  identityForms `json:"escaped_group"`
	Computer      identityForms `json:"computer"`
	MissingGUID   string        `json:"missing_guid"`
}

// identityResolution records one form's outcome. The resolved GUID is kept so a
// form that resolved the *wrong* object is distinguishable from one that failed.
type identityResolution struct {
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

type identityObservation struct {
	Cmdlet string `json:"cmdlet"`
	Object string `json:"fixture"`
	// Forms is every documented form for this fixture, each resolved
	// independently and compared against the fixture's own GUID.
	Forms []identityResolution `json:"forms"`
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
func (o identityObservation) qualifies() bool {
	if len(o.Forms) < 2 {
		return false
	}
	for _, form := range o.Forms {
		if !form.Resolved || !form.SameAs {
			return false
		}
	}
	return o.WrongClassRefused && o.MissingRefused && o.Allocations == 0
}

// identityTarget is one operation's single-object read, reduced to the shape
// every such read in this SDK shares.
type identityTarget struct {
	cmdlet  string
	fixture func(identityFixture) (string, identityForms)
	read    func(context.Context, *Client, Identity, ResolveIdentityOptions) (string, error)
}

// containerOf returns a distinguished name's parent, respecting escaped commas
// so a fixture with an escaped common name is not split in the wrong place.
func containerOf(dn string) string {
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

func identitySweepTargets() []identityTarget {
	// Each read reports the GUID through the SDK's own rendering rather than a
	// byte order reconstructed here.
	text := func(g *GUID) string {
		if g == nil {
			return ""
		}
		return g.String()
	}
	return []identityTarget{
		{"Get-ADUser",
			func(f identityFixture) (string, identityForms) { return "unicode_user", f.UnicodeUser },
			func(ctx context.Context, c *Client, id Identity, o ResolveIdentityOptions) (string, error) {
				r, err := c.User(ctx, id, o)
				if r.User == nil {
					return "", err
				}
				return text(r.User.GUID), err
			}},
		{"Get-ADGroup",
			func(f identityFixture) (string, identityForms) { return "escaped_group", f.EscapedGroup },
			func(ctx context.Context, c *Client, id Identity, o ResolveIdentityOptions) (string, error) {
				r, err := c.Group(ctx, id, o)
				if r.Group == nil {
					return "", err
				}
				return text(r.Group.GUID), err
			}},
		{"Get-ADComputer",
			func(f identityFixture) (string, identityForms) { return "computer", f.Computer },
			func(ctx context.Context, c *Client, id Identity, o ResolveIdentityOptions) (string, error) {
				r, err := c.Computer(ctx, id, o)
				if r.Computer == nil {
					return "", err
				}
				return text(r.Computer.GUID), err
			}},
		{"Get-ADOrganizationalUnit",
			func(f identityFixture) (string, identityForms) { return "ou", f.OU },
			func(ctx context.Context, c *Client, id Identity, o ResolveIdentityOptions) (string, error) {
				r, err := c.OrganizationalUnit(ctx, id, o)
				if r.Unit == nil {
					return "", err
				}
				return text(r.Unit.GUID), err
			}},
		{"Get-ADObject",
			func(f identityFixture) (string, identityForms) { return "escaped_user", f.EscapedUser },
			func(ctx context.Context, c *Client, id Identity, o ResolveIdentityOptions) (string, error) {
				r, err := c.ResolveIdentity(ctx, id, o)
				if r.Object == nil {
					return "", err
				}
				values, state := r.Object.Attribute("objectGUID")
				if state != AttributePresent || len(values) != 1 {
					return "", err
				}
				guid, convertErr := GUIDFromBytes(values[0])
				if convertErr != nil {
					return "", err
				}
				return guid.String(), err
			}},
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
	var fixture identityFixture
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
	if fixture.UnicodeUser.DN == "" || len(fixture.UnicodeUser.DN) == len([]rune(fixture.UnicodeUser.DN)) {
		t.Fatal("the unicode fixture does not carry non-ASCII text")
	}
	if !strings.Contains(fixture.EscapedUser.DN, "\\,") || !strings.Contains(fixture.EscapedGroup.DN, "\\,") {
		t.Fatal("the escaped fixtures do not carry an escaped distinguished name")
	}

	artifact := struct {
		SchemaVersion       int                   `json:"schema_version"`
		Scope               string                `json:"scope"`
		RunID               string                `json:"run_id"`
		Endpoint            string                `json:"endpoint"`
		RuntimeOS           string                `json:"runtime_os"`
		RuntimeArchitecture string                `json:"runtime_architecture"`
		Started             time.Time             `json:"started"`
		Finished            time.Time             `json:"finished"`
		Passed              bool                  `json:"passed"`
		FullTicketComplete  bool                  `json:"full_ticket_complete"`
		FailureStage        string                `json:"failure_stage,omitempty"`
		Operations          []identityObservation `json:"operations"`
	}{
		SchemaVersion: 1, Scope: "directory-identity-forms-and-scope", RunID: runID,
		Endpoint: fixture.Server, RuntimeOS: runtime.GOOS, RuntimeArchitecture: runtime.GOARCH,
		Started: time.Now().UTC(), Operations: []identityObservation{},
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
		file, err := os.OpenFile(resultPath, os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0600)
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

	withSession := func(fn func(*Client)) (int, error) {
		client, err := Dial(ctx, Config{Endpoint: Endpoint{Host: fixture.Server, Port: 389}, Timeout: 30 * time.Second})
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

	stage = "operation-sweep"
	for _, target := range identitySweepTargets() {
		name, forms := target.fixture(fixture)
		o := identityObservation{Cmdlet: target.cmdlet, Object: name, Forms: []identityResolution{}}

		// Only the forms this object carries, built through the public
		// constructors so an unsupported form is rejected before any call.
		candidates := []struct {
			form  string
			value string
			build func(string) (Identity, error)
		}{
			{"dn", forms.DN, IdentityByDN},
			{"guid", forms.GUID, IdentityByGUID},
			{"sid", forms.SID, IdentityBySID},
			{"account", forms.Account, IdentityByAccountName},
		}
		leaked, sessionErr := withSession(func(c *Client) {
			for _, candidate := range candidates {
				if candidate.value == "" {
					continue
				}
				resolution := identityResolution{Form: candidate.form}
				identity, buildErr := candidate.build(candidate.value)
				if buildErr != nil {
					resolution.Detail = "construct: " + buildErr.Error()
					o.Forms = append(o.Forms, resolution)
					continue
				}
				guid, readErr := target.read(ctx, c, identity, ResolveIdentityOptions{})
				resolution.Resolved = readErr == nil && guid != ""
				resolution.GUID = guid
				resolution.SameAs = strings.EqualFold(guid, forms.GUID)
				if readErr != nil {
					resolution.Detail = readErr.Error()
				}
				// Repeat with the search narrowed to the fixture's container.
				if container := containerOf(forms.DN); container != "" {
					scoped, scopedErr := target.read(ctx, c, identity,
						ResolveIdentityOptions{Partition: container})
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
			if target.cmdlet == "Get-ADOrganizationalUnit" {
				wrong = fixture.UnicodeUser.DN
			}
			if target.cmdlet == "Get-ADObject" {
				// The generic read accepts any class by design, so the
				// mismatch it must refuse is a malformed identity instead.
				wrong = ""
				if _, buildErr := IdentityByDN("this is not a distinguished name"); buildErr != nil {
					o.WrongClassRefused = true
					o.WrongClassDetail = "construct: " + buildErr.Error()
				}
			}
			if wrong != "" {
				identity, buildErr := IdentityByDN(wrong)
				if buildErr != nil {
					o.WrongClassDetail = "construct: " + buildErr.Error()
					o.WrongClassRefused = true
				} else {
					guid, readErr := target.read(ctx, c, identity, ResolveIdentityOptions{})
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
			identity, buildErr := IdentityByGUID(fixture.MissingGUID)
			if buildErr != nil {
				o.MissingDetail = "construct: " + buildErr.Error()
			} else {
				guid, readErr := target.read(ctx, c, identity, ResolveIdentityOptions{})
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
		o.Passed = o.qualifies()
		if !o.Passed {
			fail("%s: identity observation incomplete: %+v", target.cmdlet, o)
		}
		artifact.Operations = append(artifact.Operations, o)
	}

	if !t.Failed() {
		stage = "complete"
	}
	t.Logf("identity form sweep over %d operations on %s; full ticket qualification remains incomplete",
		len(artifact.Operations), fixture.Server)
}
