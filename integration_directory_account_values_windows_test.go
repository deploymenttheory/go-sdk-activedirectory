//go:build windows && (amd64 || arm64)

package activedirectory

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"math"
	"os"
	"runtime"
	"slices"
	"strings"
	"testing"
	"time"
)

// Four property families on the three account classes, measured where a
// provider actually meets them: at create time and on an update.
//
// The generic write sweeps establish that a write lands and that a bad request
// is refused. They say nothing about what a *value* means, and these four
// families are where a provider's state and the directory come apart:
//
//   - an expiry sentinel read as an instant, or an unread field read as
//     "never", silently clears a caller's expiry
//   - certificate bytes routed through text validation are rejected or
//     corrupted, and an unrequested field mistaken for an empty one deletes
//     certificates nobody mentioned
//   - an SPN write that replaces where it should add drops service principal
//     names another team owns
//   - a property mapped to the wrong attribute writes where the reference
//     module would not have written at all
//
// Each family has its own observation and its own qualifies(), so a permissive
// aggregation in one cannot carry another.

// --- account-expiration-values ----------------------------------------------

type expirationObservation struct {
	Cmdlet string            `json:"cmdlet"`
	Role   writeEndpointRole `json:"role"`

	// A finite instant must survive as that exact instant. accountExpires
	// carries 100ns ticks, so a round-trip that agrees only to the second is
	// not the same claim.
	FiniteRoundTrip bool   `json:"finite_instant_round_tripped"`
	FiniteStamp     string `json:"finite_stamp"`
	// The same instant expressed in a non-UTC zone must produce that stamp,
	// not one shifted by the offset.
	ZoneAgnostic bool `json:"non_utc_zone_produced_the_same_stamp"`

	// Both documented never-expire sentinels must read as never, and a
	// never-expire value must not be presented as an instant.
	NeverZero      bool `json:"zero_reads_as_never"`
	NeverMax       bool `json:"max_int64_reads_as_never"`
	NeverNoInstant bool `json:"a_never_expire_value_carries_no_instant"`

	// Creating without mentioning expiry must leave the directory's own
	// default rather than a stamp the SDK chose.
	OmittedDefault      bool   `json:"create_without_expiry_left_the_directory_default"`
	OmittedDefaultStamp string `json:"create_default_stamp,omitempty"`

	// Clearing writes a sentinel. It is not a deletion and not the -1
	// instruction, and a caller that cleared must be able to see that it did.
	ClearedIsNever bool   `json:"cleared_reads_as_never"`
	ClearedStamp   string `json:"cleared_stamp,omitempty"`
	ClearedPresent bool   `json:"cleared_attribute_still_present"`

	// An update that does not mention expiry must leave it alone.
	OmittedUnchanged bool `json:"omitted_update_left_the_stamp_unchanged"`

	// The distinction a provider gets wrong first. Nil means "not read"; the
	// API documents that it does not mean never. Reading it as never would
	// clear a caller's expiry out of state on any partial read.
	UnreadIsNotNever bool `json:"an_unread_attribute_is_not_reported_as_never"`

	// Inputs the typed instant surface must refuse rather than adjust.
	SentinelRefused  bool   `json:"an_instant_mapping_onto_a_sentinel_was_refused"`
	SentinelClass    string `json:"sentinel_error_class,omitempty"`
	PrecisionRefused bool   `json:"a_sub_100ns_instant_was_refused"`
	PrecisionClass   string `json:"precision_error_class,omitempty"`

	Detail string `json:"detail,omitempty"`
	Passed bool   `json:"passed"`
}

func (o expirationObservation) qualifies() bool {
	// Shared by both roles: the sentinels, the finite instant, and the rule
	// that an unread value is not a never-expire reading.
	common := o.FiniteRoundTrip && o.ZoneAgnostic && o.NeverZero && o.NeverMax &&
		o.NeverNoInstant && o.UnreadIsNotNever
	request := func(class string) bool { return class == ClassInvalidRequest.String() }
	switch o.Role {
	case writeRoleCreate:
		return common && o.OmittedDefault
	case writeRoleUpdate:
		return common && o.ClearedIsNever && o.ClearedPresent && o.OmittedUnchanged &&
			o.SentinelRefused && request(o.SentinelClass) &&
			o.PrecisionRefused && request(o.PrecisionClass)
	}
	return false
}

// --- binary-certificate-values ----------------------------------------------

type certificateObservation struct {
	Cmdlet string            `json:"cmdlet"`
	Role   writeEndpointRole `json:"role"`

	// Two values whose bytes include NUL and 0xFF. That is the point: a
	// certificate is not directory text, and a binary attribute routed through
	// text validation would reject or truncate them.
	ByteExact   bool     `json:"every_byte_survived"`
	ValueCount  int      `json:"values_written"`
	Digests     []string `json:"value_digests"`
	ReadDigests []string `json:"readback_digests"`

	// The same bytes offered to a text-typed property must be refused. Without
	// this half, the byte-exact claim above could be a property of the
	// directory accepting anything rather than of the binary path.
	TextPathRefused bool   `json:"the_same_bytes_were_refused_by_a_text_property"`
	TextPathClass   string `json:"text_property_error_class,omitempty"`

	// Three retrieval states a caller must be able to tell apart: a loaded
	// set, a loaded empty set, and a field never requested. Reading the third
	// as the second is how a provider deletes certificates nobody mentioned.
	ClearedState   string `json:"state_after_clearing"`
	UnloadedState  string `json:"state_when_not_requested"`
	StatesDistinct bool   `json:"cleared_and_unrequested_are_distinguishable"`
	// A clear that leaves the attribute absent cannot be proved by a readback,
	// because absence is also what a denied read looks like, so the SDK
	// declines to call it verified. That is the documented outcome, not a
	// failure: the harness accepts it and then proves the effect with a read of
	// its own, which is the only thing that can settle it.
	ClearedUnverifiable bool   `json:"the_clear_was_reported_unverifiable"`
	ClearedDetail       string `json:"clear_detail,omitempty"`

	Detail string `json:"detail,omitempty"`
	Passed bool   `json:"passed"`
}

func (o certificateObservation) qualifies() bool {
	return o.ByteExact && o.ValueCount == 2 && len(o.Digests) == 2 &&
		slices.Equal(o.Digests, o.ReadDigests) &&
		o.TextPathRefused && o.TextPathClass == ClassInvalidRequest.String() &&
		o.StatesDistinct && o.ClearedState != "" && o.UnloadedState != "" &&
		o.ClearedState != o.UnloadedState
}

// --- spn-multivalue-constraints ---------------------------------------------

type spnObservation struct {
	Cmdlet string            `json:"cmdlet"`
	Role   writeEndpointRole `json:"role"`
	// Which door this class offers. User and computer have no typed service
	// principal name field; only the service account does. Recording the door
	// keeps the artifact from implying a uniform surface.
	Path string `json:"modification_path"`
	// What that door can express, which is not the same on both. The explicit
	// attribute-change path adds and removes individual values. The typed
	// property replaces the whole set, so on that path "kept the others" means
	// a replace that named them preserved them — the semantics the property
	// documents, and a weaker guarantee than an add. Recorded because a reader
	// who assumed the stronger one would write a provider that drops values.
	Semantics string `json:"value_semantics"`

	AddKeptOthers     bool `json:"adding_one_value_kept_the_others"`
	ReplaceSetExactly bool `json:"replacing_set_exactly_the_requested_values"`
	RemoveKeptOthers  bool `json:"removing_one_value_kept_the_others"`
	ClearEmptied      bool `json:"clearing_removed_every_value"`
	NonASCIIRoundTrip bool `json:"non_ascii_value_round_tripped"`

	// Forest-wide uniqueness is the constraint a caller cannot discover any
	// other way, and the one that makes an SPN write fail in production.
	ForeignRefused bool   `json:"a_value_owned_by_another_object_was_refused"`
	ForeignClass   string `json:"foreign_owner_error_class,omitempty"`
	ForeignDetail  string `json:"foreign_owner_detail,omitempty"`
	ForeignNoWrite bool   `json:"the_refused_write_changed_nothing"`

	// Clearing leaves the attribute absent, which no readback can prove, so
	// the SDK reports it unverifiable by design. The harness accepts that and
	// proves the effect with a read of its own.
	ClearUnverifiable bool   `json:"the_clear_was_reported_unverifiable"`
	ClearDetail       string `json:"clear_detail,omitempty"`

	// A value already present on this object. The directory answers, and the
	// harness records which answer rather than assuming one.
	DuplicateRefused bool   `json:"a_value_already_present_was_refused"`
	DuplicateClass   string `json:"duplicate_error_class,omitempty"`
	DuplicateDetail  string `json:"duplicate_detail,omitempty"`

	Detail string `json:"detail,omitempty"`
	Passed bool   `json:"passed"`
}

// directoryRefusal accepts only the classes that mean the directory itself
// rejected the value. A denial means permissions, and an uncertain outcome
// means the write may have landed — neither is a constraint observation.
func directoryRefusal(class string) bool {
	switch class {
	case ClassInvalidRequest.String(), ClassConflict.String(), ClassAlreadyExists.String():
		return true
	}
	return false
}

func (o spnObservation) qualifies() bool {
	intent := o.AddKeptOthers && o.ReplaceSetExactly && o.RemoveKeptOthers &&
		o.ClearEmptied && o.NonASCIIRoundTrip
	unique := o.ForeignRefused && o.ForeignNoWrite && directoryRefusal(o.ForeignClass)
	duplicate := o.DuplicateRefused && directoryRefusal(o.DuplicateClass)
	return intent && unique && duplicate && o.Semantics == spnSemantics(o.Path)
}

const (
	spnPathTyped    = "typed property"
	spnPathExplicit = "explicit attribute change"

	spnSemanticsReplace = "replace the whole set"
	spnSemanticsValues  = "add and remove individual values"
)

// spnSemantics is the one mapping from door to semantics. An observation whose
// recorded semantics disagree with its path has mislabelled what it measured,
// and must not pass on either reading.
func spnSemantics(path string) string {
	switch path {
	case spnPathTyped:
		return spnSemanticsReplace
	case spnPathExplicit:
		return spnSemanticsValues
	}
	return ""
}

// --- user-derived-property-roundtrips ---------------------------------------

type userPropertyField struct {
	Property  string `json:"property"`
	Attribute string `json:"attribute"`
	Path      string `json:"path"`
	RoundTrip bool   `json:"unicode_value_round_tripped"`
	Written   string `json:"written"`
	Read      string `json:"read"`
	// An update naming no property at all must leave this one alone, and the
	// properties written alongside it must still be there.
	OmittedUnchanged bool `json:"omitted_update_left_it_unchanged"`
	UnrelatedKept    bool `json:"unrelated_properties_survived"`
}

func (f userPropertyField) acceptable() bool {
	if f.Property == "" || f.Attribute == "" {
		return false
	}
	if f.Path != spnPathTyped && f.Path != spnPathExplicit {
		return false
	}
	return f.RoundTrip && f.OmittedUnchanged && f.UnrelatedKept
}

type userPropertyObservation struct {
	Cmdlet string              `json:"cmdlet"`
	Role   writeEndpointRole   `json:"role"`
	Fields []userPropertyField `json:"fields"`

	// The one validating property on the typed surface: a manager that is not
	// a distinguished name must be refused before any write, because the
	// attribute is a DN reference and a bad value cannot be repaired from the
	// caller's side.
	// What the write itself reported. A verification failure here is a real
	// disagreement, and the per-field readings below are what identify which
	// property caused it — so the harness records it and carries on rather
	// than returning an error that names nothing.
	WriteDetail string `json:"write_detail,omitempty"`
	WriteClass  string `json:"write_error_class,omitempty"`

	// The SDK's own TargetDN must be the name the directory reports, byte for
	// byte. A caller stores it and writes it back into DN-valued attributes
	// where the verification is byte-exact, so the submitted spelling would
	// make every one of those writes report an effect it could not confirm.
	TargetDNCanonical bool   `json:"target_dn_matches_the_directory"`
	TargetDNObserved  string `json:"target_dn,omitempty"`
	TargetDNReported  string `json:"directory_distinguished_name,omitempty"`
	// The name carried on the creation readback's search entry, recorded
	// separately from the directory's distinguishedName attribute because a
	// base-scoped search can echo the name the request supplied. Anything
	// relying on an entry name rather than the attribute inherits that.
	TargetDNEntryName string `json:"readback_entry_name,omitempty"`

	// A DN the caller spelled with a non-canonical attribute type addresses
	// the same object and is written correctly, but the byte-exact comparison
	// cannot confirm it. Recorded because a provider storing a hand-written DN
	// meets this, and because the reading it gets back is "uncertain" rather
	// than "unverified" — the write landed, and the class does not say so.
	NonCanonicalClass  string `json:"non_canonical_dn_error_class,omitempty"`
	NonCanonicalLanded bool   `json:"non_canonical_dn_write_landed_anyway"`

	ManagerRefused bool   `json:"a_manager_that_is_not_a_distinguished_name_was_refused"`
	ManagerClass   string `json:"manager_error_class,omitempty"`
	ManagerNoWrite bool   `json:"the_refused_manager_write_changed_nothing"`

	// Properties the reference module exposes that this typed surface does
	// not, and which therefore had to be driven through explicit attribute
	// changes. Recorded so the gap is visible in the evidence rather than
	// hidden behind a passing state.
	TypedGaps []string `json:"properties_without_a_typed_field,omitempty"`

	Detail string `json:"detail,omitempty"`
	Passed bool   `json:"passed"`
}

func (o userPropertyObservation) qualifies() bool {
	if len(o.Fields) == 0 {
		return false
	}
	for _, field := range o.Fields {
		if !field.acceptable() {
			return false
		}
	}
	// A non-canonical DN that did not land would be a far worse defect than
	// one that cannot be confirmed, so it is required to have landed.
	canonical := o.TargetDNCanonical && o.NonCanonicalLanded && o.NonCanonicalClass != ""
	return canonical && o.ManagerRefused && o.ManagerNoWrite &&
		o.ManagerClass == ClassInvalidRequest.String()
}

// --- shared read helpers ----------------------------------------------------

func accountValueStateName(state AttributeState) string {
	switch state {
	case AttributeUnloaded:
		return "unloaded"
	case AttributeAbsent:
		return "absent"
	case AttributePresent:
		return "present"
	case AttributePartial:
		return "partial"
	}
	return "unknown"
}

// accountValueRaw reads an attribute without sorting or converting it, which
// lifecycleValues deliberately does not offer: a byte-exact claim cannot be
// made against values that have been through a string round-trip and a sort.
func accountValueRaw(ctx context.Context, c *Client, id Identity, attribute string) ([][]byte, AttributeState, error) {
	observed, err := c.ResolveIdentity(ctx, id, ResolveIdentityOptions{Properties: []string{attribute}})
	if err != nil {
		return nil, AttributeUnloaded, err
	}
	if observed.Object == nil {
		return nil, AttributeUnloaded, ErrDirectoryObjectNotFound
	}
	values, state := observed.Object.Attribute(attribute)
	return values, state, nil
}

func accountValueDigests(values [][]byte) []string {
	digests := make([]string, 0, len(values))
	for _, value := range values {
		sum := sha256.Sum256(value)
		digests = append(digests, hex.EncodeToString(sum[:]))
	}
	return digests
}

func accountValueText(ctx context.Context, c *Client, id Identity, attribute string) (string, error) {
	values, _, err := accountValueRaw(ctx, c, id, attribute)
	if err != nil || len(values) == 0 {
		return "", err
	}
	return string(values[0]), nil
}

func accountValueSorted(ctx context.Context, c *Client, id Identity, attribute string) ([]string, AttributeState, error) {
	values, state, err := accountValueRaw(ctx, c, id, attribute)
	if err != nil {
		return nil, state, err
	}
	text := make([]string, 0, len(values))
	for _, value := range values {
		text = append(text, string(value))
	}
	slices.Sort(text)
	return text, state, nil
}

// accountExpiresStamp reads the raw accountExpires text, which is the only
// form that distinguishes the two never-expire sentinels from each other.
func accountExpiresStamp(ctx context.Context, c *Client, id Identity) (string, error) {
	return accountValueText(ctx, c, id, "accountExpires")
}

// --- the account classes ----------------------------------------------------

// accountValueTarget drives one account class through every family. The three
// classes are kept in one table for the same reason the lifecycle table exists:
// a per-class copy of these probes would drift, and a family measured on one
// class is not evidence for the others.
type accountValueTarget struct {
	kind, createCmdlet, updateCmdlet string
	// typedSPN records whether this class offers a typed service principal
	// name writer. Only the service account does.
	typedSPN bool

	// create makes the fixture. expires and attributes are both optional, so
	// one function serves the plain create, the create-with-expiry and the
	// create-with-certificates probes.
	create func(context.Context, *Client, Identity, string, *FileTime, map[string][]RawValue, ObjectMutationOptions) (ObjectMutationResult, error)
	// updateExpires writes the typed expiry field only.
	updateExpires func(context.Context, *Client, Identity, FileTime, ObjectMutationOptions) (ObjectMutationResult, error)
	// updateRaw writes explicit attribute changes only.
	updateRaw func(context.Context, *Client, Identity, []AttributeChange, ObjectMutationOptions) (ObjectMutationResult, error)
	// updateText writes one text property through the typed surface, which is
	// how the omitted-update half is shown to be a write that touched nothing
	// else rather than a write that did not happen.
	updateText func(context.Context, *Client, Identity, string, ObjectMutationOptions) (ObjectMutationResult, error)
	// updateSPNTyped is nil unless typedSPN.
	updateSPNTyped func(context.Context, *Client, Identity, []string, ObjectMutationOptions) (ObjectMutationResult, error)
}

func accountValueTargets() []accountValueTarget {
	text := func(value string) *string { return &value }
	return []accountValueTarget{
		{
			kind: "user", createCmdlet: "New-ADUser", updateCmdlet: "Set-ADUser",
			create: func(ctx context.Context, c *Client, parent Identity, name string, expires *FileTime, attrs map[string][]RawValue, o ObjectMutationOptions) (ObjectMutationResult, error) {
				result, err := c.CreateUser(ctx, CreateUserRequest{Parent: parent, Name: name,
					Properties: UserProperties{AccountExpires: expires}, Attributes: attrs, Options: o})
				return result.Creation, err
			},
			updateExpires: func(ctx context.Context, c *Client, id Identity, stamp FileTime, o ObjectMutationOptions) (ObjectMutationResult, error) {
				result, err := c.UpdateUser(ctx, UpdateUserRequest{Identity: id,
					Properties: UserProperties{AccountExpires: &stamp}, Options: o})
				return result.Mutation, err
			},
			updateRaw: func(ctx context.Context, c *Client, id Identity, changes []AttributeChange, o ObjectMutationOptions) (ObjectMutationResult, error) {
				result, err := c.UpdateUser(ctx, UpdateUserRequest{Identity: id, Changes: changes, Options: o})
				return result.Mutation, err
			},
			updateText: func(ctx context.Context, c *Client, id Identity, value string, o ObjectMutationOptions) (ObjectMutationResult, error) {
				result, err := c.UpdateUser(ctx, UpdateUserRequest{Identity: id,
					Properties: UserProperties{DisplayName: text(value)}, Options: o})
				return result.Mutation, err
			},
		},
		{
			kind: "computer", createCmdlet: "New-ADComputer", updateCmdlet: "Set-ADComputer",
			create: func(ctx context.Context, c *Client, parent Identity, name string, expires *FileTime, attrs map[string][]RawValue, o ObjectMutationOptions) (ObjectMutationResult, error) {
				result, err := c.CreateComputer(ctx, CreateComputerRequest{Parent: parent, Name: name,
					Properties: ComputerProperties{AccountExpires: expires}, Attributes: attrs, Options: o})
				return result.Creation, err
			},
			updateExpires: func(ctx context.Context, c *Client, id Identity, stamp FileTime, o ObjectMutationOptions) (ObjectMutationResult, error) {
				result, err := c.UpdateComputer(ctx, UpdateComputerRequest{Identity: id,
					Properties: ComputerProperties{AccountExpires: &stamp}, Options: o})
				return result.Mutation, err
			},
			updateRaw: func(ctx context.Context, c *Client, id Identity, changes []AttributeChange, o ObjectMutationOptions) (ObjectMutationResult, error) {
				result, err := c.UpdateComputer(ctx, UpdateComputerRequest{Identity: id, Changes: changes, Options: o})
				return result.Mutation, err
			},
			updateText: func(ctx context.Context, c *Client, id Identity, value string, o ObjectMutationOptions) (ObjectMutationResult, error) {
				result, err := c.UpdateComputer(ctx, UpdateComputerRequest{Identity: id,
					Properties: ComputerProperties{DisplayName: text(value)}, Options: o})
				return result.Mutation, err
			},
		},
		{
			kind: "service-account", createCmdlet: "New-ADServiceAccount", updateCmdlet: "Set-ADServiceAccount",
			typedSPN: true,
			create: func(ctx context.Context, c *Client, parent Identity, name string, expires *FileTime, attrs map[string][]RawValue, o ObjectMutationOptions) (ObjectMutationResult, error) {
				result, err := c.CreateServiceAccount(ctx, CreateServiceAccountRequest{
					Kind: ServiceAccountStandalone, Parent: parent, Name: name,
					Properties: ServiceAccountProperties{AccountExpires: expires}, Attributes: attrs, Options: o})
				return result.Creation, err
			},
			updateExpires: func(ctx context.Context, c *Client, id Identity, stamp FileTime, o ObjectMutationOptions) (ObjectMutationResult, error) {
				result, err := c.UpdateServiceAccount(ctx, UpdateServiceAccountRequest{Identity: id,
					Properties: ServiceAccountProperties{AccountExpires: &stamp}, Options: o})
				return result.Mutation, err
			},
			updateRaw: func(ctx context.Context, c *Client, id Identity, changes []AttributeChange, o ObjectMutationOptions) (ObjectMutationResult, error) {
				result, err := c.UpdateServiceAccount(ctx, UpdateServiceAccountRequest{Identity: id, Changes: changes, Options: o})
				return result.Mutation, err
			},
			updateText: func(ctx context.Context, c *Client, id Identity, value string, o ObjectMutationOptions) (ObjectMutationResult, error) {
				result, err := c.UpdateServiceAccount(ctx, UpdateServiceAccountRequest{Identity: id,
					Properties: ServiceAccountProperties{DisplayName: text(value)}, Options: o})
				return result.Mutation, err
			},
			updateSPNTyped: func(ctx context.Context, c *Client, id Identity, values []string, o ObjectMutationOptions) (ObjectMutationResult, error) {
				result, err := c.UpdateServiceAccount(ctx, UpdateServiceAccountRequest{Identity: id,
					Properties: ServiceAccountProperties{ServicePrincipalNames: &values}, Options: o})
				return result.Mutation, err
			},
		},
	}
}

// The two certificate values. Both carry a NUL and a 0xFF byte, which is what
// separates a binary attribute from a text one: validDirectoryText rejects NUL
// and invalid UTF-8, so these bytes cannot have gone through it.
func accountValueCertificates() [][]byte {
	first := []byte{0x30, 0x82, 0x01, 0x00, 0x02, 0x01, 0x00, 0xff, 0xfe, 0x7f, 0x80}
	second := []byte{0x30, 0x82, 0x02, 0x00, 0xff, 0xff, 0x00, 0x00, 0x01, 0xc0, 0x80, 0x41}
	return [][]byte{first, second}
}

// The outer harness supplies the endpoint and the write authorization only
// inside an owned run. This test mutates the directory: it creates one
// organizational unit of fixtures and removes it. Ordinary go test invocations
// skip it.
func TestDirectoryAccountValueSweepLab(t *testing.T) {
	endpoint := os.Getenv("ADSDK_ACCOUNTVALUE_ENDPOINT")
	if endpoint == "" {
		t.Skip("requires the opt-in isolated account value harness")
	}
	if os.Getenv("ADSDK_ACCOUNTVALUE_ALLOW_WRITES") != "yes" {
		t.Fatal("this harness mutates the directory and requires explicit write authorization")
	}
	resultPath := os.Getenv("ADSDK_ACCOUNTVALUE_RESULT")
	runID := os.Getenv("ADSDK_ACCOUNTVALUE_RUN_ID")
	if resultPath == "" || runID == "" {
		t.Fatal("an endpoint, a run identity and a fresh result path are required")
	}

	artifact := struct {
		SchemaVersion       int                       `json:"schema_version"`
		Scope               string                    `json:"scope"`
		RunID               string                    `json:"run_id"`
		Endpoint            string                    `json:"endpoint"`
		RuntimeOS           string                    `json:"runtime_os"`
		RuntimeArchitecture string                    `json:"runtime_architecture"`
		Started             time.Time                 `json:"started"`
		Finished            time.Time                 `json:"finished"`
		Passed              bool                      `json:"passed"`
		FullTicketComplete  bool                      `json:"full_ticket_complete"`
		FailureStage        string                    `json:"failure_stage,omitempty"`
		FixtureRoot         string                    `json:"fixture_root"`
		FixtureRootRemoved  bool                      `json:"fixture_root_removed"`
		Expiration          []expirationObservation   `json:"account_expiration_values"`
		Certificates        []certificateObservation  `json:"binary_certificate_values"`
		SPNs                []spnObservation          `json:"spn_multivalue_constraints"`
		UserProperties      []userPropertyObservation `json:"user_derived_property_roundtrips"`
	}{
		SchemaVersion: 1, Scope: "directory-account-values", RunID: runID,
		Endpoint: endpoint, RuntimeOS: runtime.GOOS, RuntimeArchitecture: runtime.GOARCH,
		Started: time.Now().UTC(),
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
			t.Error("cannot encode account value artifact")
			return
		}
		file, err := os.OpenFile(resultPath, os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0600)
		if err != nil {
			t.Error("cannot create fresh account value artifact")
			return
		}
		_, writeErr := file.Write(append(data, '\n'))
		if closeErr := file.Close(); writeErr != nil || closeErr != nil {
			t.Error("cannot finish account value artifact")
		}
	}()

	ctx, cancel := context.WithTimeout(context.Background(), 45*time.Minute)
	defer cancel()

	client, err := Dial(ctx, Config{Endpoint: Endpoint{Host: endpoint, Port: 389}, Timeout: 60 * time.Second})
	if err != nil {
		t.Fatal("native dial failed")
	}
	defer func() {
		if closeErr := client.Close(); closeErr != nil {
			t.Error("the owning client did not close cleanly")
		}
	}()

	stage = "fixture-root"
	root, err := client.RootDSE(ctx, RootDSEOptions{})
	if err != nil || root.DefaultNamingContext == nil || *root.DefaultNamingContext == "" {
		t.Fatal("the connection did not report a default naming context")
	}
	domainIdentity, err := IdentityByDN(*root.DefaultNamingContext)
	if err != nil {
		t.Fatal("the default naming context is not a usable identity")
	}
	rootResult, rootErr := client.CreateOrganizationalUnit(ctx, CreateOrganizationalUnitRequest{
		Parent: domainIdentity, Name: "sdk-accountvalue-" + runID,
		ProtectedFromAccidentalDeletion: new(bool),
	})
	if rootResult.Object.TargetGUID != nil {
		artifact.FixtureRoot = rootResult.Object.TargetDN
		fixture := objectGUIDIdentity(*rootResult.Object.TargetGUID)
		defer func() {
			removal, removeErr := client.DeleteOrganizationalUnit(ctx,
				DeleteOrganizationalUnitRequest{Identity: fixture, Recursive: true})
			artifact.FixtureRootRemoved = removeErr == nil && removal.AbsentAfter &&
				lifecycleAbsent(ctx, client, fixture)
			if !artifact.FixtureRootRemoved {
				t.Errorf("the fixture root was not proved removed: err=%v absentAfter=%v",
					removeErr, removal.AbsentAfter)
			}
		}()
	}
	if rootErr != nil || rootResult.Object.TargetGUID == nil {
		t.Fatalf("cannot create the fixture root: %v", rootErr)
	}
	fixtureRoot := objectGUIDIdentity(*rootResult.Object.TargetGUID)

	// One instant for every finite probe, at exactly 100ns precision so a
	// refusal cannot be blamed on the input.
	finite := time.Date(2031, time.March, 4, 5, 6, 7, 1_000_000, time.UTC)
	finiteStamp, stampErr := FileTimeFromTime(finite)
	if stampErr != nil {
		t.Fatalf("the harness instant is not representable: %v", stampErr)
	}

	for _, target := range accountValueTargets() {
		name := func(suffix string) string { return "sdkav-" + target.kind[:1] + suffix }

		// --- account-expiration-values, create role ----------------------
		stage = target.kind + "-expiration-create"
		create := expirationObservation{Cmdlet: target.createCmdlet, Role: writeRoleCreate}
		func() {
			// A create that names a finite expiry must produce that stamp.
			observe := ObjectMutationOptions{Properties: []string{"accountExpires"}}
			stampValue := finiteStamp
			result, err := target.create(ctx, client, fixtureRoot, name("exp1"), &stampValue, nil, observe)
			if err != nil || result.TargetGUID == nil {
				create.Detail = "finite create: " + lifecycleDetail(err)
				return
			}
			id := objectGUIDIdentity(*result.TargetGUID)
			read, readErr := client.AccountExpiration(ctx, id, ResolveIdentityOptions{})
			if readErr != nil || read.Expiration == nil {
				create.Detail = "finite readback: " + lifecycleDetail(readErr)
				return
			}
			create.FiniteStamp = finiteStamp.LDAPString()
			create.FiniteRoundTrip = read.Expiration.ExpiresAt != nil &&
				read.Expiration.ExpiresAt.Equal(finite) &&
				read.Expiration.NeverExpires != nil && !*read.Expiration.NeverExpires

			// The same instant in a non-UTC zone must map onto the same stamp.
			zone := time.FixedZone("harness+0530", 5*3600+1800)
			shifted, shiftErr := FileTimeFromTime(finite.In(zone))
			create.ZoneAgnostic = shiftErr == nil && shifted == finiteStamp

			// An unread attribute must not be reported as never-expire.
			observed, obsErr := client.ResolveIdentity(ctx, id, ResolveIdentityOptions{
				Properties: []string{"objectGUID"}})
			if obsErr == nil && observed.Object != nil {
				unread, decodeErr := decodeAccountExpiration(*observed.Object)
				create.UnreadIsNotNever = decodeErr == nil &&
					unread.Value == nil && unread.NeverExpires == nil
			}

			// Both sentinels, written at create time.
			for _, sentinel := range []struct {
				stamp FileTime
				set   *bool
			}{{0, &create.NeverZero}, {math.MaxInt64, &create.NeverMax}} {
				value := sentinel.stamp
				sResult, sErr := target.create(ctx, client, fixtureRoot,
					name("exp"+value.LDAPString()[:1]), &value, nil, observe)
				if sErr != nil || sResult.TargetGUID == nil {
					create.Detail += "; sentinel " + value.LDAPString() + ": " + lifecycleDetail(sErr)
					continue
				}
				sRead, sReadErr := client.AccountExpiration(ctx,
					objectGUIDIdentity(*sResult.TargetGUID), ResolveIdentityOptions{})
				if sReadErr != nil || sRead.Expiration == nil {
					continue
				}
				*sentinel.set = sRead.Expiration.NeverExpires != nil && *sRead.Expiration.NeverExpires
				create.NeverNoInstant = sRead.Expiration.ExpiresAt == nil
			}

			// A create that says nothing about expiry must leave the
			// directory's own default.
			plain, plainErr := target.create(ctx, client, fixtureRoot, name("expd"), nil, nil, observe)
			if plainErr == nil && plain.TargetGUID != nil {
				stamp, stampReadErr := accountExpiresStamp(ctx, client, objectGUIDIdentity(*plain.TargetGUID))
				create.OmittedDefaultStamp = stamp
				create.OmittedDefault = stampReadErr == nil && stamp != finiteStamp.LDAPString()
			}
		}()
		create.Passed = create.qualifies()
		if !create.Passed {
			fail("%s did not qualify for account-expiration-values: %+v", target.createCmdlet, create)
		}
		artifact.Expiration = append(artifact.Expiration, create)

		// --- account-expiration-values, update role ----------------------
		stage = target.kind + "-expiration-update"
		update := expirationObservation{Cmdlet: target.updateCmdlet, Role: writeRoleUpdate}
		func() {
			observe := ObjectMutationOptions{Properties: []string{"accountExpires"}}
			subject, err := target.create(ctx, client, fixtureRoot, name("expu"), nil, nil, observe)
			if err != nil || subject.TargetGUID == nil {
				update.Detail = "subject create: " + lifecycleDetail(err)
				return
			}
			id := objectGUIDIdentity(*subject.TargetGUID)

			// The dedicated instant API, which is the one a caller reaches for.
			if _, setErr := client.SetAccountExpiration(ctx, SetAccountExpirationRequest{
				Identity: id, At: finite}); setErr != nil {
				update.Detail = "set: " + lifecycleDetail(setErr)
			} else if read, readErr := client.AccountExpiration(ctx, id, ResolveIdentityOptions{}); readErr == nil && read.Expiration != nil {
				update.FiniteStamp = finiteStamp.LDAPString()
				update.FiniteRoundTrip = read.Expiration.ExpiresAt != nil &&
					read.Expiration.ExpiresAt.Equal(finite) &&
					read.Expiration.NeverExpires != nil && !*read.Expiration.NeverExpires
			}
			zone := time.FixedZone("harness-0800", -8*3600)
			shifted, shiftErr := FileTimeFromTime(finite.In(zone))
			update.ZoneAgnostic = shiftErr == nil && shifted == finiteStamp

			// An update that mentions no expiry at all must leave the stamp
			// where it is. A text write proves the update happened.
			before, _ := accountExpiresStamp(ctx, client, id)
			if _, textErr := target.updateText(ctx, client, id, "account value harness", observe); textErr == nil {
				after, afterErr := accountExpiresStamp(ctx, client, id)
				update.OmittedUnchanged = afterErr == nil && before != "" && after == before
			}

			// Clearing writes MaxInt64. It must read as never, and the
			// attribute must still be there to read.
			if _, clearErr := client.ClearAccountExpiration(ctx, id, observe); clearErr == nil {
				read, readErr := client.AccountExpiration(ctx, id, ResolveIdentityOptions{})
				stamp, stampErr := accountExpiresStamp(ctx, client, id)
				update.ClearedStamp = stamp
				update.ClearedPresent = stampErr == nil && stamp != ""
				update.ClearedIsNever = readErr == nil && read.Expiration != nil &&
					read.Expiration.NeverExpires != nil && *read.Expiration.NeverExpires
				update.NeverMax = update.ClearedIsNever && stamp == FileTime(math.MaxInt64).LDAPString()
				update.NeverNoInstant = readErr == nil && read.Expiration != nil &&
					read.Expiration.ExpiresAt == nil
			}

			// The other sentinel, through the typed field.
			if _, zeroErr := target.updateExpires(ctx, client, id, 0, observe); zeroErr == nil {
				read, readErr := client.AccountExpiration(ctx, id, ResolveIdentityOptions{})
				update.NeverZero = readErr == nil && read.Expiration != nil &&
					read.Expiration.NeverExpires != nil && *read.Expiration.NeverExpires
			}

			// An unread attribute is not a never-expire reading.
			observed, obsErr := client.ResolveIdentity(ctx, id, ResolveIdentityOptions{
				Properties: []string{"objectGUID"}})
			if obsErr == nil && observed.Object != nil {
				unread, decodeErr := decodeAccountExpiration(*observed.Object)
				update.UnreadIsNotNever = decodeErr == nil &&
					unread.Value == nil && unread.NeverExpires == nil
			}

			// An instant that maps onto a sentinel must be refused rather
			// than written as "never" behind the caller's back.
			sentinelInstant, _ := FileTime(math.MaxInt64).Time()
			if sentinelInstant.IsZero() {
				// MaxInt64 is a sentinel and carries no instant, so the
				// equivalent input is the epoch the zero stamp denotes.
				sentinelInstant = time.Date(1601, time.January, 1, 0, 0, 0, 0, time.UTC)
			}
			_, sentinelErr := client.SetAccountExpiration(ctx, SetAccountExpirationRequest{
				Identity: id, At: sentinelInstant})
			update.SentinelRefused = sentinelErr != nil
			update.SentinelClass = lifecycleClass(sentinelErr)

			// Sub-100ns precision must be refused, not truncated: a provider
			// that wrote a truncated stamp would re-plan the difference for
			// ever.
			_, precisionErr := client.SetAccountExpiration(ctx, SetAccountExpirationRequest{
				Identity: id, At: finite.Add(37 * time.Nanosecond)})
			update.PrecisionRefused = precisionErr != nil
			update.PrecisionClass = lifecycleClass(precisionErr)
		}()
		update.Passed = update.qualifies()
		if !update.Passed {
			fail("%s did not qualify for account-expiration-values: %+v", target.updateCmdlet, update)
		}
		artifact.Expiration = append(artifact.Expiration, update)

		// --- binary-certificate-values -----------------------------------
		for _, role := range []writeEndpointRole{writeRoleCreate, writeRoleUpdate} {
			stage = target.kind + "-certificates-" + string(role)
			o := certificateObservation{Cmdlet: target.createCmdlet, Role: role}
			if role == writeRoleUpdate {
				o.Cmdlet = target.updateCmdlet
			}
			func() {
				certificates := accountValueCertificates()
				o.ValueCount = len(certificates)
				o.Digests = accountValueDigests(certificates)
				raw := make([]RawValue, 0, len(certificates))
				for _, value := range certificates {
					raw = append(raw, NewRawValue(value))
				}
				observe := ObjectMutationOptions{Properties: []string{"userCertificate"}}

				var id Identity
				switch role {
				case writeRoleCreate:
					result, err := target.create(ctx, client, fixtureRoot, name("cc"),
						nil, map[string][]RawValue{"userCertificate": raw}, observe)
					if err != nil || result.TargetGUID == nil {
						o.Detail = "create: " + lifecycleDetail(err)
						return
					}
					id = objectGUIDIdentity(*result.TargetGUID)
				case writeRoleUpdate:
					result, err := target.create(ctx, client, fixtureRoot, name("cu"), nil, nil, observe)
					if err != nil || result.TargetGUID == nil {
						o.Detail = "subject create: " + lifecycleDetail(err)
						return
					}
					id = objectGUIDIdentity(*result.TargetGUID)
					if _, writeErr := target.updateRaw(ctx, client, id, []AttributeChange{{
						Attribute: "userCertificate", Kind: AttributeSet, Values: raw}}, observe); writeErr != nil {
						o.Detail = "update: " + lifecycleDetail(writeErr)
						return
					}
				}

				// Byte-exact, and in the order written. userCertificate has no
				// ordering guarantee, so the comparison is order-insensitive
				// over digests but value-exact over bytes.
				readValues, state, readErr := accountValueRaw(ctx, client, id, "userCertificate")
				if readErr != nil || state != AttributePresent {
					o.Detail += "; readback state " + accountValueStateName(state)
					return
				}
				o.ReadDigests = accountValueDigests(readValues)
				slices.Sort(o.Digests)
				slices.Sort(o.ReadDigests)
				exact := len(readValues) == len(certificates)
				for _, want := range certificates {
					found := false
					for _, got := range readValues {
						found = found || bytes.Equal(want, got)
					}
					exact = exact && found
				}
				o.ByteExact = exact

				// The same bytes through a text property must be refused.
				_, textErr := target.updateText(ctx, client, id, string(certificates[0]), observe)
				o.TextPathRefused = textErr != nil
				o.TextPathClass = lifecycleClass(textErr)

				// A cleared set and an unrequested field must be
				// distinguishable from each other.
				_, clearErr := target.updateRaw(ctx, client, id, []AttributeChange{{
					Attribute: "userCertificate", Kind: AttributeClear}}, observe)
				o.ClearedUnverifiable = errors.Is(clearErr, ErrObjectUnverifiable)
				o.ClearedDetail = lifecycleDetail(clearErr)
				if clearErr == nil || o.ClearedUnverifiable {
					_, clearedState, _ := accountValueRaw(ctx, client, id, "userCertificate")
					o.ClearedState = accountValueStateName(clearedState)
				}
				if observed, obsErr := client.ResolveIdentity(ctx, id, ResolveIdentityOptions{
					Properties: []string{"objectGUID"}}); obsErr == nil && observed.Object != nil {
					_, unloaded := observed.Object.Attribute("userCertificate")
					o.UnloadedState = accountValueStateName(unloaded)
				}
				o.StatesDistinct = o.ClearedState != "" && o.UnloadedState != "" &&
					o.ClearedState != o.UnloadedState
			}()
			o.Passed = o.qualifies()
			if !o.Passed {
				fail("%s did not qualify for binary-certificate-values: %+v", o.Cmdlet, o)
			}
			artifact.Certificates = append(artifact.Certificates, o)
		}

		// --- spn-multivalue-constraints ----------------------------------
		for _, role := range []writeEndpointRole{writeRoleCreate, writeRoleUpdate} {
			stage = target.kind + "-spn-" + string(role)
			o := spnObservation{Cmdlet: target.createCmdlet, Role: role, Path: spnPathExplicit}
			if role == writeRoleUpdate {
				o.Cmdlet = target.updateCmdlet
				if target.typedSPN {
					o.Path = spnPathTyped
				}
			}
			o.Semantics = spnSemantics(o.Path)
			func() {
				prefix := "sdkav" + target.kind[:1] + string(role[:1])
				first := prefix + "svc1/host.harness.invalid"
				second := prefix + "svc2/host.harness.invalid"
				third := prefix + "svc3/host.harness.invalid"
				// A non-ASCII service class exercises the text path rather
				// than the DN path, which is where an encoding bug would show.
				exotic := prefix + "sérviceé/høst.harness.invalid"
				observe := ObjectMutationOptions{Properties: []string{"servicePrincipalName"}}
				set := func(id Identity, values ...string) error {
					if o.Path == spnPathTyped {
						_, err := target.updateSPNTyped(ctx, client, id, values, observe)
						return err
					}
					change := AttributeChange{Attribute: "servicePrincipalName",
						Kind: AttributeSet, Values: lifecycleRawValues(values...)}
					if len(values) == 0 {
						change.Kind = AttributeClear
					}
					_, err := target.updateRaw(ctx, client, id, []AttributeChange{change}, observe)
					return err
				}

				// The subject starts with the first two values, written the
				// way this role writes them.
				var id Identity
				if role == writeRoleCreate {
					result, err := target.create(ctx, client, fixtureRoot, name("sc"), nil,
						map[string][]RawValue{"servicePrincipalName": lifecycleRawValues(first, second)}, observe)
					if err != nil || result.TargetGUID == nil {
						o.Detail = "create: " + lifecycleDetail(err)
						return
					}
					id = objectGUIDIdentity(*result.TargetGUID)
				} else {
					result, err := target.create(ctx, client, fixtureRoot, name("su"), nil, nil, observe)
					if err != nil || result.TargetGUID == nil {
						o.Detail = "subject create: " + lifecycleDetail(err)
						return
					}
					id = objectGUIDIdentity(*result.TargetGUID)
					if setErr := set(id, first, second); setErr != nil {
						o.Detail = "initial set: " + lifecycleDetail(setErr)
						return
					}
				}
				// The class may own service principal names of its own. They
				// are part of what must survive, so they are measured, not
				// assumed away.
				baseline, _, baseErr := accountValueSorted(ctx, client, id, "servicePrincipalName")
				if baseErr != nil {
					o.Detail = "baseline: " + lifecycleDetail(baseErr)
					return
				}

				// Add one value. Everything already there must survive, which
				// is the whole difference between an add and a replace.
				addErr := func() error {
					if o.Path == spnPathTyped {
						return set(id, append(slices.Clone(baseline), third)...)
					}
					_, err := target.updateRaw(ctx, client, id, []AttributeChange{{
						Attribute: "servicePrincipalName", Kind: AttributeAddValues,
						Values: lifecycleRawValues(third)}}, observe)
					return err
				}()
				if addErr == nil {
					after, _, _ := accountValueSorted(ctx, client, id, "servicePrincipalName")
					want := append(slices.Clone(baseline), third)
					slices.Sort(want)
					o.AddKeptOthers = slices.Equal(after, want)
				} else {
					o.Detail += "; add: " + lifecycleDetail(addErr)
				}

				// A value already present. The directory answers; the harness
				// records which answer.
				duplicateErr := func() error {
					if o.Path == spnPathTyped {
						return set(id, first, first)
					}
					_, err := target.updateRaw(ctx, client, id, []AttributeChange{{
						Attribute: "servicePrincipalName", Kind: AttributeAddValues,
						Values: lifecycleRawValues(first)}}, observe)
					return err
				}()
				o.DuplicateRefused = duplicateErr != nil
				o.DuplicateClass = lifecycleClass(duplicateErr)
				o.DuplicateDetail = lifecycleDetail(duplicateErr)

				// Replace with an exact set.
				if replaceErr := set(id, first, exotic); replaceErr == nil {
					after, _, _ := accountValueSorted(ctx, client, id, "servicePrincipalName")
					want := []string{first, exotic}
					slices.Sort(want)
					o.ReplaceSetExactly = slices.Equal(after, want)
					o.NonASCIIRoundTrip = slices.Contains(after, exotic)
				} else {
					o.Detail += "; replace: " + lifecycleDetail(replaceErr)
				}

				// Remove one of two. The other must survive.
				removeErr := func() error {
					if o.Path == spnPathTyped {
						return set(id, first)
					}
					_, err := target.updateRaw(ctx, client, id, []AttributeChange{{
						Attribute: "servicePrincipalName", Kind: AttributeRemoveValues,
						Values: lifecycleRawValues(exotic)}}, observe)
					return err
				}()
				if removeErr == nil {
					after, _, _ := accountValueSorted(ctx, client, id, "servicePrincipalName")
					o.RemoveKeptOthers = slices.Equal(after, []string{first})
				} else {
					o.Detail += "; remove: " + lifecycleDetail(removeErr)
				}

				// A value another object already owns. Service principal names
				// are unique forest-wide, and this is the constraint a caller
				// cannot discover from the schema.
				owner, ownerErr := target.create(ctx, client, fixtureRoot, name("so"+string(role[:1])), nil,
					map[string][]RawValue{"servicePrincipalName": lifecycleRawValues(
						prefix + "owned/host.harness.invalid")}, observe)
				if ownerErr != nil || owner.TargetGUID == nil {
					o.Detail += "; owner create: " + lifecycleDetail(ownerErr)
				} else {
					beforeForeign, _, _ := accountValueSorted(ctx, client, id, "servicePrincipalName")
					beforeVersion, versionErr := lifecycleVersion(ctx, client, id)
					foreignErr := func() error {
						if o.Path == spnPathTyped {
							return set(id, first, prefix+"owned/host.harness.invalid")
						}
						_, err := target.updateRaw(ctx, client, id, []AttributeChange{{
							Attribute: "servicePrincipalName", Kind: AttributeAddValues,
							Values: lifecycleRawValues(prefix + "owned/host.harness.invalid")}}, observe)
						return err
					}()
					o.ForeignRefused = foreignErr != nil
					o.ForeignClass = lifecycleClass(foreignErr)
					o.ForeignDetail = lifecycleDetail(foreignErr)
					afterForeign, _, _ := accountValueSorted(ctx, client, id, "servicePrincipalName")
					afterVersion, afterVersionErr := lifecycleVersion(ctx, client, id)
					// uSNChanged is the witness: it advances on any write the
					// directory accepted, so an unchanged counter is the
					// directory's own statement that nothing was written.
					o.ForeignNoWrite = slices.Equal(beforeForeign, afterForeign) &&
						versionErr == nil && afterVersionErr == nil &&
						beforeVersion.USNChanged == afterVersion.USNChanged
				}

				// Clear. Every value goes, including any the class owned.
				clearErr := set(id)
				o.ClearUnverifiable = errors.Is(clearErr, ErrObjectUnverifiable)
				o.ClearDetail = lifecycleDetail(clearErr)
				if clearErr == nil || o.ClearUnverifiable {
					after, state, _ := accountValueSorted(ctx, client, id, "servicePrincipalName")
					o.ClearEmptied = len(after) == 0 && state != AttributePresent
				} else {
					o.Detail += "; clear: " + lifecycleDetail(clearErr)
				}
			}()
			o.Passed = o.qualifies()
			if !o.Passed {
				fail("%s did not qualify for spn-multivalue-constraints: %+v", o.Cmdlet, o)
			}
			artifact.SPNs = append(artifact.SPNs, o)
		}
	}

	// --- user-derived-property-roundtrips -----------------------------------
	// Only the user class carries these properties, so this family claims
	// New-ADUser and Set-ADUser and nothing else.
	for _, role := range []writeEndpointRole{writeRoleCreate, writeRoleUpdate} {
		stage = "user-properties-" + string(role)
		o := userPropertyObservation{Cmdlet: "New-ADUser", Role: role}
		if role == writeRoleUpdate {
			o.Cmdlet = "Set-ADUser"
		}
		func() {
			// Unicode values throughout: a property that only round-trips
			// ASCII is a property that corrupts half the directories it meets.
			home := "\\\\fileserver.harness.invalid\\høme\\sdkav"
			drive := "H:"
			profile := "\\\\fileserver.harness.invalid\\pröfiles\\sdkav"
			country := "Sénégal"
			workstations := "WØRKST1,WØRKST2"
			observe := ObjectMutationOptions{Properties: []string{
				"homeDirectory", "homeDrive", "profilePath", "manager", "co", "userWorkstations"}}

			// Country and LogonWorkstations have no typed field on
			// UserProperties, so they are driven through explicit attribute
			// changes. The gap is recorded rather than papered over.
			o.TypedGaps = []string{"Country", "LogonWorkstations"}
			raw := map[string][]RawValue{
				"co":               lifecycleRawValues(country),
				"userWorkstations": lifecycleRawValues(workstations),
			}
			typed := UserProperties{
				HomeDirectory: &home, HomeDrive: &drive, ProfilePath: &profile,
			}

			// A manager the harness can point at, so the DN-valued property is
			// measured rather than skipped.
			manager, managerErr := client.CreateUser(ctx, CreateUserRequest{
				Parent: fixtureRoot, Name: "sdkav-mgr" + string(role[:1])})
			if managerErr != nil || manager.Creation.TargetDN == "" {
				o.Detail = "manager fixture: " + lifecycleDetail(managerErr)
				return
			}
			typed.ManagerDN = &manager.Creation.TargetDN
			// TargetDN is what a caller stores, so it must be what the
			// directory answers. Measured against the directory rather than
			// against the SDK's own composition of it.
			o.TargetDNObserved = manager.Creation.TargetDN
			if manager.Creation.After != nil {
				o.TargetDNEntryName = manager.Creation.After.DistinguishedName
			}
			o.TargetDNReported, _ = accountValueText(ctx, client,
				objectGUIDIdentity(*manager.Creation.TargetGUID), "distinguishedName")
			o.TargetDNCanonical = o.TargetDNReported != "" &&
				o.TargetDNObserved == o.TargetDNReported

			var id Identity
			switch role {
			case writeRoleCreate:
				result, err := client.CreateUser(ctx, CreateUserRequest{Parent: fixtureRoot,
					Name: "sdkav-pc" + string(role[:1]), Properties: typed, Attributes: raw, Options: observe})
				o.WriteDetail, o.WriteClass = lifecycleDetail(err), lifecycleClass(err)
				if result.Creation.TargetGUID == nil {
					o.Detail = "create produced no object: " + lifecycleDetail(err)
					return
				}
				id = objectGUIDIdentity(*result.Creation.TargetGUID)
			case writeRoleUpdate:
				result, err := client.CreateUser(ctx, CreateUserRequest{Parent: fixtureRoot,
					Name: "sdkav-pu" + string(role[:1])})
				if err != nil || result.Creation.TargetGUID == nil {
					o.Detail = "subject create: " + lifecycleDetail(err)
					return
				}
				id = objectGUIDIdentity(*result.Creation.TargetGUID)
				changes := make([]AttributeChange, 0, len(raw))
				for attribute, values := range raw {
					changes = append(changes, AttributeChange{Attribute: attribute,
						Kind: AttributeSet, Values: values})
				}
				_, updateErr := client.UpdateUser(ctx, UpdateUserRequest{Identity: id,
					Properties: typed, Changes: changes, Options: observe})
				o.WriteDetail, o.WriteClass = lifecycleDetail(updateErr), lifecycleClass(updateErr)
			}

			fields := []struct {
				property, attribute, path, written string
			}{
				{"HomeDirectory", "homeDirectory", spnPathTyped, home},
				{"HomeDrive", "homeDrive", spnPathTyped, drive},
				{"ProfilePath", "profilePath", spnPathTyped, profile},
				{"Manager", "manager", spnPathTyped, manager.Creation.TargetDN},
				{"Country", "co", spnPathExplicit, country},
				{"LogonWorkstations", "userWorkstations", spnPathExplicit, workstations},
			}
			// One update that mentions none of them, so "unchanged" is a
			// statement about a write that happened rather than about no write.
			readAll := func() map[string]string {
				values := map[string]string{}
				for _, field := range fields {
					text, _ := accountValueText(ctx, client, id, field.attribute)
					values[field.attribute] = text
				}
				return values
			}
			before := readAll()
			marker := "account value property harness"
			if _, err := client.UpdateUser(ctx, UpdateUserRequest{Identity: id,
				Properties: UserProperties{DisplayName: &marker}, Options: observe}); err != nil {
				o.Detail += "; unrelated update: " + lifecycleDetail(err)
			}
			after := readAll()

			for _, field := range fields {
				observedField := userPropertyField{
					Property: field.property, Attribute: field.attribute,
					Path: field.path, Written: field.written, Read: after[field.attribute],
				}
				observedField.RoundTrip = after[field.attribute] == field.written
				observedField.OmittedUnchanged = before[field.attribute] == after[field.attribute]
				// Every other property in the set is the unrelated state this
				// one must not have disturbed.
				kept := true
				for _, other := range fields {
					if other.attribute == field.attribute {
						continue
					}
					kept = kept && after[other.attribute] == other.written
				}
				observedField.UnrelatedKept = kept
				o.Fields = append(o.Fields, observedField)
			}

			// The same manager, spelled with a lower-case attribute type. It
			// is a valid distinguished name addressing the same object, so the
			// write must land; the byte-exact comparison cannot confirm it,
			// and what a caller gets told about that is the point.
			if lower, cut := strings.CutPrefix(manager.Creation.TargetDN, "CN="); cut {
				spelled := "cn=" + lower
				_, nonCanonicalErr := client.UpdateUser(ctx, UpdateUserRequest{Identity: id,
					Properties: UserProperties{ManagerDN: &spelled}, Options: observe})
				o.NonCanonicalClass = lifecycleClass(nonCanonicalErr)
				landed, _ := accountValueText(ctx, client, id, "manager")
				o.NonCanonicalLanded = strings.EqualFold(landed, spelled)
			}

			// A manager that is not a distinguished name. The typed surface
			// validates it, so this must be refused before any write.
			beforeVersion, versionErr := lifecycleVersion(ctx, client, id)
			bad := "not a distinguished name"
			_, managerRefusal := client.UpdateUser(ctx, UpdateUserRequest{Identity: id,
				Properties: UserProperties{ManagerDN: &bad}, Options: observe})
			o.ManagerRefused = managerRefusal != nil
			o.ManagerClass = lifecycleClass(managerRefusal)
			afterVersion, afterVersionErr := lifecycleVersion(ctx, client, id)
			current, _ := accountValueText(ctx, client, id, "manager")
			o.ManagerNoWrite = versionErr == nil && afterVersionErr == nil &&
				beforeVersion.USNChanged == afterVersion.USNChanged &&
				current == manager.Creation.TargetDN
		}()
		o.Passed = o.qualifies()
		if !o.Passed {
			fail("%s did not qualify for user-derived-property-roundtrips: %+v", o.Cmdlet, o)
		}
		artifact.UserProperties = append(artifact.UserProperties, o)
	}
}
