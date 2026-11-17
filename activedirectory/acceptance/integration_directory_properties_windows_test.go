//go:build windows && (amd64 || arm64)

package acceptance

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"os"
	"runtime"
	"slices"
	"strconv"
	"strings"
	"testing"
	"time"

	adengine "github.com/deploymenttheory/go-sdk-activedirectory/activedirectory/internal/engine"
	admodel "github.com/deploymenttheory/go-sdk-activedirectory/activedirectory/internal/model"
)

// propertySelection names the attribute shapes the selected-and-raw-properties
// scenario asks for, once, so the selection the harness sends and the states it
// later asserts cannot drift apart. Every name is an LDAP attribute description
// rather than a PowerShell property alias, because that is what this SDK sends.
type InternalPropertySelection struct {
	// binary is single-valued, 16 bytes, and present on every directory object.
	// It is the typed-conversion subject: GUID in, the same bytes back out.
	InternalBinary string
	// multiValued is present with at least two values on every object of every
	// class, so a multi-valued read is observable without a fixture.
	InternalMultiValued string
	// largeInteger and timestamp carry the precision claims. A 64-bit counter
	// must not be narrowed, and a generalized time must keep its exact
	// representation, including its fraction and zone.
	InternalLargeInteger, InternalTimestamp string
	// sid is class-dependent: security principals carry it and configuration
	// objects do not, so its round-trip is recorded as not applicable rather
	// than failed when the directory does not return it.
	InternalSid string
	// extension is an attribute a later schema extension introduced rather than
	// one from the original schema. Reading it is the schema-extension shape;
	// the harness cannot add a schema extension of its own because this scenario
	// is read-only and a schema extension is irreversible.
	InternalExtension string
	// sentinelCandidates are FILETIME attributes that commonly hold a sentinel
	// rather than an instant. The first one the lab actually holds is used.
	InternalSentinelCandidates []string
	// absentProbes are requested but expected to hold no value, so they come
	// back AttributeAbsent. unloadedProbes are deliberately never requested, so
	// they come back AttributeUnloaded. Both lists are candidates: a probe the
	// lab happens to populate, or one an operation's own default set already
	// requests, proves nothing and is skipped in favour of the next.
	InternalAbsentProbes, InternalUnloadedProbes []string
}

func InternalPropertyShapes() InternalPropertySelection {
	return InternalPropertySelection{
		InternalBinary:       "objectGUID",
		InternalMultiValued:  "objectClass",
		InternalLargeInteger: "uSNCreated",
		InternalTimestamp:    "whenCreated",
		InternalSid:          "objectSid",
		InternalExtension:    "msDS-SupportedEncryptionTypes",
		InternalSentinelCandidates: []string{
			"accountExpires",
			"pwdLastSet",
			"lockoutTime",
			"lastLogonTimestamp",
		},
		InternalAbsentProbes: []string{
			"carLicense",
			"roomNumber",
			"preferredLanguage",
			"houseIdentifier",
		},
		InternalUnloadedProbes: []string{
			"secretary",
			"businessCategory",
			"seeAlso",
			"employeeNumber",
		},
	}
}

// requested is the explicit selection. Every typed read in this SDK adds its own
// documented default set to the caller's selection rather than replacing it, so
// this list is a lower bound on what each operation asks the server for, and the
// unloaded probes are absent from it on purpose.
func (s InternalPropertySelection) InternalRequested() []string {
	selection := []string{
		"distinguishedName",
		"name",
		s.InternalBinary,
		s.InternalMultiValued,
		s.InternalLargeInteger,
		s.InternalTimestamp,
		s.InternalSid,
		s.InternalExtension,
	}
	selection = append(selection, s.InternalAbsentProbes...)
	return append(selection, s.InternalSentinelCandidates...)
}

// propertyObservation is one operation's selected-and-raw-properties result.
// Each field is a separate observation rather than an aggregate, so a reader can
// see which attribute shape a failure came from, and every read carries the
// reason it did not complete.
//
// Pointer fields are observations that may legitimately not apply to an
// operation: a class with no SID, a lab with no FILETIME sentinel, or a read
// that refuses the blanket wildcard by design. They are neutral when nil and
// load-bearing when set, so an inapplicable shape is never counted as evidence.
type InternalPropertyObservation struct {
	Cmdlet string `json:"cmdlet"`
	// Observable records whether the lab supplied the fixtures this scenario
	// needs at all: an object under the operation's container, a binary value,
	// a multi-valued attribute, and probes that genuinely distinguish absent
	// from unloaded. An operation without them is reported and excluded rather
	// than passed on checks that cannot fail.
	Observable bool `json:"observable"`
	// ReadsCompleted separates the two reasons an observation can be
	// incomplete. A read that did not finish is a failure of the operation and
	// must never be excused by excluding it as not observable; a lab that holds
	// no fixture for a shape is a gap in the lab. Only the second one is an
	// exclusion.
	ReadsCompleted bool   `json:"documented_reads_completed"`
	Subject        string `json:"subject_dn,omitempty"`

	DefaultRead       bool   `json:"default_property_set_read"`
	DefaultObjects    int    `json:"default_property_set_objects"`
	DefaultAttributes int    `json:"default_property_set_attributes"`
	DefaultDetail     string `json:"default_property_set_detail,omitempty"`

	SelectedRead     bool     `json:"selected_property_read"`
	SelectedNames    []string `json:"selected_properties"`
	SelectedRecorded bool     `json:"selected_properties_recorded"`
	SelectedDetail   string   `json:"selected_property_detail,omitempty"`

	WildcardRead       *bool    `json:"wildcard_read"`
	WildcardAttributes int      `json:"wildcard_attributes"`
	WildcardWidens     *bool    `json:"wildcard_widens_default_set"`
	WildcardRefused    bool     `json:"wildcard_selection_refused_by_sdk"`
	WildcardMissing    []string `json:"wildcard_missing_default_attributes,omitempty"`
	WildcardDetail     string   `json:"wildcard_detail,omitempty"`

	BinaryObservable   bool   `json:"binary_attribute_observable"`
	GUIDBytesRoundTrip bool   `json:"object_guid_bytes_round_trip"`
	GUIDTextRoundTrip  bool   `json:"object_guid_text_round_trip"`
	BinaryDetail       string `json:"binary_detail,omitempty"`
	SIDRoundTrip       *bool  `json:"object_sid_round_trip"`
	SIDDetail          string `json:"object_sid_detail,omitempty"`

	MultiValuedObservable bool   `json:"multi_valued_observable"`
	MultiValuedName       string `json:"multi_valued_attribute,omitempty"`
	MultiValuedCount      int    `json:"multi_valued_values"`
	MultiValuedPreserved  bool   `json:"multi_valued_values_preserved"`
	MultiValuedDetail     string `json:"multi_valued_detail,omitempty"`

	LargeIntegerRoundTrip bool   `json:"large_integer_round_trip"`
	TimestampRoundTrip    bool   `json:"generalized_time_round_trip"`
	PrecisionDetail       string `json:"precision_detail,omitempty"`

	SentinelName      string `json:"file_time_sentinel_attribute,omitempty"`
	SentinelValue     string `json:"file_time_sentinel_value,omitempty"`
	SentinelRoundTrip *bool  `json:"file_time_sentinel_round_trip"`

	ProbesObservable  bool   `json:"state_probes_observable"`
	AbsentName        string `json:"absent_attribute,omitempty"`
	UnloadedName      string `json:"unloaded_attribute,omitempty"`
	StatesDistinct    bool   `json:"present_absent_and_unloaded_distinct"`
	EmptyNotConflated bool   `json:"absent_and_unloaded_refuse_a_value"`
	StateDetail       string `json:"state_detail,omitempty"`

	ExtensionName     string `json:"schema_extension_attribute,omitempty"`
	ExtensionState    string `json:"schema_extension_state,omitempty"`
	ExtensionDefinite bool   `json:"schema_extension_state_definite"`
	ExtensionDetail   string `json:"schema_extension_detail,omitempty"`

	InvalidPropertyRefused  bool   `json:"invalid_property_selection_refused"`
	InvalidPropertyDetail   string `json:"invalid_property_detail,omitempty"`
	ReservedPropertyRefused bool   `json:"reserved_property_selection_refused"`
	ReservedPropertyDetail  string `json:"reserved_property_detail,omitempty"`
	MalformedValueRefused   bool   `json:"malformed_typed_value_refused"`
	MalformedValueDetail    string `json:"malformed_value_detail,omitempty"`

	Allocations int    `json:"native_allocations_remaining"`
	Detail      string `json:"detail,omitempty"`
	Passed      bool   `json:"passed"`
}

// qualifies keeps the whole scenario in one testable place. Both halves the
// coverage contract needs are here: the seven attribute shapes read and
// round-tripped, against three refusals. An aggregation that silently became
// permissive would make a future run report success regardless of what the
// directory did, and the artifact would look like evidence.
func (o InternalPropertyObservation) InternalQualifies() bool {
	wildcardHeld := (o.WildcardRead == nil || *o.WildcardRead) &&
		(o.WildcardWidens == nil || *o.WildcardWidens)
	sidHeld := o.SIDRoundTrip == nil || *o.SIDRoundTrip
	sentinelHeld := o.SentinelRoundTrip == nil || *o.SentinelRoundTrip
	return o.Observable && o.ReadsCompleted &&
		o.DefaultRead && o.SelectedRead && o.SelectedRecorded && wildcardHeld &&
		o.GUIDBytesRoundTrip && o.GUIDTextRoundTrip && sidHeld &&
		o.MultiValuedPreserved &&
		o.LargeIntegerRoundTrip && o.TimestampRoundTrip && sentinelHeld &&
		o.StatesDistinct && o.EmptyNotConflated && o.ExtensionDefinite &&
		o.InvalidPropertyRefused && o.ReservedPropertyRefused && o.MalformedValueRefused &&
		o.Allocations == 0
}

// propertyOutcome is one operation's verdict. The distinction that matters is
// between a read that broke and a lab that holds no fixture: the first is a
// failure of the operation and the second is an exclusion, and confusing them
// would turn every broken read into a silently skipped one.
type InternalPropertyOutcome int

const (
	InternalPropertyFailed InternalPropertyOutcome = iota
	InternalPropertyExcluded
	InternalPropertyQualified
)

func (o InternalPropertyObservation) InternalOutcome() InternalPropertyOutcome {
	switch {
	case !o.ReadsCompleted:
		return InternalPropertyFailed
	case !o.Observable:
		return InternalPropertyExcluded
	case !o.InternalQualifies():
		return InternalPropertyFailed
	}
	return InternalPropertyQualified
}

// propertyStateName names a retrieval state for the artifact. The four states
// are the scenario's subject, so recording a number would make the evidence
// unreadable and a renumbering silent.
func InternalPropertyStateName(state admodel.AttributeState) string {
	switch state {
	case admodel.AttributeUnloaded:
		return "unloaded"
	case admodel.AttributeAbsent:
		return "absent"
	case admodel.AttributePresent:
		return "present"
	case admodel.AttributePartial:
		return "partial"
	}
	return "unrecognised"
}

// propertySubject pins one entry for every read in this scenario, so the
// default, selected and wildcard observations describe the same object rather
// than whatever the server happened to return first. The lowest distinguished
// name is an arbitrary but stable choice.
func InternalPropertySubject(objects []admodel.Object) (admodel.Object, bool) {
	chosen, found := admodel.Object{}, false
	for _, object := range objects {
		if object.DistinguishedName == "" {
			continue
		}
		if !found || object.DistinguishedName < chosen.DistinguishedName {
			chosen, found = object, true
		}
	}
	return chosen, found
}

func InternalPropertyEntry(objects []admodel.Object, dn string) (admodel.Object, bool) {
	for _, object := range objects {
		if strings.EqualFold(object.DistinguishedName, dn) {
			return object, true
		}
	}
	return admodel.Object{}, false
}

// propertyProbes resolves the two states that cannot be fabricated from a read
// alone. A probe the lab populated is not evidence of absence, and a probe an
// operation's own default set already requests cannot be unloaded, so each list
// is tried in order and an empty result means the distinction is not observable
// here rather than that it failed.
func InternalPropertyProbes(
	subject admodel.Object,
	absentProbes, unloadedProbes []string,
) (absent, unloaded string) {
	for _, name := range absentProbes {
		if _, state := subject.Attribute(name); state == admodel.AttributeAbsent {
			absent = name
			break
		}
	}
	for _, name := range unloadedProbes {
		if _, state := subject.Attribute(name); state == admodel.AttributeUnloaded {
			unloaded = name
			break
		}
	}
	return absent, unloaded
}

// propertyStatesDistinct is the heart of the scenario. One object must report
// three different states for three names: a value that was returned, a name that
// was asked for and not returned, and a name that was never asked for. The last
// two both carry no values, so only the state separates them; collapsing either
// into the other would make an unloaded attribute indistinguishable from an
// unset one, and a caller would write a wrong decision from it.
func InternalPropertyStatesDistinct(
	subject admodel.Object,
	present, absent, unloaded string,
) (bool, string) {
	if absent == "" || unloaded == "" {
		return false, "no probe distinguished absent from unloaded"
	}
	presentValues, presentState := subject.Attribute(present)
	absentValues, absentState := subject.Attribute(absent)
	unloadedValues, unloadedState := subject.Attribute(unloaded)
	switch {
	case presentState != admodel.AttributePresent || len(presentValues) == 0:
		return false, present + " is " + InternalPropertyStateName(presentState) + " with no value"
	case absentState != admodel.AttributeAbsent || absentValues != nil:
		return false, absent + " is " + InternalPropertyStateName(
			absentState,
		) + " rather than absent"
	case unloadedState != admodel.AttributeUnloaded || unloadedValues != nil:
		return false, unloaded + " is " + InternalPropertyStateName(
			unloadedState,
		) + " rather than unloaded"
	case absentState == unloadedState:
		return false, "absent and unloaded share one state"
	}
	return true, ""
}

// propertyNoEmptyValue proves neither an absent nor an unloaded attribute is
// presented as a value, not even as an empty one: both carry no values at all,
// and Single refuses both for the same stated reason rather than returning a
// zero RawValue a caller would read as an empty directory value.
func InternalPropertyNoEmptyValue(subject admodel.Object, names ...string) (bool, string) {
	for _, name := range names {
		if name == "" {
			return false, "no probe to check"
		}
		values := subject.Values(name)
		if len(values.Values) != 0 {
			return false, name + " carried values"
		}
		if _, err := values.Single(); !errors.Is(err, admodel.ErrAttributeUnavailable) {
			return false, name + " did not refuse a single value"
		}
	}
	return true, ""
}

// propertyMultiValuePreserved checks a multi-valued read keeps every value, in
// the order the server sent them, with its bytes unchanged. Duplicates are
// retained deliberately, so a deduplicating projection would be caught here.
func InternalPropertyMultiValuePreserved(subject admodel.Object, name string) (int, bool, string) {
	raw, state := subject.Attribute(name)
	if state != admodel.AttributePresent {
		return len(raw), false, name + " is " + InternalPropertyStateName(state)
	}
	if len(raw) < 2 {
		return len(raw), false, "not multi-valued in this directory"
	}
	values := subject.Values(name)
	if len(values.Values) != len(raw) {
		return len(raw), false, "value count changed in projection"
	}
	for i := range raw {
		if !bytes.Equal(values.Values[i].Bytes(), raw[i]) {
			return len(raw), false, "value order or content changed in projection"
		}
		if _, err := values.Values[i].Text(); err != nil {
			return len(raw), false, err.Error()
		}
	}
	return len(raw), true, ""
}

// propertyGUIDRoundTrip reads a binary attribute as a typed GUID and back. The
// bytes must be returned unchanged, and the text form must parse back to the
// same value: the first three fields are little-endian, so a reversal applied
// once in each direction would otherwise cancel out unnoticed.
func InternalPropertyGUIDRoundTrip(value admodel.RawValue) (bool, bool, string) {
	guid, err := value.GUID()
	if err != nil {
		return false, false, err.Error()
	}
	held := bytes.Equal(guid.Bytes(), value.Bytes())
	parsed, err := admodel.ParseGUID(guid.String())
	if err != nil {
		return held, false, err.Error()
	}
	return held, parsed == guid, ""
}

func InternalPropertySIDRoundTrip(value admodel.RawValue) (bool, string) {
	sid, err := value.SID()
	if err != nil {
		return false, err.Error()
	}
	if !bytes.Equal(sid.Bytes(), value.Bytes()) {
		return false, "SID bytes were not preserved"
	}
	parsed, err := admodel.ParseSID(sid.String())
	if err != nil {
		return false, err.Error()
	}
	return parsed == sid, ""
}

// propertyLargeIntegerRoundTrip checks a 64-bit LDAP integer is not narrowed.
// Formatting the typed value must reproduce the server's own digits.
func InternalPropertyLargeIntegerRoundTrip(value admodel.RawValue) (bool, string) {
	text, err := value.Text()
	if err != nil {
		return false, err.Error()
	}
	number, err := value.Int64()
	if err != nil {
		return false, err.Error()
	}
	if strconv.FormatInt(number, 10) != text {
		return false, "precision lost: " + text + " became " + strconv.FormatInt(number, 10)
	}
	return true, ""
}

// propertyTimestampRoundTrip checks a generalized time keeps its exact
// representation, including fraction and zone, and still converts to an instant.
func InternalPropertyTimestampRoundTrip(value admodel.RawValue) (bool, string) {
	text, err := value.Text()
	if err != nil {
		return false, err.Error()
	}
	stamp, err := admodel.ParseGeneralizedTime(text)
	if err != nil {
		return false, err.Error()
	}
	if stamp.String() != text {
		return false, "representation not preserved: " + text + " became " + stamp.String()
	}
	if _, err := stamp.Time(); err != nil {
		return false, err.Error()
	}
	return true, ""
}

// propertySentinelRoundTrip finds a FILETIME sentinel the lab actually holds and
// checks it survives: Time refuses to invent an instant for it, and the original
// 64 bits come back as the server's own digits. A lab with no sentinel returns a
// nil result, which is recorded as not applicable rather than satisfied.
func InternalPropertySentinelRoundTrip(
	objects []admodel.Object,
	candidates []string,
) (string, string, *bool) {
	for _, object := range objects {
		for _, name := range candidates {
			value, err := object.Values(name).Single()
			if err != nil {
				continue
			}
			text, err := value.Text()
			if err != nil {
				continue
			}
			stamp, err := value.FileTime()
			if err != nil {
				continue
			}
			if _, err := stamp.Time(); !errors.Is(err, admodel.ErrValueSentinel) {
				continue
			}
			held := stamp.LDAPString() == text
			return name, text, &held
		}
	}
	return "", "", nil
}

// propertyFlagsPreserved checks every bit of a flag attribute survives. The SDK
// documents both LDAP integer representations for a 32-bit mask, so either set
// of digits is a faithful reproduction; a changed value is not.
func InternalPropertyFlagsPreserved(value admodel.RawValue) (bool, string) {
	text, err := value.Text()
	if err != nil {
		return false, err.Error()
	}
	flags, err := value.Flags32()
	if err != nil {
		return false, err.Error()
	}
	if flags.LDAPString() == text || strconv.FormatUint(uint64(flags), 10) == text {
		return true, ""
	}
	return false, "flag bits were not preserved: " + text + " became " + flags.LDAPString()
}

// propertySchemaExtension reads an attribute introduced by a later schema
// extension. Requesting it must yield a definite state — that is what
// AttributeAbsent exists for — and a returned value must survive as flags. An
// extension attribute the lab does not carry is still evidence: the selection
// was recorded, so the caller can tell "not set here" from "not asked for".
func InternalPropertySchemaExtension(subject admodel.Object, name string) (string, bool, string) {
	values := subject.Values(name)
	state := InternalPropertyStateName(values.State)
	switch values.State {
	case admodel.AttributeAbsent:
		return state, true, ""
	case admodel.AttributePresent:
		value, err := values.Single()
		if err != nil {
			// A multi-valued extension attribute is still a definite state;
			// only its single-value projection does not apply.
			return state, true, err.Error()
		}
		held, detail := InternalPropertyFlagsPreserved(value)
		return state, held, detail
	}
	return state, false, "the selection was not recorded"
}

// propertyWildcardWidens compares one entry read twice. "*" asks for the
// server's user attributes, so it must return strictly more than the operation's
// own default set. The default-set names the wildcard did not carry are recorded
// rather than failed: the wildcard is documented not to include every
// operational property, and which attributes are operational is schema
// information this SDK deliberately does not infer.
func InternalPropertyWildcardWidens(withDefaults, withWildcard admodel.Object) (bool, []string) {
	missing := make([]string, 0, len(withDefaults.Attributes))
	for name := range withDefaults.Attributes {
		if _, found := withWildcard.Attributes[name]; !found {
			missing = append(missing, name)
		}
	}
	slices.Sort(missing)
	return len(withWildcard.Attributes) > len(withDefaults.Attributes), missing
}

// propertyMalformedRefused is the failure half applied to values the directory
// actually returned. A conversion is never inferred from an attribute name, so a
// generalized time asked for as a FILETIME must be refused rather than guessed;
// a truncated GUID must not be padded into a plausible one in either its binary
// or its text form.
func InternalPropertyMalformedRefused(binary, timestamp admodel.RawValue) (bool, string) {
	raw := binary.Bytes()
	if len(raw) == 0 {
		return false, "no binary value to malform"
	}
	if _, err := admodel.GUIDFromBytes(raw[:len(raw)-1]); !errors.Is(err, admodel.ErrInvalidValue) {
		return false, "a truncated binary GUID was accepted"
	}
	guid, err := binary.GUID()
	if err != nil {
		return false, err.Error()
	}
	text := guid.String()
	if _, err := admodel.ParseGUID(text[:len(text)-1]); !errors.Is(err, admodel.ErrInvalidValue) {
		return false, "a truncated GUID text form was accepted"
	}
	if _, err := timestamp.FileTime(); !errors.Is(err, admodel.ErrInvalidValue) {
		return false, "a generalized time was accepted as a FILETIME"
	}
	return true, ""
}

// The outer harness supplies the endpoint only inside an owned run. This test
// never starts PowerShell, mutates the directory, or operates a VM; every call
// is a paged read and no attribute is written. Ordinary go test invocations skip
// it.
//
// It qualifies selected-and-raw-properties across the same operation table the
// endpoint and query sweeps use. Both halves the coverage contract needs are
// observed: the documented default property set, an explicit selection, the "*"
// wildcard, a binary attribute through its typed conversion, a multi-valued
// attribute, an absent attribute, a schema-extension attribute and a FILETIME
// sentinel, against an invalid property selection, a reserved one, and typed
// conversions refusing malformed directory values.
func TestDirectoryPropertySweepLab(t *testing.T) {
	endpoint := os.Getenv("ADSDK_PROPERTIES_ENDPOINT")
	if endpoint == "" {
		t.Skip("requires the opt-in isolated directory property harness")
	}
	resultPath := os.Getenv("ADSDK_PROPERTIES_RESULT")
	runID := os.Getenv("ADSDK_PROPERTIES_RUN_ID")
	if resultPath == "" || runID == "" {
		t.Fatal("an endpoint, a run identity and a fresh result path are required")
	}
	shapes := InternalPropertyShapes()
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
		Selection           []string                      `json:"explicit_selection"`
		Qualified           []string                      `json:"qualified_operations"`
		Excluded            []string                      `json:"excluded_operations"`
		Operations          []InternalPropertyObservation `json:"operations"`
	}{
		SchemaVersion: 1, Scope: "directory-selected-and-raw-properties", RunID: runID,
		Endpoint: endpoint, RuntimeOS: runtime.GOOS, RuntimeArchitecture: runtime.GOARCH,
		Started: time.Now().UTC(), Selection: shapes.InternalRequested(),
		Qualified: []string{}, Excluded: []string{}, Operations: []InternalPropertyObservation{},
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
			t.Error("cannot encode property artifact")
			return
		}
		file, err := os.OpenFile(resultPath, os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0o600)
		if err != nil {
			t.Error("cannot create fresh property artifact")
			return
		}
		_, writeErr := file.Write(append(data, '\n'))
		if closeErr := file.Close(); writeErr != nil || closeErr != nil {
			t.Error("cannot finish property artifact")
		}
	}()

	ctx, cancel := context.WithTimeout(context.Background(), 15*time.Minute)
	defer cancel()

	// withSession dials the endpoint, runs the observations for one operation
	// against it, and closes it. The allocation total is returned so a leak is
	// attributed to the operation that caused it.
	withSession := func(fn func(*adengine.Client)) (int, error) {
		client, err := adengine.Dial(
			ctx,
			admodel.Config{
				Endpoint: admodel.Endpoint{Host: endpoint, Port: 389},
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

	stage = "default-naming-context"
	defaultNC := ""
	if _, err := withSession(func(c *adengine.Client) {
		root, readErr := c.RootDSE(ctx, admodel.RootDSEOptions{})
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
	for _, target := range InternalEndpointSweepTargets() {
		o := InternalPropertyObservation{
			Cmdlet:        target.InternalCmdlet,
			SelectedNames: shapes.InternalRequested(),
		}

		// A base every read in the table can serve, and an explicit scope.
		// The typed plural reads default an empty base to the default naming
		// context but never set Scope, so the caller's zero value leaves it at
		// ScopeBase and an unscoped call reads only the partition head. A
		// domain-scoped read is given the Users container as a subtree rather
		// than the domain root: the root holds subordinate naming contexts
		// whose references this SDK reports rather than chases, so a
		// whole-domain subtree read is deliberately incomplete. The
		// container-scoped reads pin their own base and scope and ignore this.
		base := admodel.SearchOptions{PageSize: 64}
		if target.InternalDomainScoped {
			base = admodel.SearchOptions{
				Base:     "CN=Users," + defaultNC,
				Scope:    admodel.ScopeSubtree,
				PageSize: 64,
			}
		}
		with := func(properties []string) admodel.SearchOptions {
			options := base
			options.Properties = properties
			return options
		}

		leaked, err := withSession(func(c *adengine.Client) {
			// The documented default property set: no selection at all, so each
			// operation asks for exactly what it documents.
			defaults, readErr := target.InternalRead(ctx, c, with(nil))
			o.DefaultRead = readErr == nil && defaults.Complete
			o.DefaultObjects = len(defaults.Objects)
			o.DefaultDetail = InternalSweepDetail(readErr, defaults)
			subject, found := InternalPropertySubject(defaults.Objects)
			if !found {
				// Nothing under this operation's container. Every remaining
				// observation would be about an object that does not exist, so
				// the operation is excluded rather than failed — but only if the
				// read itself finished.
				o.ReadsCompleted = o.DefaultRead
				return
			}
			o.Subject = subject.DistinguishedName
			o.DefaultAttributes = len(subject.Attributes)

			// An explicit selection. Each operation adds its own default set to
			// it rather than replacing it, so the request is a superset of this
			// list and every name in the list must come back with a definite
			// state.
			selected, readErr := target.InternalRead(ctx, c, with(shapes.InternalRequested()))
			o.SelectedRead = readErr == nil && selected.Complete
			o.SelectedDetail = InternalSweepDetail(readErr, selected)
			chosen, ok := InternalPropertyEntry(selected.Objects, subject.DistinguishedName)
			if !ok {
				o.SelectedDetail += " subject absent from the selected read"
				return
			}
			o.SelectedRecorded = true
			for _, name := range shapes.InternalRequested() {
				if _, state := chosen.Attribute(name); state == admodel.AttributeUnloaded {
					o.SelectedRecorded = false
					o.SelectedDetail += " " + name + " was not recorded as requested"
				}
			}

			// The wildcard. One read in this table refuses it before contacting
			// the directory, because "*" on a managed service account would ask
			// for its managed password material; that refusal is recorded as a
			// refusal and the widening observation does not apply. An operation
			// that refuses the wildcard still has to honour the explicit
			// selection above, which is asserted either way, so the refusal
			// cannot be used to skip the scenario.
			wildcard, readErr := target.InternalRead(ctx, c, with([]string{"*"}))
			if errors.Is(readErr, admodel.ErrInvalidProperty) {
				o.WildcardRefused = true
				o.WildcardDetail = readErr.Error()
			} else {
				read := readErr == nil && wildcard.Complete
				o.WildcardRead = &read
				o.WildcardDetail = InternalSweepDetail(readErr, wildcard)
				if wide, ok := InternalPropertyEntry(
					wildcard.Objects,
					subject.DistinguishedName,
				); ok {
					o.WildcardAttributes = len(wide.Attributes)
					widens, missing := InternalPropertyWildcardWidens(subject, wide)
					o.WildcardWidens, o.WildcardMissing = &widens, missing
				} else {
					withheld := false
					o.WildcardWidens = &withheld
					o.WildcardDetail += " subject absent from the wildcard read"
				}
			}

			// A binary attribute through its typed conversion.
			binary, binaryErr := chosen.Values(shapes.InternalBinary).Single()
			o.BinaryObservable = binaryErr == nil
			if binaryErr != nil {
				o.BinaryDetail = binaryErr.Error()
			} else {
				o.GUIDBytesRoundTrip, o.GUIDTextRoundTrip, o.BinaryDetail = InternalPropertyGUIDRoundTrip(
					binary,
				)
			}

			// A SID is class-dependent, so it is observed only where the
			// directory returned one.
			if sid, sidErr := chosen.Values(shapes.InternalSid).Single(); sidErr == nil {
				held, detail := InternalPropertySIDRoundTrip(sid)
				o.SIDRoundTrip, o.SIDDetail = &held, detail
			}

			// A multi-valued attribute.
			o.MultiValuedName = shapes.InternalMultiValued
			o.MultiValuedCount, o.MultiValuedPreserved, o.MultiValuedDetail = InternalPropertyMultiValuePreserved(
				chosen,
				shapes.InternalMultiValued,
			)
			o.MultiValuedObservable = o.MultiValuedCount >= 2

			// Precision: a 64-bit counter and an exact timestamp.
			largeInteger, largeErr := chosen.Values(shapes.InternalLargeInteger).Single()
			timestamp, timeErr := chosen.Values(shapes.InternalTimestamp).Single()
			switch {
			case largeErr != nil:
				o.PrecisionDetail = shapes.InternalLargeInteger + ": " + largeErr.Error()
			case timeErr != nil:
				o.PrecisionDetail = shapes.InternalTimestamp + ": " + timeErr.Error()
			default:
				var detail string
				o.LargeIntegerRoundTrip, detail = InternalPropertyLargeIntegerRoundTrip(
					largeInteger,
				)
				o.PrecisionDetail = detail
				o.TimestampRoundTrip, detail = InternalPropertyTimestampRoundTrip(timestamp)
				if detail != "" {
					o.PrecisionDetail += " " + detail
				}
			}

			// A sentinel, where the lab holds one.
			o.SentinelName, o.SentinelValue, o.SentinelRoundTrip = InternalPropertySentinelRoundTrip(
				selected.Objects,
				shapes.InternalSentinelCandidates,
			)

			// Absent against unloaded: the distinction this scenario exists for.
			o.AbsentName, o.UnloadedName = InternalPropertyProbes(
				chosen,
				shapes.InternalAbsentProbes,
				shapes.InternalUnloadedProbes,
			)
			o.ProbesObservable = o.AbsentName != "" && o.UnloadedName != ""
			var reasons []string
			distinct, detail := InternalPropertyStatesDistinct(
				chosen,
				shapes.InternalMultiValued,
				o.AbsentName,
				o.UnloadedName,
			)
			o.StatesDistinct = distinct
			if detail != "" {
				reasons = append(reasons, detail)
			}
			empty, detail := InternalPropertyNoEmptyValue(chosen, o.AbsentName, o.UnloadedName)
			o.EmptyNotConflated = empty
			if detail != "" {
				reasons = append(reasons, detail)
			}
			o.StateDetail = strings.Join(reasons, "; ")

			// A schema-extension attribute.
			o.ExtensionName = shapes.InternalExtension
			o.ExtensionState, o.ExtensionDefinite, o.ExtensionDetail = InternalPropertySchemaExtension(
				chosen,
				shapes.InternalExtension,
			)

			// The failure half. An invalid attribute description and a reserved
			// selection must both be refused by the SDK before the directory is
			// asked, and typed conversions must refuse malformed values rather
			// than guess at them.
			_, readErr = target.InternalRead(ctx, c, with([]string{"not a property"}))
			o.InvalidPropertyRefused = errors.Is(readErr, admodel.ErrInvalidProperty)
			if readErr != nil {
				o.InvalidPropertyDetail = readErr.Error()
			}
			_, readErr = target.InternalRead(ctx, c, with([]string{"1.1", "cn"}))
			o.ReservedPropertyRefused = errors.Is(readErr, admodel.ErrInvalidProperty)
			if readErr != nil {
				o.ReservedPropertyDetail = readErr.Error()
			}
			if binaryErr == nil && timeErr == nil {
				o.MalformedValueRefused, o.MalformedValueDetail = InternalPropertyMalformedRefused(
					binary,
					timestamp,
				)
			} else {
				o.MalformedValueDetail = "no directory value to malform"
			}

			o.ReadsCompleted = o.DefaultRead && o.SelectedRead
		})
		if err != nil {
			// A session that could not be dialled or could not be closed leaves
			// every observation above unattributable.
			o.Detail, o.ReadsCompleted = "session: "+err.Error(), false
		}
		o.Allocations = leaked
		// The fixtures this scenario needs. Without an object there is nothing
		// to read; without a binary value or a multi-valued attribute two of the
		// seven shapes cannot be observed; without both probes the absent and
		// unloaded states cannot be told apart, which is the whole point.
		o.Observable = o.DefaultObjects >= 1 && o.Subject != "" &&
			o.BinaryObservable && o.MultiValuedObservable && o.ProbesObservable
		o.Passed = o.InternalQualifies()
		switch o.InternalOutcome() {
		case InternalPropertyExcluded:
			// Not a failure of the SDK: the lab does not hold the fixtures this
			// operation's container would need. Recorded and excluded so the
			// artifact cannot be read as evidence for it.
			artifact.Excluded = append(artifact.Excluded, target.InternalCmdlet)
			t.Logf(
				"%s: not observable (%d object(s), binary=%t multi-valued=%t probes=%t); excluded",
				target.InternalCmdlet,
				o.DefaultObjects,
				o.BinaryObservable,
				o.MultiValuedObservable,
				o.ProbesObservable,
			)
		case InternalPropertyQualified:
			artifact.Qualified = append(artifact.Qualified, target.InternalCmdlet)
		default:
			fail("%s: property observation incomplete: %+v", target.InternalCmdlet, o)
		}
		artifact.Operations = append(artifact.Operations, o)
	}

	if len(artifact.Qualified) == 0 {
		fail("no operation in the table was observable; the run is not evidence for anything")
	}
	if !t.Failed() {
		stage = "complete"
	}
	t.Logf(
		"selected and raw property sweep over %d operations on %s: %d qualified, %d excluded; full ticket qualification remains incomplete",
		len(artifact.Operations),
		endpoint,
		len(artifact.Qualified),
		len(artifact.Excluded),
	)
}

// The decision logic above runs only inside an opt-in lab harness, so without
// these tests nothing exercises it. An aggregation that silently became
// permissive would make every future run report success regardless of what the
// directory did, and the lab artifact would look like evidence.

func InternalPassingPropertyObservation() InternalPropertyObservation {
	read, widens := true, true
	sid, sentinel := true, true
	return InternalPropertyObservation{
		Cmdlet:                  "Get-ADObject",
		Observable:              true,
		ReadsCompleted:          true,
		Subject:                 "CN=Administrator,CN=Users,DC=example,DC=test",
		DefaultRead:             true,
		DefaultObjects:          3,
		DefaultAttributes:       4,
		SelectedRead:            true,
		SelectedRecorded:        true,
		WildcardRead:            &read,
		WildcardAttributes:      27,
		WildcardWidens:          &widens,
		BinaryObservable:        true,
		GUIDBytesRoundTrip:      true,
		GUIDTextRoundTrip:       true,
		SIDRoundTrip:            &sid,
		MultiValuedObservable:   true,
		MultiValuedCount:        4,
		MultiValuedPreserved:    true,
		LargeIntegerRoundTrip:   true,
		TimestampRoundTrip:      true,
		SentinelRoundTrip:       &sentinel,
		ProbesObservable:        true,
		AbsentName:              "carLicense",
		UnloadedName:            "secretary",
		StatesDistinct:          true,
		EmptyNotConflated:       true,
		ExtensionDefinite:       true,
		InvalidPropertyRefused:  true,
		ReservedPropertyRefused: true,
		MalformedValueRefused:   true,
		Allocations:             0,
	}
}

// Every input must be load-bearing. Withholding any single one must withhold the
// qualification, including the native allocation balance.
func TestPropertyObservationRequiresEveryObservation(t *testing.T) {
	if !InternalPassingPropertyObservation().InternalQualifies() {
		t.Fatal("the fully satisfied observation does not qualify")
	}
	refused := false
	for _, mutation := range []struct {
		InternalName  string
		InternalApply func(*InternalPropertyObservation)
	}{
		{"observable fixtures", func(o *InternalPropertyObservation) { o.Observable = false }},
		{"documented reads completed", func(o *InternalPropertyObservation) { o.ReadsCompleted = false }},
		{"default property set read", func(o *InternalPropertyObservation) { o.DefaultRead = false }},
		{"selected property read", func(o *InternalPropertyObservation) { o.SelectedRead = false }},
		{"selection recorded", func(o *InternalPropertyObservation) { o.SelectedRecorded = false }},
		{"wildcard read", func(o *InternalPropertyObservation) { o.WildcardRead = &refused }},
		{"wildcard widens the default set", func(o *InternalPropertyObservation) { o.WildcardWidens = &refused }},
		{"binary bytes round-trip", func(o *InternalPropertyObservation) { o.GUIDBytesRoundTrip = false }},
		{"binary text round-trip", func(o *InternalPropertyObservation) { o.GUIDTextRoundTrip = false }},
		{"SID round-trip", func(o *InternalPropertyObservation) { o.SIDRoundTrip = &refused }},
		{"multi-valued values preserved", func(o *InternalPropertyObservation) { o.MultiValuedPreserved = false }},
		{"large integer round-trip", func(o *InternalPropertyObservation) { o.LargeIntegerRoundTrip = false }},
		{"generalized time round-trip", func(o *InternalPropertyObservation) { o.TimestampRoundTrip = false }},
		{"FILETIME sentinel round-trip", func(o *InternalPropertyObservation) { o.SentinelRoundTrip = &refused }},
		{"present, absent and unloaded distinct", func(o *InternalPropertyObservation) { o.StatesDistinct = false }},
		{"absent and unloaded refuse a value", func(o *InternalPropertyObservation) { o.EmptyNotConflated = false }},
		{"schema extension state definite", func(o *InternalPropertyObservation) { o.ExtensionDefinite = false }},
		{"invalid property refused", func(o *InternalPropertyObservation) { o.InvalidPropertyRefused = false }},
		{"reserved property refused", func(o *InternalPropertyObservation) { o.ReservedPropertyRefused = false }},
		{"malformed typed value refused", func(o *InternalPropertyObservation) { o.MalformedValueRefused = false }},
		{"native allocations balanced", func(o *InternalPropertyObservation) { o.Allocations = 1 }},
	} {
		t.Run(mutation.InternalName, func(t *testing.T) {
			o := InternalPassingPropertyObservation()
			mutation.InternalApply(&o)
			if o.InternalQualifies() {
				t.Fatalf("the observation still qualified without %q", mutation.InternalName)
			}
		})
	}
}

// Three observations do not apply to every operation: a class with no SID, a lab
// with no FILETIME sentinel, and a read that refuses the blanket wildcard by
// design. A nil must neither qualify an operation by itself nor excuse a
// required observation.
func TestPropertyObservationTreatsInapplicableShapesAsNeutral(t *testing.T) {
	o := InternalPassingPropertyObservation()
	o.WildcardRead, o.WildcardWidens, o.WildcardRefused = nil, nil, true
	o.SIDRoundTrip, o.SentinelRoundTrip = nil, nil
	if !o.InternalQualifies() {
		t.Fatal("an operation was disqualified for shapes its objects do not carry")
	}
	for _, mutation := range []struct {
		InternalName  string
		InternalApply func(*InternalPropertyObservation)
	}{
		{"selection recorded", func(o *InternalPropertyObservation) { o.SelectedRecorded = false }},
		{"states distinct", func(o *InternalPropertyObservation) { o.StatesDistinct = false }},
		{"invalid property refused", func(o *InternalPropertyObservation) { o.InvalidPropertyRefused = false }},
	} {
		t.Run(mutation.InternalName, func(t *testing.T) {
			withheld := o
			mutation.InternalApply(&withheld)
			if withheld.InternalQualifies() {
				t.Fatalf("an inapplicable shape excused %q", mutation.InternalName)
			}
		})
	}
}

// Exclusion exists for a lab that holds no fixture, never for a read that
// broke. If the two were confused, a sweep in which every read failed would
// report a clean run with every operation quietly skipped.
func TestPropertyOutcomeNeverExcusesABrokenRead(t *testing.T) {
	for _, test := range []struct {
		InternalName  string
		InternalApply func(*InternalPropertyObservation)
		InternalWant  InternalPropertyOutcome
	}{
		{"satisfied", func(*InternalPropertyObservation) {}, InternalPropertyQualified},
		{"no fixtures", func(o *InternalPropertyObservation) { o.Observable = false }, InternalPropertyExcluded},
		{"read did not complete", func(o *InternalPropertyObservation) { o.ReadsCompleted = false }, InternalPropertyFailed},
		{
			"read did not complete and no fixtures",
			func(o *InternalPropertyObservation) { o.ReadsCompleted, o.Observable = false, false },
			InternalPropertyFailed,
		},
		{"observed but not qualified", func(o *InternalPropertyObservation) { o.StatesDistinct = false }, InternalPropertyFailed},
	} {
		t.Run(test.InternalName, func(t *testing.T) {
			o := InternalPassingPropertyObservation()
			test.InternalApply(&o)
			if got := o.InternalOutcome(); got != test.InternalWant {
				t.Fatalf("outcome = %d, want %d", got, test.InternalWant)
			}
		})
	}
}

// A refused wildcard is only neutral because the explicit selection is still
// asserted. If the wildcard observation were dropped rather than recorded, a
// read that silently returned nothing for "*" would pass.
func TestPropertyObservationRejectsAnUnreadWildcard(t *testing.T) {
	o := InternalPassingPropertyObservation()
	read := false
	o.WildcardRead = &read
	if o.InternalQualifies() {
		t.Fatal("a wildcard read that did not complete still qualified")
	}
}

func TestPropertyStateNamesEveryState(t *testing.T) {
	for _, test := range []struct {
		InternalState admodel.AttributeState
		InternalWant  string
	}{
		{admodel.AttributeUnloaded, "unloaded"},
		{admodel.AttributeAbsent, "absent"},
		{admodel.AttributePresent, "present"},
		{admodel.AttributePartial, "partial"},
		{admodel.AttributeState(99), "unrecognised"},
	} {
		if got := InternalPropertyStateName(test.InternalState); got != test.InternalWant {
			t.Errorf("state %d named %q, want %q", test.InternalState, got, test.InternalWant)
		}
	}
}

// propertySubject must pin the same entry every run, or the default, selected
// and wildcard observations would silently describe different objects.
func TestPropertySubjectIsStable(t *testing.T) {
	objects := []admodel.Object{
		{DistinguishedName: "CN=Guest,CN=Users,DC=example,DC=test"},
		{DistinguishedName: ""},
		{DistinguishedName: "CN=Administrator,CN=Users,DC=example,DC=test"},
	}
	subject, found := InternalPropertySubject(objects)
	if !found || subject.DistinguishedName != "CN=Administrator,CN=Users,DC=example,DC=test" {
		t.Fatalf("subject = %q (found %t)", subject.DistinguishedName, found)
	}
	if _, found := InternalPropertySubject(nil); found {
		t.Fatal("an empty result produced a subject")
	}
	if _, found := InternalPropertySubject([]admodel.Object{{DistinguishedName: ""}}); found {
		t.Fatal("an object with no distinguished name was chosen as the subject")
	}
}

// propertyProbes must reject candidates that prove nothing: a probe the
// directory populated is not evidence of absence, and a probe the operation's
// own default set already requested cannot be unloaded.
func TestPropertyProbesSkipCandidatesThatProveNothing(t *testing.T) {
	subject := admodel.Object{
		DistinguishedName: "CN=Administrator,CN=Users,DC=example,DC=test",
		Attributes: map[string][][]byte{
			"carlicense":        {[]byte("AB-12-CD")},
			"businesscategory":  {[]byte("example")},
			"preferredlanguage": nil,
		},
		RequestedProperties: []string{"carLicense", "roomNumber", "secretary"},
	}
	// carLicense was requested but came back with a value; roomNumber was
	// requested and did not. secretary was requested, so it cannot be unloaded;
	// businessCategory came back with a value; seeAlso was never requested.
	absent, unloaded := InternalPropertyProbes(subject,
		[]string{"carLicense", "roomNumber"},
		[]string{"secretary", "businessCategory", "seeAlso"})
	if absent != "roomNumber" {
		t.Errorf("absent probe = %q, want roomNumber", absent)
	}
	if unloaded != "seeAlso" {
		t.Errorf("unloaded probe = %q, want seeAlso", unloaded)
	}
	absent, unloaded = InternalPropertyProbes(
		subject,
		[]string{"carLicense"},
		[]string{"secretary"},
	)
	if absent != "" || unloaded != "" {
		t.Errorf("exhausted candidates produced probes %q and %q", absent, unloaded)
	}
}

// The scenario's central claim, tested without a directory: one object reports
// three different states, and neither state with no values is presentable as a
// value — not even an empty one.
func TestPropertyStatesDistinguishUnloadedFromAbsent(t *testing.T) {
	subject := admodel.Object{
		DistinguishedName: "CN=Administrator,CN=Users,DC=example,DC=test",
		Attributes: map[string][][]byte{
			"objectclass": {[]byte("top"), []byte("person"), []byte("user")},
		},
		RequestedProperties: []string{"objectClass", "carLicense"},
	}
	if distinct, detail := InternalPropertyStatesDistinct(
		subject,
		"objectClass",
		"carLicense",
		"secretary",
	); !distinct {
		t.Fatalf("the three states were not distinguished: %s", detail)
	}
	if empty, detail := InternalPropertyNoEmptyValue(subject, "carLicense", "secretary"); !empty {
		t.Fatalf("an unavailable attribute was presentable as a value: %s", detail)
	}
	for _, test := range []struct {
		InternalName                                      string
		InternalPresent, InternalAbsent, InternalUnloaded string
		InternalWantDistinct, InternalWantNoEmptyChecks   bool
	}{
		{"no absent probe", "objectClass", "", "secretary", false, false},
		{"no unloaded probe", "objectClass", "carLicense", "", false, false},
		// secretary was never requested, so asking for it as the absent probe
		// must be refused rather than reported as an unset attribute.
		{"unloaded offered as absent", "objectClass", "secretary", "seeAlso", false, true},
		// carLicense was requested, so it is absent and cannot stand in for an
		// attribute that was never asked for.
		{"absent offered as unloaded", "objectClass", "roomNumber", "carLicense", false, true},
		// A name that carries values is not an absent attribute.
		{"present offered as absent", "objectClass", "objectClass", "secretary", false, true},
		{"absent offered as present", "carLicense", "roomNumber", "secretary", false, true},
	} {
		t.Run(test.InternalName, func(t *testing.T) {
			if distinct, _ := InternalPropertyStatesDistinct(
				subject,
				test.InternalPresent,
				test.InternalAbsent,
				test.InternalUnloaded,
			); distinct != test.InternalWantDistinct {
				t.Fatalf("distinct = %t, want %t", distinct, test.InternalWantDistinct)
			}
		})
	}
	if empty, _ := InternalPropertyNoEmptyValue(subject, "objectClass", "secretary"); empty {
		t.Fatal("an attribute carrying values was accepted as unavailable")
	}
	if empty, _ := InternalPropertyNoEmptyValue(subject, ""); empty {
		t.Fatal("a missing probe name was accepted")
	}
}

// A multi-valued read must keep every value, in order, including duplicates.
func TestPropertyMultiValuePreservation(t *testing.T) {
	subject := admodel.Object{
		Attributes: map[string][][]byte{
			"objectclass":  {[]byte("top"), []byte("person"), []byte("person")},
			"single":       {[]byte("one")},
			"emptyvalue":   {{}, {}},
			"invalidtext":  {[]byte("ok"), {0x00, 0x01}},
			"objectguid;r": {[]byte("ignored")},
		},
		RequestedProperties: []string{
			"objectClass",
			"single",
			"emptyValue",
			"invalidText",
			"notReturned",
		},
	}
	if count, held, detail := InternalPropertyMultiValuePreserved(
		subject,
		"objectClass",
	); count != 3 ||
		!held {
		t.Fatalf("objectClass: count %d held %t (%s)", count, held, detail)
	}
	// Two empty values are still two values: a multi-valued attribute of empty
	// strings must not collapse to one, or to none.
	if count, held, _ := InternalPropertyMultiValuePreserved(
		subject,
		"emptyValue",
	); count != 2 ||
		!held {
		t.Fatalf("emptyValue: count %d held %t", count, held)
	}
	for _, name := range []string{"single", "invalidText", "notReturned", "neverRequested"} {
		if _, held, detail := InternalPropertyMultiValuePreserved(subject, name); held {
			t.Errorf("%s was accepted as a preserved multi-valued read (%s)", name, detail)
		}
	}
}

// The typed conversions are the scenario's round-trip claim. A GUID's first
// three fields are little-endian, so a reversal applied once in each direction
// would cancel out unnoticed unless both the bytes and the text are checked.
func TestPropertyTypedRoundTrips(t *testing.T) {
	guid := admodel.NewRawValue(
		[]byte{
			0x10,
			0x32,
			0x54,
			0x76,
			0x98,
			0xba,
			0xdc,
			0xfe,
			0x01,
			0x23,
			0x45,
			0x67,
			0x89,
			0xab,
			0xcd,
			0xef,
		},
	)
	held, text, detail := InternalPropertyGUIDRoundTrip(guid)
	if !held || !text {
		t.Fatalf("GUID round-trip: bytes %t text %t (%s)", held, text, detail)
	}
	if held, text, _ := InternalPropertyGUIDRoundTrip(
		admodel.NewRawValue([]byte{0x01}),
	); held ||
		text {
		t.Fatal("a short binary value round-tripped as a GUID")
	}

	sid, err := admodel.ParseSID("S-1-5-21-1004336348-1177238915-682003330-512")
	if err != nil {
		t.Fatal(err)
	}
	if held, detail := InternalPropertySIDRoundTrip(admodel.NewRawValue(sid.Bytes())); !held {
		t.Fatalf("SID round-trip withheld: %s", detail)
	}
	if held, _ := InternalPropertySIDRoundTrip(admodel.NewRawValue([]byte("not a sid"))); held {
		t.Fatal("a malformed value round-tripped as a SID")
	}

	if held, detail := InternalPropertyLargeIntegerRoundTrip(
		admodel.NewRawValue([]byte("9223372036854775807")),
	); !held {
		t.Fatalf("a 64-bit counter lost precision: %s", detail)
	}
	for _, text := range []string{"+12", "012", "9223372036854775808", "not a number"} {
		if held, _ := InternalPropertyLargeIntegerRoundTrip(
			admodel.NewRawValue([]byte(text)),
		); held {
			t.Errorf("%q round-tripped as a 64-bit integer", text)
		}
	}

	if held, detail := InternalPropertyTimestampRoundTrip(
		admodel.NewRawValue([]byte("20240115103000.0Z")),
	); !held {
		t.Fatalf("a generalized time lost its representation: %s", detail)
	}
	for _, text := range []string{"20240115103000Z extra", "2024011510300", ""} {
		if held, _ := InternalPropertyTimestampRoundTrip(admodel.NewRawValue([]byte(text))); held {
			t.Errorf("%q round-tripped as a generalized time", text)
		}
	}

	for _, text := range []string{"28", "0", "-2147483648", "2147483648"} {
		if held, detail := InternalPropertyFlagsPreserved(
			admodel.NewRawValue([]byte(text)),
		); !held {
			t.Errorf("flag bits %q were not preserved: %s", text, detail)
		}
	}
	if held, _ := InternalPropertyFlagsPreserved(admodel.NewRawValue([]byte("not flags"))); held {
		t.Error("a malformed value was accepted as flags")
	}
}

// A sentinel must stay a sentinel: Time refuses to invent an instant for it and
// the original digits come back. A lab holding no sentinel must report nothing
// rather than a satisfied observation.
func TestPropertySentinelRoundTrip(t *testing.T) {
	objects := []admodel.Object{
		{
			Attributes:          map[string][][]byte{"pwdlastset": {[]byte("133500000000000000")}},
			RequestedProperties: []string{"pwdLastSet", "accountExpires"},
		},
		{
			Attributes:          map[string][][]byte{"accountexpires": {[]byte("0")}},
			RequestedProperties: []string{"pwdLastSet", "accountExpires"},
		},
	}
	name, value, held := InternalPropertySentinelRoundTrip(
		objects,
		[]string{"pwdLastSet", "accountExpires"},
	)
	if name != "accountExpires" || value != "0" || held == nil || !*held {
		t.Fatalf("sentinel = %q %q %v", name, value, held)
	}
	if _, _, held := InternalPropertySentinelRoundTrip(
		objects[:1],
		[]string{"pwdLastSet"},
	); held != nil {
		t.Fatal("an instant was reported as a sentinel")
	}
	if _, _, held := InternalPropertySentinelRoundTrip(
		nil,
		[]string{"accountExpires"},
	); held != nil {
		t.Fatal("an empty read reported a sentinel")
	}
	// Both all-ones forms are sentinels and both must come back as the server's
	// own digits rather than as the other representation.
	for _, text := range []string{"9223372036854775807", "-1"} {
		objects := []admodel.Object{{
			Attributes:          map[string][][]byte{"accountexpires": {[]byte(text)}},
			RequestedProperties: []string{"accountExpires"},
		}}
		_, value, held := InternalPropertySentinelRoundTrip(objects, []string{"accountExpires"})
		if held == nil || !*held || value != text {
			t.Errorf("sentinel %q round-tripped as %q (%v)", text, value, held)
		}
	}
}

// The wildcard must widen the default set, and the names it does not carry must
// be reported rather than assumed absent.
func TestPropertyWildcardWidening(t *testing.T) {
	defaults := admodel.Object{Attributes: map[string][][]byte{
		"distinguishedname": {[]byte("CN=x")}, "name": {[]byte("x")},
		"objectclass": {[]byte("top")}, "objectguid": {[]byte("g")},
	}}
	wildcard := admodel.Object{Attributes: map[string][][]byte{
		"distinguishedname": {[]byte("CN=x")}, "name": {[]byte("x")},
		"objectclass": {[]byte("top")}, "description": {[]byte("d")},
		"whencreated": {[]byte("t")},
	}}
	widens, missing := InternalPropertyWildcardWidens(defaults, wildcard)
	if !widens {
		t.Fatal("a wider wildcard read was not recognised")
	}
	if !slices.Equal(missing, []string{"objectguid"}) {
		t.Fatalf("missing = %v, want [objectguid]", missing)
	}
	if widens, _ := InternalPropertyWildcardWidens(defaults, defaults); widens {
		t.Fatal("an identical read was reported as widening the default set")
	}
	if widens, _ := InternalPropertyWildcardWidens(wildcard, admodel.Object{}); widens {
		t.Fatal("an empty read was reported as widening the default set")
	}
}

// A conversion is never inferred from an attribute name, and a truncated value
// is never padded into a plausible one.
func TestPropertyMalformedValuesAreRefused(t *testing.T) {
	guid := admodel.NewRawValue(
		[]byte{
			0x10,
			0x32,
			0x54,
			0x76,
			0x98,
			0xba,
			0xdc,
			0xfe,
			0x01,
			0x23,
			0x45,
			0x67,
			0x89,
			0xab,
			0xcd,
			0xef,
		},
	)
	timestamp := admodel.NewRawValue([]byte("20240115103000.0Z"))
	if refused, detail := InternalPropertyMalformedRefused(guid, timestamp); !refused {
		t.Fatalf("a malformed value was not refused: %s", detail)
	}
	if refused, _ := InternalPropertyMalformedRefused(
		admodel.NewRawValue(nil),
		timestamp,
	); refused {
		t.Fatal("a missing binary value was reported as a refusal")
	}
	// A value that genuinely is a FILETIME must not be reported as a refusal:
	// the check has to be about the conversion, not about the attribute.
	if refused, _ := InternalPropertyMalformedRefused(
		guid,
		admodel.NewRawValue([]byte("133500000000000000")),
	); refused {
		t.Fatal("a valid FILETIME was reported as refused")
	}
}

// A schema-extension attribute must come back with a definite state whether or
// not the directory carries it, and a returned value must keep its bits.
func TestPropertySchemaExtensionStates(t *testing.T) {
	for _, test := range []struct {
		InternalName         string
		InternalSubject      admodel.Object
		InternalWantState    string
		InternalWantDefinite bool
	}{
		{
			"returned", admodel.Object{
				Attributes:          map[string][][]byte{"msds-supportedencryptiontypes": {[]byte("28")}},
				RequestedProperties: []string{"msDS-SupportedEncryptionTypes"},
			}, "present", true,
		},
		{
			"requested and not set", admodel.Object{
				Attributes:          map[string][][]byte{},
				RequestedProperties: []string{"msDS-SupportedEncryptionTypes"},
			}, "absent", true,
		},
		{
			"never requested", admodel.Object{
				Attributes:          map[string][][]byte{},
				RequestedProperties: []string{"name"},
			}, "unloaded", false,
		},
		{
			"returned but unreadable", admodel.Object{
				Attributes:          map[string][][]byte{"msds-supportedencryptiontypes": {[]byte("not flags")}},
				RequestedProperties: []string{"msDS-SupportedEncryptionTypes"},
			}, "present", false,
		},
	} {
		t.Run(test.InternalName, func(t *testing.T) {
			state, definite, detail := InternalPropertySchemaExtension(
				test.InternalSubject,
				"msDS-SupportedEncryptionTypes",
			)
			if state != test.InternalWantState || definite != test.InternalWantDefinite {
				t.Fatalf("state %q definite %t (%s), want %q and %t",
					state, definite, detail, test.InternalWantState, test.InternalWantDefinite)
			}
		})
	}
}

// The selection is a claim about the scenario: it has to contain one attribute
// for every shape the contract names, or the harness would read fewer shapes
// than it reports.
func TestPropertySelectionCoversEveryShape(t *testing.T) {
	shapes := InternalPropertyShapes()
	selection := shapes.InternalRequested()
	for _, name := range []string{shapes.InternalBinary, shapes.InternalMultiValued, shapes.InternalLargeInteger, shapes.InternalTimestamp, shapes.InternalSid, shapes.InternalExtension} {
		if !slices.ContainsFunc(
			selection,
			func(selected string) bool { return strings.EqualFold(selected, name) },
		) {
			t.Errorf("%s is not in the explicit selection", name)
		}
	}
	for _, name := range shapes.InternalAbsentProbes {
		if !slices.Contains(selection, name) {
			t.Errorf("absent probe %s is not requested, so it could only ever be unloaded", name)
		}
	}
	// The unloaded probes must never be requested, or they could not report an
	// unloaded state at all.
	for _, name := range shapes.InternalUnloadedProbes {
		if slices.ContainsFunc(
			selection,
			func(selected string) bool { return strings.EqualFold(selected, name) },
		) {
			t.Errorf("unloaded probe %s is requested, so it can never be unloaded", name)
		}
	}
	if len(shapes.InternalAbsentProbes) == 0 || len(shapes.InternalUnloadedProbes) == 0 ||
		len(shapes.InternalSentinelCandidates) == 0 {
		t.Fatal("the selection has no probe candidates")
	}
	// Every selected name must survive the SDK's own attribute description
	// validation, or the explicit read would be refused as invalid rather than
	// observing anything.
	if err := (admodel.SearchOptions{Properties: selection}).Validate(); err != nil {
		t.Fatalf("the explicit selection is not a valid attribute selection: %v", err)
	}
	// The refusal half's selections must be refused, and for the documented
	// reason, or the failure half would observe nothing.
	for _, refused := range [][]string{{"not a property"}, {"1.1", "cn"}} {
		if err := (admodel.SearchOptions{Properties: refused}).Validate(); !errors.Is(
			err,
			admodel.ErrInvalidProperty,
		) {
			t.Errorf("%v was not refused as an invalid property selection: %v", refused, err)
		}
	}
}

// The table is a claim about the coverage contract: each row says it observes one
// operation's selected-and-raw-properties scenario. A row naming an operation
// that has no such scenario, or a duplicate row, would make the artifact cite
// evidence for something the contract does not ask for.
func TestPropertySweepTableMatchesCoverageContract(t *testing.T) {
	data, err := os.ReadFile(repositoryFile("coverage/inventory.json"))
	if err != nil {
		t.Fatal(err)
	}
	// Windows PowerShell UTF8 output may include the BOM.
	if len(data) >= 3 && string(data[:3]) == "\xef\xbb\xbf" {
		data = data[3:]
	}
	var inventory struct {
		Operations []struct {
			Cmdlet    string `json:"cmdlet"`
			Scenarios []struct {
				Name string `json:"name"`
			} `json:"scenarios"`
		} `json:"operations"`
	}
	if err := json.Unmarshal(data, &inventory); err != nil {
		t.Fatal(err)
	}
	scoped := map[string]bool{}
	for _, operation := range inventory.Operations {
		for _, scenario := range operation.Scenarios {
			if scenario.Name == "selected-and-raw-properties" {
				scoped[operation.Cmdlet] = true
			}
		}
	}
	if len(scoped) == 0 {
		t.Fatal("no operation in the contract declares a selected-and-raw-properties scenario")
	}
	seen := map[string]bool{}
	for _, target := range InternalEndpointSweepTargets() {
		if seen[target.InternalCmdlet] {
			t.Errorf("%s appears twice in the property sweep table", target.InternalCmdlet)
		}
		seen[target.InternalCmdlet] = true
		if !scoped[target.InternalCmdlet] {
			t.Errorf(
				"%s has no selected-and-raw-properties scenario in the coverage contract",
				target.InternalCmdlet,
			)
		}
	}
	if len(seen) == 0 {
		t.Fatal("the property sweep table is empty")
	}
}
