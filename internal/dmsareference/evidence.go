// Package dmsareference checks captured dMSA observations without a directory or
// Windows dependency. Its findings support review; it cannot yet establish
// complete Microsoft cmdlet or native SDK qualification.
package dmsareference

import (
	"bytes"
	"crypto/sha256"
	"encoding/base64"
	"encoding/binary"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"slices"
	"strconv"
	"strings"
	"time"
)

// RequiredScenarios returns independent transition and failure observations.
// Each command must have its own repeat, conflict, denied-rights and recovery case.
func RequiredScenarios() []string {
	ids := []string{"start-unlinked", "complete-started", "undo-started", "undo-completed", "reset-started", "reset-completed", "reset-unlinked"}
	for _, operation := range []string{"start", "complete", "undo", "reset"} {
		for _, behavior := range []string{"repeat", "conflict", "denied", "partial-failure"} {
			ids = append(ids, operation+"-"+behavior)
		}
	}
	return ids
}

// RequiredAttributes is deliberately an allowlist: account key/password values
// must never enter evidence. Field presence and read status are independent.
func RequiredAttributes() []string {
	return []string{
		"ntsecuritydescriptor", "msds-groupmsamembership", "useraccountcontrol",
		"msds-user-account-control-computed", "accountexpires", "pwdlastset",
		"msds-supportedencryptiontypes", "serviceprincipalname", "msds-allowedtodelegateto",
		"msds-allowedtoactonbehalfofotheridentity", "msds-assignedauthnpolicy",
		"msds-assignedauthnpolicysilo", "msds-authnpolicysilomembersbl", "memberof",
		"msds-delegatedmsastate", "msds-supersededserviceaccountstate",
		"msds-managedaccountprecededbylink", "msds-managedaccountprecededbylinkbl",
		"msds-supersededmanagedaccountlink", "msds-supersededmanagedaccountlinkbl",
	}
}

type Artifact struct {
	Path   string `json:"path"`
	SHA256 string `json:"sha256"`
}

type Provenance struct {
	SourceCommit string   `json:"source_commit"`
	Runner       Artifact `json:"runner"`
	Capture      Artifact `json:"capture"`
	Environment  Artifact `json:"environment"`
}

type Environment struct {
	RunID         string   `json:"run_id"`
	LabID         string   `json:"lab_id"`
	DomainSID     string   `json:"domain_sid"`
	OSBuild       string   `json:"os_build"`
	Architecture  string   `json:"architecture"`
	PowerShell    string   `json:"powershell"`
	ModuleVersion string   `json:"module_version"`
	ModuleFile    string   `json:"module_file_version"`
	ModuleHash    string   `json:"module_sha256"`
	SchemaVersion int      `json:"schema_version"`
	DomainLevel   string   `json:"domain_level"`
	ForestLevel   string   `json:"forest_level"`
	Servers       []string `json:"servers"`
	ObservedAt    string   `json:"observed_at"`
}

type Run struct {
	SchemaVersion int        `json:"schema_version"`
	RunID         string     `json:"run_id"`
	LabID         string     `json:"lab_id"`
	DomainSID     string     `json:"domain_sid"`
	Provenance    Provenance `json:"provenance"`
	Cases         []Case     `json:"cases"`
	Unresolved    []string   `json:"unresolved"`
}

type Case struct {
	ID              string        `json:"id"`
	Family          string        `json:"family"`
	Command         string        `json:"command"`
	Outcome         string        `json:"outcome"`
	Errors          []NativeError `json:"errors"`
	Before          Artifact      `json:"before"`
	After           Artifact      `json:"after"`
	Replicated      Artifact      `json:"replicated"`
	RecoveryTarget  Artifact      `json:"recovery_target"`
	Recovered       Artifact      `json:"recovered"`
	Cleanup         []Artifact    `json:"cleanup"`
	Effects         []Effect      `json:"effects"`
	RecoveryEffects []Effect      `json:"recovery_effects"`
	Service         []Artifact    `json:"service"`
	Credentials     []Artifact    `json:"credentials"`
	Unresolved      []string      `json:"unresolved"`
}

type NativeError struct {
	Type    string `json:"type"`
	HResult int64  `json:"hresult"`
	Code    *int64 `json:"code"`
}

type Field struct {
	Status string   `json:"status"`
	Kind   string   `json:"kind"`
	Values []string `json:"values"`
}

type Metadata struct {
	Name     string `json:"name"`
	ValueKey string `json:"value_key"`
	Version  int64  `json:"version"`
	USN      string `json:"originating_usn"`
}

type Object struct {
	Role       string           `json:"role"`
	GUID       string           `json:"guid"`
	SID        string           `json:"sid"`
	DN         string           `json:"dn"`
	Class      string           `json:"class"`
	Marker     string           `json:"marker"`
	Status     string           `json:"status"`
	SDSections int              `json:"sd_sections"`
	Fields     map[string]Field `json:"fields"`
	Metadata   []Metadata       `json:"metadata"`
}

type Capture struct {
	SchemaVersion int           `json:"schema_version"`
	RunID         string        `json:"run_id"`
	CaseID        string        `json:"case_id"`
	Point         string        `json:"point"`
	Server        string        `json:"server"`
	StartedAt     string        `json:"started_at"`
	FinishedAt    string        `json:"finished_at"`
	Objects       []Object      `json:"objects"`
	Errors        []NativeError `json:"errors"`
}

// Effect is an externally reviewed expected difference. Evaluation recomputes
// the difference from before/after captures and compares both values; a note or
// a boolean alone cannot explain a mutation.
type Effect struct {
	ObjectGUID     string `json:"object_guid"`
	Attribute      string `json:"attribute"`
	Before         Field  `json:"before"`
	After          Field  `json:"after"`
	Classification string `json:"classification"`
	Source         string `json:"source"`
	Explanation    string `json:"explanation"`
}

type Finding struct {
	Case   string `json:"case,omitempty"`
	Detail string `json:"detail"`
}

type Report struct {
	Status           string    `json:"status"`
	EvidenceComplete bool      `json:"evidence_complete"`
	CasesRead        int       `json:"cases_read"`
	Findings         []Finding `json:"findings"`
}

// Assess verifies hashes, capture identity, required observations and documented
// phase assertions. It deliberately does not promote reviewed observations to
// operation coverage; service/credential semantics need a separate evaluator.
func Assess(directory string) (Report, error) {
	root, err := os.OpenRoot(directory)
	if err != nil {
		return Report{}, err
	}
	defer root.Close()
	var run Run
	data, err := read(root, "run.json")
	if err != nil {
		return Report{}, err
	}
	if err := decode(data, &run); err != nil {
		return Report{}, fmt.Errorf("run.json: %w", err)
	}
	r := Report{Status: "incomplete", Findings: []Finding{}}
	add := func(id, detail string) { r.Findings = append(r.Findings, Finding{Case: id, Detail: detail}) }
	if run.SchemaVersion != 1 || run.RunID == "" || run.LabID == "" || !strings.HasPrefix(run.DomainSID, "S-1-5-21-") {
		add("", "run identity/schema is missing or invalid")
	}
	if len(run.Provenance.SourceCommit) != 40 || !isHex(run.Provenance.SourceCommit) {
		add("", "source commit is missing or invalid")
	}
	for label, artifact := range map[string]Artifact{"runner": run.Provenance.Runner, "capture": run.Provenance.Capture} {
		if _, err := artifactBytes(root, artifact); err != nil {
			add("", label+" provenance: "+err.Error())
		}
	}
	var environment Environment
	if err := artifactJSON(root, run.Provenance.Environment, &environment); err != nil {
		add("", "environment: "+err.Error())
	} else if environment.RunID != run.RunID || environment.LabID != run.LabID || environment.DomainSID != run.DomainSID ||
		environment.OSBuild == "" || environment.Architecture == "" || environment.PowerShell == "" ||
		environment.ModuleVersion == "" || environment.ModuleFile == "" || !validHash(environment.ModuleHash) ||
		environment.SchemaVersion == 0 || environment.DomainLevel == "" || environment.ForestLevel == "" ||
		len(environment.Servers) != 2 || environment.Servers[0] == environment.Servers[1] || !timestamp(environment.ObservedAt) {
		add("", "environment identity, exact versions, schema, levels, or two distinct servers are missing")
	}
	seen := map[string]bool{}
	for _, c := range run.Cases {
		key := c.ID + "/" + c.Family
		if seen[key] {
			add(c.ID, "duplicate scenario/family")
			continue
		}
		seen[key] = true
		r.CasesRead++
		assessCase(root, run, environment, c, add)
	}
	for _, required := range RequiredScenarios() {
		for _, family := range []string{"minimal", "populated"} {
			if !seen[required+"/"+family] {
				add(required, "missing required "+family+" observation")
			}
		}
	}
	for _, unresolved := range run.Unresolved {
		add("", "unresolved: "+unresolved)
	}
	// This checker has no independent service/credential probe interpreter yet.
	// A JSON nonce, exit code, or runner-authored assertion is not that interpreter.
	add("", "service and credential observation interpretation is not implemented; no complete-evidence claim is available")
	return r, nil
}

func assessCase(root *os.Root, run Run, env Environment, c Case, add func(string, string)) {
	fail := func(detail string) { add(c.ID, detail) }
	if !slices.Contains(RequiredScenarios(), c.ID) {
		fail("unrecognized scenario")
	}
	if !slices.Contains([]string{"minimal", "populated", "policy", "preservation", "disabled-origin", "standalone", "delegation-flags"}, c.Family) {
		fail("unknown fixture family")
	}
	op := strings.Split(c.ID, "-")[0]
	if !strings.EqualFold(c.Command, op+"-ADServiceAccountMigration") {
		fail("scenario command mismatch")
	}
	if c.Outcome != "success" && c.Outcome != "error" {
		fail("command outcome must be success or error")
	}
	if c.Outcome == "error" && len(c.Errors) == 0 {
		fail("failed command has no native error details")
	}
	for _, native := range c.Errors {
		if native.Type == "" || (native.HResult == 0 && native.Code == nil) {
			fail("native error details are incomplete")
		}
	}
	if c.Outcome == "success" && len(c.Errors) > 0 {
		fail("successful command contains errors")
	}
	captures := map[string]Capture{}
	for point, artifact := range map[string]Artifact{"before": c.Before, "after": c.After, "replicated": c.Replicated, "recovery_target": c.RecoveryTarget, "recovered": c.Recovered} {
		var capture Capture
		if err := artifactJSON(root, artifact, &capture); err != nil {
			fail(point + ": " + err.Error())
			continue
		}
		for _, problem := range ValidateCapture(capture, run.RunID, c.ID) {
			fail(point + ": " + problem)
		}
		if capture.Point != point {
			fail(point + ": capture point mismatch")
		}
		if !slices.Contains(env.Servers, capture.Server) {
			fail(point + ": server is outside the recorded profile")
		}
		captures[point] = capture
	}
	before, bok := captures["before"]
	after, aok := captures["after"]
	if bok && aok {
		for _, problem := range compareEffects(before, after, c.Effects) {
			fail(problem)
		}
		if c.Outcome == "success" {
			for _, problem := range CheckPhase(c.ID, after) {
				fail(problem)
			}
		}
	}
	if replicated, ok := captures["replicated"]; ok && aok {
		if replicated.Server == after.Server {
			fail("replication was captured on the same server")
		}
		if !sameObjects(after, replicated) {
			fail("replicated values differ from the after capture")
		}
	}
	if target, ok := captures["recovery_target"]; ok {
		if recovered, ok := captures["recovered"]; ok {
			for _, problem := range compareEffects(target, recovered, c.RecoveryEffects) {
				fail("recovery: " + problem)
			}
		}
	}
	cleanupServers := map[string]bool{}
	for _, artifact := range c.Cleanup {
		var capture Capture
		if err := artifactJSON(root, artifact, &capture); err != nil {
			fail("cleanup: " + err.Error())
			continue
		}
		if capture.RunID != run.RunID || capture.CaseID != c.ID || capture.Point != "cleanup" || !slices.Contains(env.Servers, capture.Server) {
			fail("cleanup identity/point/server mismatch")
			continue
		}
		if cleanupServers[capture.Server] {
			fail("duplicate cleanup server")
		}
		cleanupServers[capture.Server] = true
		if !timestamp(capture.StartedAt) || !timestamp(capture.FinishedAt) {
			fail("cleanup timestamps missing")
		}
		if !aok || len(capture.Objects) != len(after.Objects) {
			fail("cleanup object set is incomplete")
			continue
		}
		for _, expected := range after.Objects {
			matches := 0
			for _, object := range capture.Objects {
				if object.GUID == expected.GUID && object.Marker == expected.Marker && object.Status == "absent" {
					matches++
				}
			}
			if matches != 1 {
				fail("cleanup does not independently observe owned object absence: " + expected.GUID)
			}
		}
	}
	if len(cleanupServers) != 2 {
		fail("cleanup was not captured on two distinct profile servers")
	}
	for label, artifacts := range map[string][]Artifact{"service": c.Service, "credentials": c.Credentials} {
		if len(artifacts) == 0 {
			fail(label + " observations are missing")
		}
		for _, artifact := range artifacts {
			if _, err := artifactBytes(root, artifact); err != nil {
				fail(label + ": " + err.Error())
			}
		}
	}
	for _, unresolved := range c.Unresolved {
		fail("unresolved: " + unresolved)
	}
}

// ValidateCapture rejects missing, denied and ambiguous capture data. It never
// turns a failed LDAP read into an absent field.
func ValidateCapture(c Capture, runID, caseID string) []string {
	var problems []string
	add := func(s string) { problems = append(problems, s) }
	if len(c.Errors) > 0 {
		add("capture contains read errors")
	}
	if c.SchemaVersion != 1 || c.RunID != runID || c.CaseID != caseID || c.Server == "" {
		add("capture identity/schema mismatch")
	}
	start, se := time.Parse(time.RFC3339Nano, c.StartedAt)
	end, ee := time.Parse(time.RFC3339Nano, c.FinishedAt)
	if se != nil || ee != nil || end.Before(start) {
		add("capture time interval invalid")
	}
	roles := map[string]int{}
	guids := map[string]bool{}
	for _, o := range c.Objects {
		roles[o.Role]++
		if o.GUID == "" || guids[o.GUID] {
			add("missing or duplicate object GUID")
		}
		guids[o.GUID] = true
		if o.DN == "" || o.Marker == "" || o.Class == "" || o.Status != "present" {
			add("object identity/ownership/read status incomplete: " + o.Role)
		}
		if o.Role == "legacy" || o.Role == "dmsa" {
			if o.SID == "" {
				add("account SID missing: " + o.Role)
			}
			for _, name := range RequiredAttributes() {
				if _, ok := o.Fields[name]; !ok {
					add("missing field " + o.Role + "/" + name)
				}
			}
			if o.SDSections != 15 {
				add("full security descriptor sections not captured: " + o.Role)
			}
		}
		for name, field := range o.Fields {
			if strings.ToLower(name) != name {
				add("attribute name is not canonical: " + name)
			}
			if secret(name) {
				add("forbidden secret-bearing attribute: " + name)
			}
			if field.Status != "present" && field.Status != "absent" {
				add("incomplete field read: " + o.Role + "/" + name)
			}
			if field.Status == "absent" && len(field.Values) > 0 {
				add("absent field contains values: " + name)
			}
			if field.Status == "present" && len(field.Values) == 0 {
				add("present field has no values: " + name)
			}
			if !slices.Contains([]string{"string", "integer", "dn", "sid", "security_descriptor"}, field.Kind) {
				add("unknown field kind: " + name)
			}
			if field.Kind == "integer" && field.Status == "present" {
				if len(field.Values) != 1 {
					add("integer field must be single-valued: " + name)
				} else if _, err := strconv.ParseInt(field.Values[0], 10, 64); err != nil {
					add("invalid integer field: " + name)
				}
			}
			if field.Kind == "security_descriptor" && field.Status == "present" {
				if len(field.Values) != 1 {
					add("descriptor must have one value: " + name)
				} else if err := descriptor(field.Values[0]); err != nil {
					add(name + ": " + err.Error())
				}
			}
		}
		if len(o.Metadata) == 0 {
			add("attribute metadata missing: " + o.Role)
		}
		metadataNames := map[string]bool{}
		for _, metadata := range o.Metadata {
			key := metadata.Name + "/" + metadata.ValueKey
			if metadata.Name == "" || metadataNames[key] || metadata.Version < 1 || metadata.USN == "" {
				add("invalid or duplicate attribute metadata: " + o.Role)
			}
			metadataNames[key] = true
		}
	}
	if roles["legacy"] != 1 || roles["dmsa"] != 1 {
		add("exactly one legacy and one dmsa object are required")
	}
	return problems
}

// CheckPhase computes only documented phase/link/enablement checks. Full ACL,
// service, copied-property and recovery semantics still require observation review.
func CheckPhase(id string, c Capture) []string {
	var legacy, dmsa *Object
	for i := range c.Objects {
		switch c.Objects[i].Role {
		case "legacy":
			legacy = &c.Objects[i]
		case "dmsa":
			dmsa = &c.Objects[i]
		}
	}
	if legacy == nil || dmsa == nil {
		return []string{"phase accounts are missing"}
	}
	var problems []string
	require := func(ok bool, message string) {
		if !ok {
			problems = append(problems, message)
		}
	}
	switch id {
	case "start-unlinked", "undo-completed":
		require(value(dmsa.Fields["msds-delegatedmsastate"]) == "1", "dMSA state is not started")
		require(value(legacy.Fields["msds-supersededserviceaccountstate"]) == "1", "legacy state is not started")
		require(strings.EqualFold(value(dmsa.Fields["msds-managedaccountprecededbylink"]), legacy.DN), "dMSA forward link mismatch")
		require(strings.EqualFold(value(legacy.Fields["msds-supersededmanagedaccountlink"]), dmsa.DN), "legacy forward link mismatch")
	case "complete-started":
		require(value(dmsa.Fields["msds-delegatedmsastate"]) == "2", "dMSA state is not completed")
		require(value(legacy.Fields["msds-supersededserviceaccountstate"]) == "2", "legacy state is not completed")
		uac, err := strconv.ParseUint(value(legacy.Fields["useraccountcontrol"]), 10, 32)
		require(err == nil && uac&2 != 0, "legacy account is not disabled")
		require(legacy.Fields["serviceprincipalname"].Status == "absent", "legacy SPNs remain after completion")
		require(strings.EqualFold(value(dmsa.Fields["msds-managedaccountprecededbylink"]), legacy.DN), "completed dMSA forward link mismatch")
		require(strings.EqualFold(value(legacy.Fields["msds-supersededmanagedaccountlink"]), dmsa.DN), "completed legacy forward link mismatch")
	case "undo-started", "reset-started", "reset-completed":
		for _, o := range []*Object{legacy, dmsa} {
			for _, name := range []string{"msds-managedaccountprecededbylink", "msds-managedaccountprecededbylinkbl", "msds-supersededmanagedaccountlink", "msds-supersededmanagedaccountlinkbl"} {
				require(o.Fields[name].Status == "absent", "migration link remains: "+o.Role+"/"+name)
			}
		}
	}
	return problems
}

func compareEffects(before, after Capture, effects []Effect) []string {
	var problems []string
	if len(before.Objects) != len(after.Objects) {
		problems = append(problems, "object capture set changed during operation")
	}
	expected := map[string]Effect{}
	for _, effect := range effects {
		key := effect.ObjectGUID + "/" + effect.Attribute
		if _, ok := expected[key]; ok {
			problems = append(problems, "duplicate effect: "+key)
		}
		if effect.Source == "" || effect.Explanation == "" || !slices.Contains([]string{"documented_contract", "observed_build_behavior", "harness_invariant"}, effect.Classification) {
			problems = append(problems, "effect lacks source/classification/explanation: "+key)
		}
		expected[key] = effect
	}
	for _, old := range before.Objects {
		var current *Object
		for i := range after.Objects {
			if after.Objects[i].GUID == old.GUID {
				current = &after.Objects[i]
			}
		}
		if current == nil {
			problems = append(problems, "object disappeared during operation: "+old.GUID)
			continue
		}
		if old.SID != current.SID || old.DN != current.DN || old.Marker != current.Marker || old.Class != current.Class {
			problems = append(problems, "object identity changed during operation: "+old.GUID)
		}
		if len(old.Fields) != len(current.Fields) {
			problems = append(problems, "field capture set changed during operation: "+old.GUID)
		}
		for name, prior := range old.Fields {
			next, ok := current.Fields[name]
			if !ok {
				problems = append(problems, "field disappeared from capture: "+name)
				continue
			}
			if equalField(prior, next) {
				continue
			}
			key := old.GUID + "/" + name
			effect, ok := expected[key]
			if !ok || !equalField(effect.Before, prior) || !equalField(effect.After, next) {
				problems = append(problems, "unexplained or mismatched effect: "+key)
			}
			delete(expected, key)
		}
		for _, metadata := range current.Metadata {
			changed := true
			for _, prior := range old.Metadata {
				if prior.Name == metadata.Name && prior.ValueKey == metadata.ValueKey && prior.Version == metadata.Version && prior.USN == metadata.USN {
					changed = false
				}
			}
			if _, captured := current.Fields[strings.ToLower(metadata.Name)]; changed && !captured {
				problems = append(problems, "changed metadata outside captured fields requires explanation: "+metadata.Name)
			}
		}
	}
	for key := range expected {
		problems = append(problems, "effect has no matching observed change: "+key)
	}
	return problems
}

func sameObjects(a, b Capture) bool {
	if len(a.Objects) != len(b.Objects) {
		return false
	}
	for _, left := range a.Objects {
		found := false
		for _, right := range b.Objects {
			if left.GUID != right.GUID {
				continue
			}
			found = true
			if left.SID != right.SID || left.DN != right.DN || left.Class != right.Class || left.Marker != right.Marker || left.Status != right.Status || left.SDSections != right.SDSections || len(left.Fields) != len(right.Fields) {
				return false
			}
			for name, field := range left.Fields {
				if !equalField(field, right.Fields[name]) {
					return false
				}
			}
		}
		if !found {
			return false
		}
	}
	return true
}

func equalField(a, b Field) bool {
	return a.Status == b.Status && a.Kind == b.Kind && slices.Equal(a.Values, b.Values)
}
func value(f Field) string {
	if f.Status == "present" && len(f.Values) == 1 {
		return f.Values[0]
	}
	return ""
}
func timestamp(s string) bool { _, err := time.Parse(time.RFC3339Nano, s); return err == nil }
func isHex(s string) bool     { _, err := hex.DecodeString(s); return err == nil }
func validHash(s string) bool { return len(s) == 64 && isHex(s) }
func secret(s string) bool {
	s = strings.ToLower(s)
	return slices.Contains([]string{"msds-managedpassword", "unicodepwd", "dbcspwd", "ntpwdhistory", "lmpwdhistory", "supplementalcredentials", "mskds-rootkeydata", "msds-managedpasswordid", "msds-managedpasswordpreviousid"}, s)
}

func descriptor(encoded string) error {
	data, err := base64.StdEncoding.DecodeString(encoded)
	if err != nil || len(data) < 20 || data[0] != 1 || binary.LittleEndian.Uint16(data[2:4])&0x8000 == 0 {
		return errors.New("invalid self-relative descriptor")
	}
	for offset := 4; offset < 20; offset += 4 {
		at := binary.LittleEndian.Uint32(data[offset : offset+4])
		if at != 0 && (at < 20 || int64(at) >= int64(len(data))) {
			return errors.New("descriptor offset is out of bounds")
		}
	}
	return nil
}

func artifactJSON(root *os.Root, a Artifact, target any) error {
	data, err := artifactBytes(root, a)
	if err != nil {
		return err
	}
	return decode(data, target)
}
func artifactBytes(root *os.Root, a Artifact) ([]byte, error) {
	if !validHash(a.SHA256) {
		return nil, errors.New("artifact SHA-256 is missing or invalid")
	}
	data, err := read(root, a.Path)
	if err != nil {
		return nil, err
	}
	sum := sha256.Sum256(data)
	if !strings.EqualFold(hex.EncodeToString(sum[:]), a.SHA256) {
		return nil, fmt.Errorf("artifact hash mismatch: %s", a.Path)
	}
	return data, nil
}
func read(root *os.Root, path string) ([]byte, error) {
	if path == "" || !filepath.IsLocal(path) || strings.Contains(path, "\\") || strings.Contains(path, ":") {
		return nil, fmt.Errorf("artifact path must be relative and portable: %q", path)
	}
	file, err := root.Open(path)
	if err != nil {
		return nil, err
	}
	defer file.Close()
	data, err := io.ReadAll(io.LimitReader(file, 32*1024*1024+1))
	if len(data) > 32*1024*1024 {
		return nil, errors.New("artifact exceeds 32 MiB")
	}
	return data, err
}
func decode(data []byte, target any) error {
	data = bytes.TrimPrefix(data, []byte{0xef, 0xbb, 0xbf})
	if err := uniqueKeys(json.NewDecoder(bytes.NewReader(data))); err != nil {
		return err
	}
	decoder := json.NewDecoder(bytes.NewReader(data))
	decoder.DisallowUnknownFields()
	if err := decoder.Decode(target); err != nil {
		return err
	}
	if err := decoder.Decode(new(any)); err != io.EOF {
		return errors.New("trailing JSON data")
	}
	return nil
}
func uniqueKeys(decoder *json.Decoder) error {
	token, err := decoder.Token()
	if err != nil {
		return err
	}
	delim, ok := token.(json.Delim)
	if !ok {
		return nil
	}
	if delim == '{' {
		seen := map[string]bool{}
		for decoder.More() {
			key, err := decoder.Token()
			if err != nil {
				return err
			}
			name := strings.ToLower(key.(string))
			if seen[name] {
				return fmt.Errorf("duplicate JSON key: %s", name)
			}
			seen[name] = true
			if err := uniqueKeys(decoder); err != nil {
				return err
			}
		}
	} else if delim == '[' {
		for decoder.More() {
			if err := uniqueKeys(decoder); err != nil {
				return err
			}
		}
	} else {
		return errors.New("unexpected JSON delimiter")
	}
	_, err = decoder.Token()
	return err
}
