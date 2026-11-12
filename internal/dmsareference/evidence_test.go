package dmsareference

import (
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"testing"
)

// These are synthetic parser/assertion inputs, never live AD evidence.
func captureFixture() Capture {
	makeObject := func(role string) Object {
		fields := map[string]Field{}
		for _, name := range RequiredAttributes() {
			fields[name] = Field{Status: "absent", Kind: "string", Values: []string{}}
		}
		sd := make([]byte, 20)
		sd[0] = 1
		sd[3] = 0x80
		fields["ntsecuritydescriptor"] = Field{Status: "present", Kind: "security_descriptor", Values: []string{base64.StdEncoding.EncodeToString(sd)}}
		return Object{Role: role, GUID: role + "-guid", SID: "S-1-5-21-1-2-3-1000", DN: "CN=" + role + ",DC=test", Class: "user", Marker: "fixture", Status: "present", SDSections: 15, Fields: fields, Metadata: []Metadata{{Name: "ntsecuritydescriptor", Version: 1, USN: "10"}}}
	}
	return Capture{SchemaVersion: 1, RunID: "synthetic", CaseID: "start-unlinked", Point: "after", Server: "dc1", StartedAt: "2026-11-12T12:00:00Z", FinishedAt: "2026-11-12T12:00:01Z", Objects: []Object{makeObject("legacy"), makeObject("dmsa")}}
}

func TestCaptureRejectsMissingDeniedAndSecretFields(t *testing.T) {
	for _, test := range []struct {
		name   string
		mutate func(*Capture)
		want   string
	}{
		{"missing", func(c *Capture) { delete(c.Objects[0].Fields, "useraccountcontrol") }, "missing field"},
		{"denied", func(c *Capture) {
			c.Objects[0].Fields["useraccountcontrol"] = Field{Status: "read_denied", Kind: "integer"}
		}, "incomplete field read"},
		{"ambiguous-absence", func(c *Capture) {
			c.Objects[0].Fields["useraccountcontrol"] = Field{Status: "absent", Kind: "integer", Values: []string{"0"}}
		}, "absent field contains values"},
		{"secret", func(c *Capture) {
			c.Objects[0].Fields["msds-managedpassword"] = Field{Status: "present", Kind: "string", Values: []string{"synthetic"}}
		}, "forbidden secret-bearing"},
		{"sacl-not-read", func(c *Capture) { c.Objects[0].SDSections = 7 }, "full security descriptor"},
		{"descriptor-offset", func(c *Capture) {
			sd := make([]byte, 20)
			sd[0] = 1
			sd[3] = 0x80
			sd[4] = 40
			c.Objects[0].Fields["ntsecuritydescriptor"] = Field{Status: "present", Kind: "security_descriptor", Values: []string{base64.StdEncoding.EncodeToString(sd)}}
		}, "out of bounds"},
		{"metadata-missing", func(c *Capture) { c.Objects[0].Metadata = nil }, "metadata missing"},
		{"duplicate-object", func(c *Capture) { c.Objects[1].GUID = c.Objects[0].GUID }, "duplicate object GUID"},
	} {
		t.Run(test.name, func(t *testing.T) {
			c := captureFixture()
			test.mutate(&c)
			got := strings.Join(ValidateCapture(c, "synthetic", "start-unlinked"), ";")
			if !strings.Contains(got, test.want) {
				t.Fatalf("got %q; want %q", got, test.want)
			}
		})
	}
	if problems := ValidateCapture(captureFixture(), "synthetic", "start-unlinked"); len(problems) != 0 {
		t.Fatalf("synthetic baseline malformed: %v", problems)
	}
}

func TestPhaseDoesNotAcceptTwoLinksAsCompleted(t *testing.T) {
	c := captureFixture()
	c.Objects[0].Fields["msds-supersededmanagedaccountlink"] = Field{Status: "present", Kind: "dn", Values: []string{c.Objects[1].DN}}
	c.Objects[1].Fields["msds-managedaccountprecededbylink"] = Field{Status: "present", Kind: "dn", Values: []string{c.Objects[0].DN}}
	problems := CheckPhase("complete-started", c)
	if len(problems) < 3 {
		t.Fatalf("links alone passed completed phase checks: %v", problems)
	}
}

func TestRecoveryComparesEnablementAndACLs(t *testing.T) {
	target := captureFixture()
	recovered := captureFixture()
	recovered.Objects[0].Fields["useraccountcontrol"] = Field{Status: "present", Kind: "integer", Values: []string{"514"}}
	if sameObjects(target, recovered) {
		t.Fatal("cleared links concealed unrecovered enablement")
	}
	recovered = captureFixture()
	delete(recovered.Objects[1].Fields, "ntsecuritydescriptor")
	if sameObjects(target, recovered) {
		t.Fatal("missing ACL accepted as recovered")
	}
}

func TestEffectRequiresExactObservedValues(t *testing.T) {
	before := captureFixture()
	after := captureFixture()
	after.Objects[0].Fields["useraccountcontrol"] = Field{Status: "present", Kind: "integer", Values: []string{"514"}}
	if got := compareEffects(before, after, nil); len(got) != 1 || !strings.Contains(got[0], "unexplained") {
		t.Fatalf("unexpected unexplained result: %v", got)
	}
	effect := Effect{ObjectGUID: before.Objects[0].GUID, Attribute: "useraccountcontrol", Before: before.Objects[0].Fields["useraccountcontrol"], After: after.Objects[0].Fields["useraccountcontrol"], Classification: "observed_build_behavior", Source: "synthetic test", Explanation: "Synthetic expected change"}
	if got := compareEffects(before, after, []Effect{effect}); len(got) != 0 {
		t.Fatalf("exact effect rejected: %v", got)
	}
	effect.After.Values = []string{"512"}
	if got := compareEffects(before, after, []Effect{effect}); len(got) == 0 {
		t.Fatal("mismatched explained value accepted")
	}
}

func TestMetadataDiscoversUncapturedEffect(t *testing.T) {
	before := captureFixture()
	after := captureFixture()
	after.Objects[0].Metadata = append(after.Objects[0].Metadata, Metadata{Name: "unexpectedProperty", Version: 1, USN: "11"})
	if got := compareEffects(before, after, nil); len(got) != 1 || !strings.Contains(got[0], "outside captured") {
		t.Fatalf("unobserved property missed: %v", got)
	}
}

func TestReviewedRecoveryResidualDoesNotInventFullRollback(t *testing.T) {
	target := captureFixture()
	recovered := captureFixture()
	recovered.Objects[1].Fields["serviceprincipalname"] = Field{Status: "present", Kind: "string", Values: []string{"synthetic/retained"}}
	effect := Effect{ObjectGUID: target.Objects[1].GUID, Attribute: "serviceprincipalname", Before: target.Objects[1].Fields["serviceprincipalname"], After: recovered.Objects[1].Fields["serviceprincipalname"], Classification: "observed_build_behavior", Source: "synthetic recovery observation", Explanation: "Test-only retained value, not a Microsoft behavior claim"}
	if got := compareEffects(target, recovered, nil); len(got) == 0 {
		t.Fatal("unexplained residual accepted")
	}
	if got := compareEffects(target, recovered, []Effect{effect}); len(got) != 0 {
		t.Fatalf("explained residual forced to original baseline: %v", got)
	}
}

func TestDecoderRejectsSelfAssertionsAndAmbiguousJSON(t *testing.T) {
	for _, input := range []string{`{"schema_version":1,"passed":true}`, `{"run_id":"first","run_id":"second"}`, `{"run_id":"first","RUN_ID":"second"}`, `{} {}`} {
		var run Run
		if err := decode([]byte(input), &run); err == nil {
			t.Fatalf("accepted %s", input)
		}
	}
}

func TestArtifactContainmentAndTampering(t *testing.T) {
	dir := t.TempDir()
	data := []byte("synthetic")
	if err := os.WriteFile(filepath.Join(dir, "capture.json"), data, 0600); err != nil {
		t.Fatal(err)
	}
	root, err := os.OpenRoot(dir)
	if err != nil {
		t.Fatal(err)
	}
	defer root.Close()
	sum := sha256.Sum256(data)
	artifact := Artifact{Path: "capture.json", SHA256: hex.EncodeToString(sum[:])}
	if _, err := artifactBytes(root, artifact); err != nil {
		t.Fatal(err)
	}
	for _, path := range []string{"../capture.json", "C:/capture.json", "sub\\capture.json"} {
		bad := artifact
		bad.Path = path
		if _, err := artifactBytes(root, bad); err == nil {
			t.Fatalf("unsafe path accepted: %q", path)
		}
	}
	if err := os.WriteFile(filepath.Join(dir, "capture.json"), []byte("changed"), 0600); err != nil {
		t.Fatal(err)
	}
	if _, err := artifactBytes(root, artifact); err == nil {
		t.Fatal("tampered artifact accepted")
	}
}

func TestIncompleteRunCannotBecomeEvidence(t *testing.T) {
	dir := t.TempDir()
	run := Run{SchemaVersion: 1, RunID: "synthetic", LabID: "test", DomainSID: "S-1-5-21-1-2-3", Cases: []Case{}}
	data, err := json.Marshal(run)
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(dir, "run.json"), data, 0600); err != nil {
		t.Fatal(err)
	}
	report, err := Assess(dir)
	if err != nil {
		t.Fatal(err)
	}
	if report.EvidenceComplete || report.Status != "incomplete" || len(report.Findings) < len(RequiredScenarios())*2 {
		t.Fatalf("missing observations accepted: %+v", report)
	}
	if !slices.ContainsFunc(report.Findings, func(f Finding) bool { return strings.Contains(f.Detail, "service and credential") }) {
		t.Fatal("unimplemented interpretation not disclosed")
	}
}
