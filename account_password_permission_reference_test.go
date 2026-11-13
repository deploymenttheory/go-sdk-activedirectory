package activedirectory

import (
	"encoding/json"
	"os"
	"testing"
)

type passwordPermissionReferenceCase struct {
	Name          string `json:"name"`
	Cannot        bool   `json:"requested_cannot"`
	Changed       bool   `json:"changed"`
	Before        []byte `json:"before_base64"`
	After         []byte `json:"after_base64"`
	SelfDeny      bool   `json:"self_deny"`
	EveryoneDeny  bool   `json:"everyone_deny"`
	SelfAllow     bool   `json:"self_allow"`
	EveryoneAllow bool   `json:"everyone_allow"`
}

func passwordPermissionReferenceCases(t *testing.T) []passwordPermissionReferenceCase {
	t.Helper()
	raw, err := os.ReadFile("testdata/account-password-permission-local-reference.json")
	if err != nil {
		t.Fatal(err)
	}
	var reference struct {
		Kind        string                            `json:"kind"`
		FileVersion string                            `json:"file_version"`
		SHA256      string                            `json:"assembly_sha256"`
		Cases       []passwordPermissionReferenceCase `json:"cases"`
	}
	if err := json.Unmarshal(raw, &reference); err != nil {
		t.Fatal(err)
	}
	if reference.Kind != "local-reference-only-no-directory-qualification" || reference.FileVersion != "10.0.26100.7920" || reference.SHA256 != "0DF8B9B0B77C652BB65971C3745B2B7E99AA899A0390CDDAB12142ED96EB1FC7" || len(reference.Cases) != 4 {
		t.Fatal("reference provenance changed")
	}
	return reference.Cases
}

func TestPasswordPermissionMatchesLocalMicrosoftReference(t *testing.T) {
	for _, reference := range passwordPermissionReferenceCases(t) {
		t.Run(reference.Name, func(t *testing.T) {
			before, err := decodeDirectoryDACL(reference.Before)
			if err != nil {
				t.Fatal(err)
			}
			expected, err := decodeDirectoryDACL(reference.After)
			if err != nil {
				t.Fatal(err)
			}
			aces, changed, err := changePasswordPermissionACEs(before, reference.Cannot)
			if err != nil || changed != reference.Changed || len(aces) != len(expected.aces) || !directoryACEsRetained(expected.aces, aces) {
				t.Fatal(changed, err, "ACE multiset differs from Microsoft transform")
			}
			self, everyone, cannot, unknown := observePasswordChangeACL(directoryDACL{aces: aces})
			if unknown || cannot == nil || *cannot != reference.Cannot || self.ExplicitDeny != reference.SelfDeny || everyone.ExplicitDeny != reference.EveryoneDeny || self.ExplicitAllow != reference.SelfAllow || everyone.ExplicitAllow != reference.EveryoneAllow {
				t.Fatal(self, everyone, cannot, unknown)
			}
		})
	}
}
