package conditions_test

import (
	"bytes"
	"encoding/base64"
	"encoding/json"
	"os"
	"testing"

	"github.com/deploymenttheory/go-sdk-activedirectory/conditions"
)

type nativeDescriptorCase struct {
	ID        string `json:"id"`
	InputSDDL string `json:"input_sddl"`
	Binary    []byte `json:"binary_base64"`
	Success   bool   `json:"success"`
}

func nativeDescriptorFixture(t *testing.T, id string) nativeDescriptorCase {
	t.Helper()
	data, err := os.ReadFile("testdata/sdk06-native-reference-initial.json")
	if err != nil {
		t.Fatal(err)
	}
	var corpus struct {
		Cases []nativeDescriptorCase `json:"cases"`
	}
	if err := json.Unmarshal(data, &corpus); err != nil {
		t.Fatal(err)
	}
	for _, fixture := range corpus.Cases {
		if fixture.ID == id {
			return fixture
		}
	}
	t.Fatalf("native fixture %q is missing", id)
	return nativeDescriptorCase{}
}

func TestNormalizeSDDLPreservesResourceAttributeACE(t *testing.T) {
	fixture := nativeDescriptorFixture(t, "resource-attribute")
	normalized, err := conditions.NormalizeSDDL(fixture.InputSDDL)
	if err != nil {
		t.Fatal(err)
	}
	actual, err := conditions.DescriptorBytes(normalized)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(actual, fixture.Binary) {
		t.Fatalf("normalization discarded SACL content: got %s, native %s", base64.StdEncoding.EncodeToString(actual), base64.StdEncoding.EncodeToString(fixture.Binary))
	}
}
