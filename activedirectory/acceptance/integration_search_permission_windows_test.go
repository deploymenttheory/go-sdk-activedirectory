//go:build windows && (amd64 || arm64)

package acceptance

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"io"
	"os"
	"regexp"
	"strings"
	"testing"
	"time"

	adengine "github.com/deploymenttheory/go-sdk-activedirectory/activedirectory/internal/engine"
	admodel "github.com/deploymenttheory/go-sdk-activedirectory/activedirectory/internal/model"
)

type InternalSearchPermissionInput struct {
	Server, Domain, Username, Base, Marker string
	Password                               []byte
}

func InternalReadSearchPermissionInput(reader io.Reader) (InternalSearchPermissionInput, error) {
	var input InternalSearchPermissionInput
	payload, err := io.ReadAll(io.LimitReader(reader, 16385))
	defer clear(payload)
	invalid := errors.New("invalid isolated search permission input")
	if err != nil || len(payload) > 16384 {
		return input, invalid
	}
	decoder := json.NewDecoder(bytes.NewReader(payload))
	decoder.DisallowUnknownFields()
	if err = decoder.Decode(&input); err == nil {
		var extra any
		err = decoder.Decode(&extra)
	}
	match := regexp.MustCompile(`^OU=ADSDK-Search-([0-9a-f]{32}),DC=ad,DC=sdk,DC=test$`).
		FindStringSubmatch(input.Base)
	if err != io.EOF || len(match) != 2 ||
		!strings.HasSuffix(strings.ToLower(input.Server), ".ad.sdk.test") ||
		input.Domain == "" ||
		len(input.Password) == 0 ||
		input.Marker != "ad-sdk-search:"+match[1] ||
		input.Username != "adsrch"+match[1][:12] {
		clear(input.Password)
		return InternalSearchPermissionInput{}, invalid
	}
	return input, nil
}

// The harness supplies the same ordinary identity to WinLDAP and Get-ADObject.
// The password travels only through bounded stdin and is never an artifact.
func TestSearchPermissionLab(t *testing.T) {
	if os.Getenv("ADSDK_SEARCH_PERMISSION_LAB") != "1" {
		t.Skip("requires an owned ACL fixture and redirected credential input")
	}
	input, err := InternalReadSearchPermissionInput(os.Stdin)
	if err != nil {
		t.Fatal(err)
	}
	defer clear(input.Password)
	ctx, cancel := context.WithTimeout(context.Background(), 45*time.Second)
	defer cancel()
	client, err := adengine.Dial(
		ctx,
		admodel.Config{
			Endpoint: admodel.Endpoint{Host: input.Server},
			Timeout:  10 * time.Second,
			Credentials: &admodel.Credentials{
				Domain:   input.Domain,
				Username: input.Username,
				Password: input.Password,
			},
		},
	)
	if err != nil {
		t.Fatal("ordinary search identity could not bind")
	}
	defer client.Close()
	var counts InternalSearchNativeCounts
	(*adengine.InternalClientSessionPointer(client)).(*adengine.InternalLdapSession).InternalApi = InternalCountedSearchAPI(
		&counts,
	)
	rows := make([]map[string]any, 0, 3)
	for _, probe := range []struct {
		InternalName, InternalCn string
		InternalSelected         bool
		InternalState            admodel.AttributeState
	}{
		{"hidden", "ADSDK-Search-0", true, admodel.AttributeAbsent},
		{"visible", "ADSDK-Search-1", true, admodel.AttributePresent},
		{"unloaded", "ADSDK-Search-0", false, admodel.AttributeUnloaded},
	} {
		properties := []string{"objectGUID"}
		if probe.InternalSelected {
			properties = append(properties, "description")
		}
		dn := "CN=" + probe.InternalCn + "," + input.Base
		result, searchErr := client.Search(
			ctx,
			admodel.SearchOptions{Base: dn, Properties: properties, PageSize: 1},
		)
		if searchErr != nil || !result.Complete || len(result.Objects) != 1 ||
			!strings.EqualFold(result.Objects[0].DistinguishedName, dn) {
			t.Fatalf("%s search did not return its visible object", probe.InternalName)
		}
		object := result.Objects[0]
		guid, guidState := object.Attribute("objectGUID")
		value, state := object.Attribute("description")
		if guidState != admodel.AttributePresent || len(guid) != 1 || len(guid[0]) != 16 ||
			state != probe.InternalState {
			t.Fatalf("%s lost GUID visibility or description selection state", probe.InternalName)
		}
		if probe.InternalState == admodel.AttributePresent &&
			(len(value) != 1 || string(value[0]) != input.Marker) {
			t.Fatal("visible description control is missing its administrator-set value")
		}
		if probe.InternalState != admodel.AttributePresent && len(value) != 0 {
			t.Fatal("unreturned description unexpectedly has values")
		}
		rows = append(
			rows,
			map[string]any{
				"case":              probe.InternalName,
				"object":            object,
				"description_state": state,
			},
		)
	}
	if err := client.Close(); err != nil || counts != (InternalSearchNativeCounts{}) {
		t.Fatal("ordinary search native resources were not released")
	}
	artifact := map[string]any{
		"passed":                      true,
		"server":                      input.Server,
		"username":                    input.Username,
		"rows":                        rows,
		"native_allocations_released": true,
	}
	encoded, err := json.MarshalIndent(artifact, "", "  ")
	if err != nil {
		t.Fatal(err)
	}
	path := os.Getenv("ADSDK_SEARCH_PERMISSION_RESULT")
	if path == "" {
		t.Fatal("missing nonsecret permission result destination")
	}
	if err := os.WriteFile(path, append(encoded, '\n'), 0o600); err != nil {
		t.Fatal(err)
	}
}

func TestSearchPermissionInputBoundaries(t *testing.T) {
	valid := `{"Server":"dc.ad.sdk.test","Domain":"ADSDK","Username":"adsrch0123456789ab","Base":"OU=ADSDK-Search-0123456789abcdef0123456789abcdef,DC=ad,DC=sdk,DC=test","Marker":"ad-sdk-search:0123456789abcdef0123456789abcdef","Password":"c2VjcmV0"}`
	input, err := InternalReadSearchPermissionInput(strings.NewReader(valid))
	if err != nil || string(input.Password) != "secret" {
		t.Fatal("valid redirected input rejected")
	}
	clear(input.Password)
	for _, payload := range []string{
		valid + `{}`, strings.Repeat(" ", 16385),
		strings.Replace(valid, `"Password":`, `"Unexpected":0,"Password":`, 1),
		strings.Replace(valid, "ad-sdk-search:", "foreign:", 1),
		strings.Replace(valid, "dc.ad.sdk.test", "dc.example.test", 1),
		strings.Replace(valid, "adsrch0123456789ab", "Administrator", 1),
		strings.Replace(valid, "OU=ADSDK-Search-", "OU=Foreign-", 1),
		strings.Replace(valid, "c2VjcmV0", "", 1),
	} {
		input, err = InternalReadSearchPermissionInput(strings.NewReader(payload))
		if err == nil || len(input.Password) != 0 || strings.Contains(err.Error(), "secret") {
			t.Fatal("invalid credential input was accepted or exposed")
		}
	}
}
