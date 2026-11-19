package main

import (
	"bytes"
	"context"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"

	ad "github.com/deploymenttheory/go-sdk-activedirectory/activedirectory"
	"github.com/deploymenttheory/go-sdk-activedirectory/activedirectory/services/discovery"
	"github.com/deploymenttheory/go-sdk-activedirectory/activedirectory/services/replication"
)

func TestReplicationInputIsBoundedStrictAndDoesNotEchoCredentials(t *testing.T) {
	for _, input := range []string{"", `[]`, `{"password_base64":"U0VDUkVULVBSSVZBVEU=","unknown_secret":"SECRET-PRIVATE"}`, `{} {}`, strings.Repeat("x", 128*1024+1)} {
		_, err := readRequest(strings.NewReader(input))
		if err == nil || strings.Contains(err.Error(), "SECRET") || strings.Contains(err.Error(), "U0VDUkVU") {
			t.Fatal("invalid input accepted or private input echoed")
		}
	}
}

func TestReplicationExampleRequiresExplicitProtectedAuthentication(t *testing.T) {
	input := request{
		Endpoint:   "dc.example.test",
		Backend:    "portable",
		Transport:  "ldap-seal",
		Source:     "keytab",
		Username:   "client",
		Realm:      "EXAMPLE.TEST",
		LDAPSPN:    "ldap/dc.example.test",
		KeytabPath: "caller-owned.keytab",
		Scope:      "server",
		Kind:       "all",
	}
	config, _, err := requestConfig(input)
	if err != nil || config.Authentication != ad.AuthenticationKerberos || config.SASLProtection != ad.SASLProtectionSeal {
		t.Fatal("explicit keytab sealing example rejected", err)
	}
	for _, transport := range []string{"ldap", "insecure", ""} {
		input.Transport = transport
		if _, _, err = requestConfig(input); err == nil {
			t.Fatal("unprotected transport accepted")
		}
	}
	input.Transport = "ldaps"
	input.Backend = "native"
	if _, _, err = requestConfig(input); err == nil {
		t.Fatal("portable keytab silently selected current Windows identity")
	}
}

func TestReplicationReportRequiresFreshPathAndDoesNotEchoPrivateMetadata(t *testing.T) {
	path := filepath.Join(t.TempDir(), "existing.json")
	if err := os.WriteFile(path, []byte("preserved"), 0o600); err != nil {
		t.Fatal(err)
	}
	var output bytes.Buffer
	if err := run(strings.NewReader(`{"result":"`+filepath.ToSlash(path)+`"}`), &output); err == nil {
		t.Fatal("existing report overwritten")
	}
	data, err := os.ReadFile(path)
	if err != nil || string(data) != "preserved" {
		t.Fatal("existing report was not preserved")
	}
	result, err := probe(context.Background(), request{SourceRevision: "secret-private-invalid-source", Password: []byte("SECRET-PRIVATE")})
	if err == nil || result.SourceRevision != "" || result.RunID != "" {
		t.Fatal("untrusted source label accepted or echoed")
	}
}

func TestReplicationStatusReportPreservesRealCodesAndDeduplicatesJoinedCauses(t *testing.T) {
	actual := &discovery.NativeStatusError{Operation: "IDL_DRSGetReplInfo", Code: 8453}
	values := statuses(errors.Join(actual, errors.Join(actual, &ad.LDAPError{Code: 50})))
	if len(values) != 2 {
		t.Fatal("exact real protocol codes lost or duplicate error graph inflated statuses")
	}
	found := false
	for _, value := range values {
		if value.Protocol == "win32-rpc" && value.Operation == "IDL_DRSGetReplInfo" && value.Code == 8453 {
			found = true
		}
	}
	if !found {
		t.Fatal("actual DRS status translated to another protocol/code")
	}
	values = statuses(
		errors.Join(
			&replication.ReplicationReadError{Server: ad.Endpoint{Host: "one.example.test"}, Cause: actual},
			&replication.ReplicationReadError{Server: ad.Endpoint{Host: "two.example.test"}, Cause: actual},
		),
	)
	if len(values) != 2 || values[0].Server == nil || values[1].Server == nil || values[0].Server.Host == values[1].Server.Host {
		t.Fatal("per-server status ownership collapsed")
	}
}
