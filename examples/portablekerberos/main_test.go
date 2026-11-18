package main

import (
	"bytes"
	"encoding/base64"
	"strings"
	"testing"
)

func TestInputPreservesExactPasswordAndRefusesAmbiguousSource(t *testing.T) {
	password := []byte("  unit fixture:\nΔ\r\n")
	text := `{"endpoint":"dc.ad.sdk.test:636","transport":"ldaps","source":"password","username":"owned-fixture","realm":"AD.SDK.TEST","spn":"ldap/dc.ad.sdk.test","password_base64":"` +
		base64.StdEncoding.EncodeToString(
			password,
		) + `"}`
	input, err := readRequest(strings.NewReader(text))
	if err != nil || !bytes.Equal(input.Password, password) {
		t.Fatal("stdin changed the exact password bytes")
	}
	defer clear(input.Password)
	if _, err := requestConfig(input); err != nil {
		t.Fatal(err)
	}
	input.KeytabPath = "must-not-silently-ignore.keytab"
	if _, err := requestConfig(input); err == nil {
		t.Fatal("multiple credential sources were accepted")
	}
}

func TestInputRefusesMalformedDataWithoutEchoingSecrets(t *testing.T) {
	for _, input := range []string{`null`, `{"password_base64":"private-secret!"}`, `{"private-secret":"do-not-echo"}`, `{} {}`, strings.Repeat("private-secret", 12000)} {
		var output bytes.Buffer
		err := run(strings.NewReader(input), &output)
		if err == nil || strings.Contains(err.Error(), "private-secret") || strings.Contains(output.String(), "private-secret") {
			t.Fatal("invalid input succeeded or disclosed raw credentials")
		}
	}
}
