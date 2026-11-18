package main

import (
	"bytes"
	"encoding/json"
	"strings"
	"testing"
)

func TestQualificationInputNeverEchoesSecretAndRejectsTrailingOrOversizedData(t *testing.T) {
	r := request{
		RunID:          "sdk03-fixture",
		SourceRevision: strings.Repeat("a", 40),
		Endpoint:       "dc1.ad.sdk.test",
		Port:           636,
		Transport:      "ldaps",
		CAFile:         "root.pem",
		Username:       "fixture",
		Password:       []byte("owned-test-password"),
		Expect:         "valid",
	}
	valid, err := json.Marshal(r)
	if err != nil {
		t.Fatal(err)
	}
	parsed, err := decode(bytes.NewReader(valid))
	if err != nil || !bytes.Equal(parsed.Password, r.Password) {
		t.Fatal("exact password input was not retained")
	}
	clear(parsed.Password)
	for _, bad := range [][]byte{append(append([]byte{}, valid...), []byte(" {}")...), append(append([]byte{}, valid...), bytes.Repeat([]byte{' '}, 65536)...), []byte(`{"unknown":"owned-test-password"}`)} {
		parsed, err := decode(bytes.NewReader(bad))
		if err == nil || len(parsed.Password) != 0 || strings.Contains(err.Error(), "owned-test-password") {
			t.Fatal("malformed input accepted or secret echoed")
		}
	}
}
