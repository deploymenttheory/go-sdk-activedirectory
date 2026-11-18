package engine

import (
	"bytes"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestKerberosLabInputRefusesMalformedOrOversizedSecretInput(t *testing.T) {
	for _, input := range []string{`null`, `{"password_base64":"private-secret!"}`, `{"private-secret":"do-not-echo"}`, `{} {}`, strings.Repeat("private-secret", 12000)} {
		_, err := internalReadKerberosLabInput(strings.NewReader(input))
		if err == nil || strings.Contains(err.Error(), "private-secret") {
			t.Fatal("invalid lab input succeeded or disclosed credentials")
		}
	}
}

func TestKerberosLabArtifactNeverOverwritesExistingCapture(t *testing.T) {
	path := filepath.Join(t.TempDir(), "capture.json")
	before := []byte("owned original capture")
	if err := os.WriteFile(path, before, 0o600); err != nil {
		t.Fatal(err)
	}
	file, err := internalOpenKerberosLabArtifact(path)
	if file != nil || !errors.Is(err, os.ErrExist) {
		t.Fatal("existing capture was not rejected")
	}
	after, err := os.ReadFile(path)
	if err != nil || !bytes.Equal(before, after) {
		t.Fatal("original capture bytes changed")
	}
}
