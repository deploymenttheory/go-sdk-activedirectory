package engine

import (
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
