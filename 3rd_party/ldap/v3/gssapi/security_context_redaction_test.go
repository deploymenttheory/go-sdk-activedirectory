package gssapi

import (
	"bytes"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"log/slog"
	"strings"
	"testing"
)

func TestSASLSecurityContextRedactsNestedFormatsAndStructuredLogs(t *testing.T) {
	key := []byte("copied-secret-key-test-pattern")
	context := SASLSecurityContext{KeyType: 17, KeyValue: key, SASLSecurity: 4, SendSequence: 97}
	nested := struct{ Context SASLSecurityContext }{Context: context}
	encoded, err := json.Marshal(nested)
	if err != nil {
		t.Fatal(err)
	}
	var logged bytes.Buffer
	slog.New(slog.NewJSONHandler(&logged, nil)).Info("test", "context", context)
	outputs := []string{string(encoded), logged.String()}
	for _, verb := range []string{"%v", "%+v", "%#v", "%s", "%q", "%d", "%x", "%X", "%b"} {
		outputs = append(outputs, fmt.Sprintf(verb, context), fmt.Sprintf(verb, nested))
	}
	for _, output := range outputs {
		if !strings.Contains(output, "REDACTED") || strings.Contains(output, string(key)) || strings.Contains(output, hex.EncodeToString(key)) ||
			strings.Contains(output, fmt.Sprint(key)) {
			t.Fatalf("copied security context was not redacted: %s", output)
		}
	}
}
