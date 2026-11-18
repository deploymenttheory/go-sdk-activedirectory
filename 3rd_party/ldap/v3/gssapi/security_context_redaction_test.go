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
	for _, output := range []string{fmt.Sprint(context), fmt.Sprintf("%+v", nested), fmt.Sprintf("%#v", nested), string(encoded), logged.String()} {
		if !strings.Contains(output, "REDACTED") || strings.Contains(output, string(key)) || strings.Contains(output, hex.EncodeToString(key)) ||
			strings.Contains(output, fmt.Sprint(key)) {
			t.Fatalf("copied security context was not redacted: %s", output)
		}
	}
}
