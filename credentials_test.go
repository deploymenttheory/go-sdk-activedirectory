package activedirectory

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"strings"
	"testing"
)

func TestCredentialsValidateWithoutExposingMaterial(t *testing.T) {
	for i, credential := range []Credentials{
		{}, {Username: "bad\x00name", Password: []byte("private")},
		{Username: "user", Domain: "bad\x00domain"},
		{Username: "user", Password: []byte("private\x00value")},
		{Username: string([]byte{0xff})}, {Username: "user", Password: []byte{0xff}},
	} {
		t.Run(fmt.Sprint(i), func(t *testing.T) {
			config := Config{Endpoint: Endpoint{Host: "dc.example.test"}, Credentials: &credential}
			client, err := Dial(context.Background(), config)
			if client != nil || !errors.Is(err, ErrInvalidConfig) {
				t.Fatalf("invalid credentials reached native execution: %v", err)
			}
			if strings.Contains(err.Error(), "private") || strings.Contains(err.Error(), "bad") {
				t.Fatal("credential validation exposed input material")
			}
		})
	}
	for _, credential := range []Credentials{
		{Username: "użytkownik", Domain: "ADSDK", Password: []byte("Pāss🔑")},
		{Username: "alice@example.test"}, // Explicit empty password and omitted domain.
	} {
		if err := credential.validate(); err != nil {
			t.Fatal(err)
		}
	}
}

func TestCredentialsRedactFormattingAndSerialization(t *testing.T) {
	credential := Credentials{Username: "private-user", Domain: "private-domain", Password: []byte("private-password")}
	for _, value := range []any{credential, &credential, Config{Credentials: &credential}} {
		for _, format := range []string{"%v", "%+v", "%#v"} {
			if strings.Contains(fmt.Sprintf(format, value), "private") {
				t.Fatal("formatting exposed credential material")
			}
		}
		encoded, err := json.Marshal(value)
		if err != nil || bytes.Contains(encoded, []byte("private")) {
			t.Fatal("JSON serialization exposed credential material")
		}
	}
	text, err := credential.MarshalText()
	if err != nil || bytes.Contains(text, []byte("private")) {
		t.Fatal("text serialization exposed credential material")
	}
}

func TestClientDoesNotRetainCredentials(t *testing.T) {
	client := newClient(Config{Credentials: &Credentials{Username: "user", Password: []byte("private")}}, nil)
	defer client.cancel(nil)
	if client.config.Credentials != nil {
		t.Fatal("client retained caller credentials after bind")
	}
}
