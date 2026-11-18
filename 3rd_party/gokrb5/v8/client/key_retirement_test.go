package client

import (
	"bytes"
	"fmt"
	"strings"
	"testing"
	"time"

	"github.com/deploymenttheory/go-sdk-activedirectory/3rd_party/gokrb5/v8/config"
	"github.com/deploymenttheory/go-sdk-activedirectory/3rd_party/gokrb5/v8/messages"
	"github.com/deploymenttheory/go-sdk-activedirectory/3rd_party/gokrb5/v8/types"
)

func TestStrictClientDestroyClearsOwnedKeysWithoutClearingCallerCopies(t *testing.T) {
	cl := NewWithPassword("owned-fixture", "EXAMPLE.TEST", "fixture-only", config.New(), StrictRealm("EXAMPLE.TEST"))
	input := types.EncryptionKey{KeyType: 18, KeyValue: bytes.Repeat([]byte{0x61}, 32)}
	spn := types.NewPrincipalName(2, "ldap/dc.example.test")
	ticket := messages.Ticket{TktVNO: 5, Realm: "EXAMPLE.TEST", SName: spn, EncPart: types.EncryptedData{EType: 18}}
	cl.cache.addEntry(ticket, time.Now().Add(-time.Minute), time.Now().Add(-time.Minute), time.Now().Add(time.Hour), time.Time{}, input)
	_, held, ok := cl.GetCachedTicket("ldap/dc.example.test")
	if !ok {
		t.Fatal("valid owned cache entry was unavailable")
	}
	copied, err := cl.GetServiceTicketWithValidity("ldap/dc.example.test")
	if err != nil {
		t.Fatal(err)
	}
	cl.Destroy()
	if !bytes.Equal(held.KeyValue, make([]byte, 32)) {
		t.Fatal("retired strict client retained its owned service key")
	}
	if !bytes.Equal(input.KeyValue, bytes.Repeat([]byte{0x61}, 32)) || !bytes.Equal(copied.Key.KeyValue, input.KeyValue) {
		t.Fatal("retirement overwrote caller-owned input or exported key copy")
	}
	clear(copied.Key.KeyValue)
}

func TestServiceTicketRedactsKeysForNumericAndNestedFormatting(t *testing.T) {
	ticket := ServiceTicket{Key: types.EncryptionKey{KeyType: 18, KeyValue: []byte("private-service-key")}}
	for _, value := range []any{ticket, &ticket, struct{ Ticket any }{ticket}} {
		for _, format := range []string{"%v", "%+v", "%#v", "%d", "%x", "%q", "%s", "%f"} {
			if rendered := fmt.Sprintf(format, value); !strings.Contains(rendered, "ServiceTicket{redacted}") {
				t.Fatalf("format %s bypassed key redaction", format)
			}
		}
	}
}
