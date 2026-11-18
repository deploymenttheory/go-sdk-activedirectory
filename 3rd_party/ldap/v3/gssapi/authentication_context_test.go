package gssapi

import (
	"testing"
	"time"
)

func TestAuthenticationFactsRequireProofAndRetainNegotiatedMode(t *testing.T) {
	client := contextTestClient(t, true)
	client.contextExpiresAt = time.Now().Add(time.Hour)
	client.channelBindingSent = true
	if _, err := client.AuthenticationContext(); err == nil {
		t.Fatal("AP-REP alone reported complete SASL authentication")
	}
	client.SASLSecurity = 4
	if _, err := client.NegotiateSaslAuth(contextTestServerOffer(t, client, []byte{7, 0, 255, 255}, 0), ""); err != nil {
		t.Fatal(err)
	}
	client.SASLSecurity = 2 // Changing a requested mode cannot change established observations.
	facts, err := client.AuthenticationContext()
	if err != nil || !facts.Complete || !facts.MutualAuthentication || !facts.ChannelBound || facts.Delegated || facts.SASLSecurity != 4 {
		t.Fatalf("authenticated context facts = %+v, error=%v", facts, err)
	}
	if err := client.DeleteSecContext(); err != nil {
		t.Fatal(err)
	}
	if _, err := client.AuthenticationContext(); err == nil {
		t.Fatal("retired context retained authentication claims")
	}
}

func TestExpiredAuthenticationFactsAreUnavailable(t *testing.T) {
	client := contextTestClient(t, false)
	client.contextExpiresAt = time.Now().Add(-time.Second)
	if _, err := client.NegotiateSaslAuth(contextTestServerOffer(t, client, []byte{1, 0, 0, 0}, 0), ""); err != nil {
		t.Fatal(err)
	}
	if _, err := client.AuthenticationContext(); err == nil {
		t.Fatal("expired mechanism context reported authenticated facts")
	}
}
