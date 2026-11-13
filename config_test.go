package activedirectory

import (
	"errors"
	"fmt"
	"math"
	"strings"
	"testing"
	"time"
)

func TestConfigPinsOneServer(t *testing.T) {
	for _, host := range []string{"dc1.ad.sdk.test", "DC1.ad.sdk.test.", "10.77.23.10", "2001:db8::1"} {
		t.Run(host, func(t *testing.T) {
			input := Config{Endpoint: Endpoint{Host: host}}
			got, err := input.normalized()
			if err != nil || got.Endpoint.Host != host || got.Endpoint.Port != 389 || got.Timeout != 30*time.Second {
				t.Fatalf("normalization = %#v, %v", got, err)
			}
			if input.Endpoint.Port != 0 || input.Timeout != 0 {
				t.Fatal("validation mutated caller configuration")
			}
		})
	}
	for index, host := range []string{
		"", "dc1", "dc1.ad.sdk.test dc2.ad.sdk.test", "ldap://user:secret@dc1.ad.sdk.test",
		"dc1.ad.sdk.test:389", "[2001:db8::1]", "fe80::1%eth0", "dc1.ad.sdk.test/path",
		"dc1.ad.sdk.test\x00ignored", "dc1..test", "-dc1.ad.test", "dc1-.ad.test", "dc1.ad.test\n",
		strings.Repeat("x", 64) + ".test", strings.Repeat("a.", 127) + "a",
	} {
		t.Run(fmt.Sprintf("reject/%d", index), func(t *testing.T) {
			err := (Config{Endpoint: Endpoint{Host: host}}).Validate()
			if !errors.Is(err, ErrInvalidConfig) {
				t.Fatalf("invalid endpoint returned %v", err)
			}
			if strings.Contains(err.Error(), "secret") {
				t.Fatal("error leaked credentials from rejected URI")
			}
		})
	}
}

func TestConfigTimeoutAndPort(t *testing.T) {
	config := Config{Endpoint: Endpoint{Host: "dc1.ad.sdk.test", Port: 3268}, Timeout: time.Millisecond}
	got, err := config.normalized()
	if err != nil || got != config {
		t.Fatalf("explicit settings changed: %#v, %v", got, err)
	}
	for _, timeout := range []time.Duration{-time.Nanosecond, time.Duration(math.MaxInt32)*time.Second + time.Nanosecond} {
		config.Timeout = timeout
		if err := config.Validate(); !errors.Is(err, ErrInvalidConfig) {
			t.Fatalf("unrepresentable timeout %v returned %v", timeout, err)
		}
	}
}

func TestConfigDelegationRequiresExplicitNegotiateDNS(t *testing.T) {
	for _, host := range []string{"src.example", "192.0.2.1", "2001:db8::1"} {
		config := Config{Endpoint: Endpoint{Host: host}, AllowDelegation: true}
		err := config.Validate()
		if host == "src.example" {
			if err != nil {
				t.Fatal(err)
			}
		} else if !errors.Is(err, ErrInvalidConfig) {
			t.Fatal(err)
		}
	}
	config := Config{Endpoint: Endpoint{Host: "src.example"}, Transport: TransportLDAPS, Authentication: AuthenticationSimple, AllowDelegation: true, Credentials: &Credentials{Username: "user", Password: []byte("test-only")}}
	if err := config.Validate(); !errors.Is(err, ErrInvalidConfig) {
		t.Fatal(err)
	}
}
