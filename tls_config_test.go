package activedirectory

import (
	"errors"
	"strings"
	"testing"
)

func TestTransportAndAuthenticationValidation(t *testing.T) {
	for _, transport := range []Transport{TransportLDAP, TransportLDAPS, TransportStartTLS} {
		config := Config{Endpoint: Endpoint{Host: "lds.ad.sdk.test"}, Transport: transport}
		normalized, err := config.normalized()
		wantPort := uint16(389)
		if transport == TransportLDAPS {
			wantPort = 636
		}
		if err != nil || normalized.Endpoint.Port != wantPort {
			t.Fatalf("transport %d default port: %d, %v", transport, normalized.Endpoint.Port, err)
		}
		config.Endpoint.Port = 51301
		normalized, err = config.normalized()
		if err != nil || normalized.Endpoint.Port != 51301 {
			t.Fatalf("custom port changed: %d, %v", normalized.Endpoint.Port, err)
		}
		config.Authentication = AuthenticationSimple
		config.Credentials = &Credentials{Username: "CN=user,CN=application", Password: []byte("synthetic-password")}
		err = config.Validate()
		if (transport == TransportLDAP) != errors.Is(err, ErrInvalidConfig) {
			t.Fatalf("simple transport %d: %v", transport, err)
		}
	}
	for _, credentials := range []*Credentials{
		nil,
		{Username: "CN=user,CN=application"},
		{Username: "CN=user,CN=application", Domain: "secret-domain", Password: []byte("secret-password")},
		{Password: []byte("secret-password")},
	} {
		config := Config{Endpoint: Endpoint{Host: "lds.ad.sdk.test"}, Transport: TransportLDAPS, Authentication: AuthenticationSimple, Credentials: credentials}
		err := config.Validate()
		if !errors.Is(err, ErrInvalidConfig) || strings.Contains(err.Error(), "secret-") {
			t.Fatalf("invalid simple credentials: %v", err)
		}
	}
	for _, config := range []Config{
		{Transport: Transport(255)}, {Authentication: AuthenticationMethod(255)},
		{Partition: "secret-partition\x00"}, {Partition: string([]byte{0xff})},
	} {
		config.Endpoint.Host = "lds.ad.sdk.test"
		err := config.Validate()
		if !errors.Is(err, ErrInvalidConfig) || strings.Contains(err.Error(), "secret-") {
			t.Fatalf("invalid TLS/partition configuration: %v", err)
		}
	}
}
