package acceptance

import (
	"errors"
	"strings"
	"testing"

	admodel "github.com/deploymenttheory/go-sdk-activedirectory/activedirectory/internal/model"
)

func TestTransportAndAuthenticationValidation(t *testing.T) {
	for _, transport := range []admodel.Transport{admodel.TransportLDAP, admodel.TransportLDAPS, admodel.TransportStartTLS} {
		config := admodel.Config{
			Endpoint:  admodel.Endpoint{Host: "lds.ad.sdk.test"},
			Transport: transport,
		}
		normalized, err := admodel.InternalConfigNormalized(config)
		wantPort := uint16(389)
		if transport == admodel.TransportLDAPS {
			wantPort = 636
		}
		if err != nil || normalized.Endpoint.Port != wantPort {
			t.Fatalf("transport %d default port: %d, %v", transport, normalized.Endpoint.Port, err)
		}
		config.Endpoint.Port = 51301
		normalized, err = admodel.InternalConfigNormalized(config)
		if err != nil || normalized.Endpoint.Port != 51301 {
			t.Fatalf("custom port changed: %d, %v", normalized.Endpoint.Port, err)
		}
		config.Authentication = admodel.AuthenticationSimple
		config.Credentials = &admodel.Credentials{
			Username: "CN=user,CN=application",
			Password: []byte("synthetic-password"),
		}
		err = config.Validate()
		if (transport == admodel.TransportLDAP) != errors.Is(err, admodel.ErrInvalidConfig) {
			t.Fatalf("simple transport %d: %v", transport, err)
		}
	}
	for _, credentials := range []*admodel.Credentials{
		nil,
		{Username: "CN=user,CN=application"},
		{Username: "CN=user,CN=application", Domain: "secret-domain", Password: []byte("secret-password")},
		{Password: []byte("secret-password")},
	} {
		config := admodel.Config{
			Endpoint:       admodel.Endpoint{Host: "lds.ad.sdk.test"},
			Transport:      admodel.TransportLDAPS,
			Authentication: admodel.AuthenticationSimple,
			Credentials:    credentials,
		}
		err := config.Validate()
		if !errors.Is(err, admodel.ErrInvalidConfig) || strings.Contains(err.Error(), "secret-") {
			t.Fatalf("invalid simple credentials: %v", err)
		}
	}
	for _, config := range []admodel.Config{
		{Transport: admodel.Transport(255)},
		{Authentication: admodel.AuthenticationMethod(255)},
		{Partition: "secret-partition\x00"},
		{Partition: string([]byte{0xff})},
	} {
		config.Endpoint.Host = "lds.ad.sdk.test"
		err := config.Validate()
		if !errors.Is(err, admodel.ErrInvalidConfig) || strings.Contains(err.Error(), "secret-") {
			t.Fatalf("invalid TLS/partition configuration: %v", err)
		}
	}
}
