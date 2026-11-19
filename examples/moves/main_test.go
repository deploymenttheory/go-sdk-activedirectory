package main

import (
	"errors"
	"testing"

	ad "github.com/deploymenttheory/go-sdk-activedirectory/activedirectory"
)

func TestIndependentDestinationCannotReuseSourceRealmOrCredentials(t *testing.T) {
	config := ad.Config{
		Backend: ad.BackendPortable, Authentication: ad.AuthenticationKerberos, Transport: ad.TransportLDAPS,
		Endpoint: ad.Endpoint{Host: "rid.target.example.test"},
		Kerberos: &ad.KerberosCredentials{
			Source: ad.KerberosKeytabFile, Username: "source", Realm: "SOURCE.EXAMPLE.TEST",
			SPN: "ldap/rid.source.example.test", KeytabPath: "/private/source.keytab",
		},
	}
	actor := destinationAuthentication{realm: "TARGET.EXAMPLE.TEST", username: "reader", cache: "/private/reader.ccache"}
	if err := actor.apply(&config); err != nil {
		t.Fatal(err)
	}
	if config.AllowDelegation || config.Kerberos.Source != ad.KerberosCredentialCacheFile || config.Kerberos.KeytabPath != "" ||
		config.Kerberos.Realm != actor.realm || config.Kerberos.Username != actor.username || config.Kerberos.SPN != "ldap/rid.target.example.test" {
		t.Fatal("destination inherited source credentials, delegation or SPN")
	}
	for _, invalid := range []destinationAuthentication{
		{realm: actor.realm},
		{username: actor.username, cache: actor.cache},
		{realm: actor.realm, username: actor.username},
		{realm: actor.realm, username: actor.username, cache: actor.cache, keytab: "/private/ambiguous.keytab"},
	} {
		if err := invalid.apply(&config); !errors.Is(err, ad.ErrInvalidConfig) {
			t.Fatal("partial or ambiguous destination identity was accepted")
		}
	}
	config.Backend, config.Authentication = ad.BackendNative, ad.AuthenticationNegotiate
	if err := actor.apply(&config); !errors.Is(err, ad.ErrInvalidConfig) {
		t.Fatal("destination silently substituted a native backend")
	}
}
