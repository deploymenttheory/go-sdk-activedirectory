// Command authcontracts validates a portable authentication request offline.
// It opens no credentials or connection and prints no identity or secret.
package main

import (
	"fmt"
	"log"

	"github.com/deploymenttheory/go-sdk-activedirectory/activedirectory/config"
)

func main() {
	options := config.Config{
		Backend:        config.BackendPortable,
		Endpoint:       config.Endpoint{Host: "dc1.example.test"},
		Transport:      config.TransportLDAPS,
		Authentication: config.AuthenticationKerberos,
		Kerberos: &config.KerberosCredentials{
			Source: config.KerberosKeytabFile, Username: "automation",
			Realm: "EXAMPLE.TEST", SPN: "ldap/dc1.example.test",
			KeytabPath: "/run/secrets/automation.keytab",
		},
	}
	if err := options.Validate(); err != nil {
		log.Fatal(err)
	}
	fmt.Printf("backend: %s; configuration valid; no credential or network access\n", options.Backend)
	fmt.Println("Protocol implementation and live qualification remain separate from this contract.")
}
