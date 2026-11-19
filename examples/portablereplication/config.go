package main

import (
	"crypto/x509"
	"errors"
	"net"
	"os"
	"strconv"
	"strings"
	"time"

	ad "github.com/deploymenttheory/go-sdk-activedirectory/activedirectory"
	"github.com/deploymenttheory/go-sdk-activedirectory/activedirectory/services/replication"
)

func requestConfig(input request) (ad.Config, replication.ReplicationSelection, error) {
	selection := replication.ReplicationSelection{
		Servers:           input.Servers,
		DomainDNS:         input.DomainDNS,
		ForestDNS:         input.ForestDNS,
		SiteName:          input.SiteName,
		ServicePrincipals: input.Principals,
	}
	switch input.Scope {
	case "server":
		selection.Scope = replication.ReplicationScopeServer
	case "domain":
		selection.Scope = replication.ReplicationScopeDomain
	case "forest":
		selection.Scope = replication.ReplicationScopeForest
	case "site":
		selection.Scope = replication.ReplicationScopeSite
	default:
		return ad.Config{}, selection, errors.New("scope must be server, domain, forest or site")
	}
	if input.Kind != "all" && input.Kind != "partners" && input.Kind != "failures" && input.Kind != "queue" {
		return ad.Config{}, selection, errors.New("kind must be all, partners, failures or queue")
	}
	host, port := input.Endpoint, uint16(0)
	if strings.Contains(host, ":") {
		name, service, err := net.SplitHostPort(host)
		if err != nil {
			return ad.Config{}, selection, errors.New("invalid explicit endpoint")
		}
		number, err := strconv.ParseUint(service, 10, 16)
		if err != nil || number == 0 {
			return ad.Config{}, selection, errors.New("invalid explicit endpoint port")
		}
		host, port = name, uint16(number)
	}
	config := ad.Config{
		Endpoint:       ad.Endpoint{Host: host, Port: port},
		Backend:        ad.BackendPortable,
		Authentication: ad.AuthenticationKerberos,
		Transport:      ad.TransportLDAPS,
		Timeout:        30 * time.Second,
	}
	switch input.Transport {
	case "ldaps":
	case "starttls":
		config.Transport = ad.TransportStartTLS
	case "ldap-seal":
		config.Transport, config.SASLProtection = ad.TransportLDAP, ad.SASLProtectionSeal
	default:
		return ad.Config{}, selection, errors.New("transport must require verified TLS or Kerberos sealing")
	}
	if input.Backend == "native" {
		if input.Source != "password" || len(input.Password) == 0 || input.Username == "" || input.KeytabPath != "" || input.CachePath != "" || input.CAFile != "" ||
			input.Principals != nil {
			return ad.Config{}, selection, errors.New("native reference requires explicit password credentials, system trust and no portable identity map")
		}
		config.Backend, config.Authentication = ad.BackendNative, ad.AuthenticationNegotiate
		config.SASLProtection = ad.SASLProtectionDefault
		config.Credentials = &ad.Credentials{Username: input.Username, Domain: input.Domain, Password: input.Password}
	} else {
		if input.Backend != "portable" {
			return ad.Config{}, selection, errors.New("backend must be explicitly portable or native")
		}
		config.Kerberos = &ad.KerberosCredentials{
			Username:   input.Username,
			Realm:      input.Realm,
			SPN:        input.LDAPSPN,
			Password:   input.Password,
			KeytabPath: input.KeytabPath,
			CachePath:  input.CachePath,
		}
		switch input.Source {
		case "password":
			config.Kerberos.Source = ad.KerberosPassword
		case "keytab":
			config.Kerberos.Source = ad.KerberosKeytabFile
		case "cache":
			config.Kerberos.Source = ad.KerberosCredentialCacheFile
		default:
			return ad.Config{}, selection, errors.New("source must be password, keytab or cache")
		}
		if input.CAFile != "" {
			pem, err := os.ReadFile(input.CAFile)
			if err != nil {
				return ad.Config{}, selection, errors.New("cannot read explicit public CA file")
			}
			roots := x509.NewCertPool()
			if !roots.AppendCertsFromPEM(pem) {
				return ad.Config{}, selection, errors.New("explicit CA file contains no certificate")
			}
			config.TLS = &ad.TLSOptions{RootCAs: roots}
		}
	}
	return config, selection, config.Validate()
}
