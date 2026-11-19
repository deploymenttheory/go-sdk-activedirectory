package main

import (
	"crypto/x509"
	"errors"
	"io"
	"net"
	"os"
	"strconv"
	"strings"
	"time"

	ad "github.com/deploymenttheory/go-sdk-activedirectory/activedirectory"
	"github.com/deploymenttheory/go-sdk-activedirectory/activedirectory/services/discovery"
)

type request struct {
	DomainDNS          string   `json:"domain_dns"`
	Endpoint           string   `json:"endpoint"`
	SiteName           string   `json:"site_name,omitempty"`
	LookupDNS          bool     `json:"lookup_dns"`
	DNSPort            uint16   `json:"dns_port,omitempty"`
	Transport          string   `json:"transport"`
	Authentication     string   `json:"authentication"`
	Source             string   `json:"source"`
	Username           string   `json:"username"`
	Realm              string   `json:"realm,omitempty"`
	SPN                string   `json:"ldap_spn,omitempty"`
	Password           []byte   `json:"password_base64,omitempty"`
	KeytabPath         string   `json:"keytab_path,omitempty"`
	CachePath          string   `json:"cache_path,omitempty"`
	CAFile             string   `json:"ca_file,omitempty"`
	ExpectedDomainGUID string   `json:"expected_domain_guid,omitempty"`
	ExpectedDomainSID  string   `json:"expected_domain_sid,omitempty"`
	ExpectedDSAGUID    string   `json:"expected_dsa_guid,omitempty"`
	Projections        []string `json:"projections,omitempty"`
	RunID              string   `json:"run_id,omitempty"`
	SourceRevision     string   `json:"source_revision,omitempty"`
	Result             string   `json:"result,omitempty"`
}

func requestConfig(input request) (ad.Config, discovery.DomainControllerSelection, error) {
	selection := discovery.DomainControllerSelection{
		DomainDNS:          input.DomainDNS,
		SiteName:           input.SiteName,
		ExpectedDomainGUID: input.ExpectedDomainGUID,
		ExpectedDomainSID:  input.ExpectedDomainSID,
		ExpectedDSAGUID:    input.ExpectedDSAGUID,
	}
	host, port := input.Endpoint, uint16(0)
	if strings.Contains(host, ":") {
		name, service, err := net.SplitHostPort(host)
		if err != nil {
			return ad.Config{}, selection, errors.New("invalid explicit controller endpoint")
		}
		number, err := strconv.ParseUint(service, 10, 16)
		if err != nil || number == 0 {
			return ad.Config{}, selection, errors.New("invalid explicit controller port")
		}
		host, port = name, uint16(number)
	}
	config := ad.Config{Backend: ad.BackendPortable, Endpoint: ad.Endpoint{Host: host, Port: port}, Timeout: 30 * time.Second}
	if err := selection.Validate(config.Endpoint); err != nil {
		return config, selection, err
	}
	switch input.Transport {
	case "ldaps":
		config.Transport = ad.TransportLDAPS
	case "starttls":
		config.Transport = ad.TransportStartTLS
	case "ldap-sign":
		config.Transport, config.SASLProtection = ad.TransportLDAP, ad.SASLProtectionSign
	case "ldap-seal":
		config.Transport, config.SASLProtection = ad.TransportLDAP, ad.SASLProtectionSeal
	default:
		return config, selection, errors.New("verified TLS or explicit Kerberos signing/sealing is required")
	}
	if input.Authentication == "simple" {
		if input.Source != "password" || input.Realm != "" || input.SPN != "" || input.KeytabPath != "" || input.CachePath != "" {
			return config, selection, errors.New("simple authentication requires only explicit password credentials")
		}
		config.Authentication = ad.AuthenticationSimple
		config.Credentials = &ad.Credentials{Username: input.Username, Password: input.Password}
	} else if input.Authentication == "kerberos" {
		config.Authentication = ad.AuthenticationKerberos
		config.Kerberos = &ad.KerberosCredentials{
			Username:   input.Username,
			Realm:      input.Realm,
			SPN:        input.SPN,
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
			return config, selection, errors.New("one explicit Kerberos credential source is required")
		}
	} else {
		return config, selection, errors.New("authentication must be explicitly simple or kerberos")
	}
	if input.CAFile != "" {
		if config.Transport == ad.TransportLDAP {
			return config, selection, errors.New("CA trust applies only to verified TLS transports")
		}
		file, err := os.Open(input.CAFile)
		if err != nil {
			return config, selection, errors.New("cannot open explicit public CA file")
		}
		data, readErr := io.ReadAll(io.LimitReader(file, 1024*1024+1))
		closeErr := file.Close()
		if readErr != nil || closeErr != nil || len(data) > 1024*1024 {
			return config, selection, errors.New("cannot read bounded public CA file")
		}
		roots := x509.NewCertPool()
		if !roots.AppendCertsFromPEM(data) {
			return config, selection, errors.New("public CA file contains no usable certificate")
		}
		config.TLS = &ad.TLSOptions{RootCAs: roots}
	}
	return config, selection, config.Validate()
}
