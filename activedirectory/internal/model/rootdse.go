package model

import (
	"errors"
	"fmt"
	"regexp"
	"slices"
	"strconv"
	"strings"
	"time"
	"unicode/utf8"
)

func (e *LDAPError) Error() string { return fmt.Sprintf("%s: LDAP status %d", e.Operation, e.Code) }

// RootDSEOptions adds attribute names to the stable default projection. Use
// "*" to also request server-returned user attributes. Operational attributes
// may require explicit names even with "*"; it does not promise every property.
type RootDSEOptions struct{ Properties []string }

var InternalAttributeDescription = regexp.MustCompile(
	`^(?:[A-Za-z][A-Za-z0-9-]*|[0-9]+(?:\.[0-9]+)+)(?:;[A-Za-z0-9-]+)*$`,
)

func InternalDefaultRootDSEAttributes() []string {
	return []string{
		"configurationNamingContext",
		"currentTime",
		"defaultNamingContext",
		"dnsHostName",
		"domainControllerFunctionality",
		"domainFunctionality",
		"dsServiceName",
		"forestFunctionality",
		"highestCommittedUSN",
		"isGlobalCatalogReady",
		"isSynchronized",
		"ldapServiceName",
		"namingContexts",
		"rootDomainNamingContext",
		"schemaNamingContext",
		"serverName",
		"subschemaSubentry",
		"supportedCapabilities",
		"supportedControl",
		"supportedLDAPPolicies",
		"supportedLDAPVersion",
		"supportedSASLMechanisms",
	}
}

func InternalRootDSEOptionsAttributes(o RootDSEOptions) ([]string, error) {
	attributes := InternalDefaultRootDSEAttributes()
	seen := make(map[string]bool, len(attributes)+len(o.Properties))
	for _, name := range attributes {
		seen[strings.ToLower(name)] = true
	}
	for _, name := range o.Properties {
		if name != "*" && !InternalAttributeDescription.MatchString(name) {
			return nil, ErrInvalidProperty
		}
		key := strings.ToLower(name)
		if !seen[key] {
			attributes = append(attributes, name)
			seen[key] = true
		}
	}
	return attributes, nil
}

// RootDSE preserves optional scalar values with pointers: absent is distinct
// from zero, false, or empty. Functional levels are raw numeric levels, not OS
// versions or schema versions. Advertised capabilities do not prove permission
// or that an authentication mechanism was negotiated by this connection.
type RootDSE struct {
	ConfigurationNamingContext    *string
	CurrentTime                   *time.Time
	DefaultNamingContext          *string
	DNSHostName                   *string
	DomainControllerFunctionality *uint32
	DomainFunctionality           *uint32
	DSServiceName                 *string
	ForestFunctionality           *uint32
	HighestCommittedUSN           *uint64
	IsGlobalCatalogReady          *bool
	IsSynchronized                *bool
	LDAPServiceName               *string
	NamingContexts                []string
	RootDomainNamingContext       *string
	SchemaNamingContext           *string
	ServerName                    *string
	SubschemaSubentry             *string
	SupportedCapabilities         []string
	SupportedControls             []string
	SupportedLDAPPolicies         []string
	SupportedLDAPVersions         []uint32
	SupportedSASLMechanisms       []string

	// Attributes uses lowercase attribute descriptions and owns all value bytes.
	// Unknown and binary attributes are preserved. An absent map key means the
	// server did not return it; absence does not prove that the schema lacks it.
	Attributes          map[string][][]byte
	RequestedProperties []string
}

func InternalDecodeRootDSE(attributes map[string][][]byte, requested []string) (RootDSE, error) {
	result := RootDSE{Attributes: attributes, RequestedProperties: slices.Clone(requested)}
	decoder := InternalRootDSEDecoder{InternalAttributes: attributes}
	result.ConfigurationNamingContext = decoder.InternalText("configurationNamingContext")
	result.CurrentTime = InternalDecodeScalar(
		&decoder,
		"currentTime",
		func(s string) (time.Time, error) { return time.Parse("20060102150405Z", s) },
	)
	result.DefaultNamingContext = decoder.InternalText("defaultNamingContext")
	result.DNSHostName = decoder.InternalText("dnsHostName")
	result.DomainControllerFunctionality = InternalDecodeScalar(
		&decoder,
		"domainControllerFunctionality",
		InternalParseUint32,
	)
	result.DomainFunctionality = InternalDecodeScalar(
		&decoder,
		"domainFunctionality",
		InternalParseUint32,
	)
	result.DSServiceName = decoder.InternalText("dsServiceName")
	result.ForestFunctionality = InternalDecodeScalar(
		&decoder,
		"forestFunctionality",
		InternalParseUint32,
	)
	result.HighestCommittedUSN = InternalDecodeScalar(
		&decoder,
		"highestCommittedUSN",
		func(s string) (uint64, error) { return strconv.ParseUint(s, 10, 64) },
	)
	result.IsGlobalCatalogReady = InternalDecodeScalar(
		&decoder,
		"isGlobalCatalogReady",
		InternalParseLDAPBool,
	)
	result.IsSynchronized = InternalDecodeScalar(&decoder, "isSynchronized", InternalParseLDAPBool)
	result.LDAPServiceName = decoder.InternalText("ldapServiceName")
	result.NamingContexts = decoder.InternalTexts("namingContexts")
	result.RootDomainNamingContext = decoder.InternalText("rootDomainNamingContext")
	result.SchemaNamingContext = decoder.InternalText("schemaNamingContext")
	result.ServerName = decoder.InternalText("serverName")
	result.SubschemaSubentry = decoder.InternalText("subschemaSubentry")
	result.SupportedCapabilities = decoder.InternalTexts("supportedCapabilities")
	result.SupportedControls = decoder.InternalTexts("supportedControl")
	result.SupportedLDAPPolicies = decoder.InternalTexts("supportedLDAPPolicies")
	result.SupportedSASLMechanisms = decoder.InternalTexts("supportedSASLMechanisms")
	for _, text := range decoder.InternalTexts("supportedLDAPVersion") {
		value, err := InternalParseUint32(text)
		if err != nil {
			decoder.InternalInvalid("supportedLDAPVersion")
			continue
		}
		result.SupportedLDAPVersions = append(result.SupportedLDAPVersions, value)
	}
	return result, errors.Join(decoder.InternalErrors...)
}

type InternalRootDSEDecoder struct {
	InternalAttributes map[string][][]byte
	InternalErrors     []error
}

func (d *InternalRootDSEDecoder) InternalInvalid(name string) {
	d.InternalErrors = append(
		d.InternalErrors,
		fmt.Errorf("%w: attribute %s has invalid syntax or cardinality", ErrInvalidResult, name),
	)
}

func (d *InternalRootDSEDecoder) InternalTexts(name string) []string {
	values, found := d.InternalAttributes[strings.ToLower(name)]
	if !found {
		return nil
	}
	if len(values) == 0 {
		d.InternalInvalid(name)
		return nil
	}
	result := make([]string, 0, len(values))
	for _, value := range values {
		if !utf8.Valid(value) || strings.ContainsRune(string(value), 0) {
			d.InternalInvalid(name)
			continue
		}
		result = append(result, string(value))
	}
	return result
}

func (d *InternalRootDSEDecoder) InternalText(name string) *string {
	return InternalDecodeScalar(d, name, func(s string) (string, error) { return s, nil })
}

func InternalDecodeScalar[T any](
	d *InternalRootDSEDecoder,
	name string,
	parse func(string) (T, error),
) *T {
	if raw, found := d.InternalAttributes[strings.ToLower(name)]; found && len(raw) != 1 {
		d.InternalInvalid(name)
		return nil
	}
	values := d.InternalTexts(name)
	if values == nil {
		return nil
	}
	if len(values) != 1 {
		d.InternalInvalid(name)
		return nil
	}
	value, err := parse(values[0])
	if err != nil {
		d.InternalInvalid(name)
		return nil
	}
	return &value
}

func InternalParseInt64(s string) (int64, error) {
	return strconv.ParseInt(s, 10, 64)
}

func InternalParseUint32(s string) (uint32, error) {
	n, err := strconv.ParseUint(s, 10, 32)
	return uint32(n), err
}

func InternalParseLDAPBool(s string) (bool, error) {
	switch s {
	case "TRUE":
		return true, nil
	case "FALSE":
		return false, nil
	default:
		return false, ErrInvalidResult
	}
}
