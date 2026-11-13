package activedirectory

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

var attributeDescription = regexp.MustCompile(`^(?:[A-Za-z][A-Za-z0-9-]*|[0-9]+(?:\.[0-9]+)+)(?:;[A-Za-z0-9-]+)*$`)

func defaultRootDSEAttributes() []string {
	return []string{
		"configurationNamingContext", "currentTime", "defaultNamingContext", "dnsHostName",
		"domainControllerFunctionality", "domainFunctionality", "dsServiceName", "forestFunctionality",
		"highestCommittedUSN", "isGlobalCatalogReady", "isSynchronized", "ldapServiceName",
		"namingContexts", "rootDomainNamingContext", "schemaNamingContext", "serverName", "subschemaSubentry",
		"supportedCapabilities", "supportedControl", "supportedLDAPPolicies", "supportedLDAPVersion", "supportedSASLMechanisms",
	}
}

func (o RootDSEOptions) attributes() ([]string, error) {
	attributes := defaultRootDSEAttributes()
	seen := make(map[string]bool, len(attributes)+len(o.Properties))
	for _, name := range attributes {
		seen[strings.ToLower(name)] = true
	}
	for _, name := range o.Properties {
		if name != "*" && !attributeDescription.MatchString(name) {
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

func decodeRootDSE(attributes map[string][][]byte, requested []string) (RootDSE, error) {
	result := RootDSE{Attributes: attributes, RequestedProperties: slices.Clone(requested)}
	decoder := rootDSEDecoder{attributes: attributes}
	result.ConfigurationNamingContext = decoder.text("configurationNamingContext")
	result.CurrentTime = decodeScalar(&decoder, "currentTime", func(s string) (time.Time, error) { return time.Parse("20060102150405Z", s) })
	result.DefaultNamingContext = decoder.text("defaultNamingContext")
	result.DNSHostName = decoder.text("dnsHostName")
	result.DomainControllerFunctionality = decodeScalar(&decoder, "domainControllerFunctionality", parseUint32)
	result.DomainFunctionality = decodeScalar(&decoder, "domainFunctionality", parseUint32)
	result.DSServiceName = decoder.text("dsServiceName")
	result.ForestFunctionality = decodeScalar(&decoder, "forestFunctionality", parseUint32)
	result.HighestCommittedUSN = decodeScalar(&decoder, "highestCommittedUSN", func(s string) (uint64, error) { return strconv.ParseUint(s, 10, 64) })
	result.IsGlobalCatalogReady = decodeScalar(&decoder, "isGlobalCatalogReady", parseLDAPBool)
	result.IsSynchronized = decodeScalar(&decoder, "isSynchronized", parseLDAPBool)
	result.LDAPServiceName = decoder.text("ldapServiceName")
	result.NamingContexts = decoder.texts("namingContexts")
	result.RootDomainNamingContext = decoder.text("rootDomainNamingContext")
	result.SchemaNamingContext = decoder.text("schemaNamingContext")
	result.ServerName = decoder.text("serverName")
	result.SubschemaSubentry = decoder.text("subschemaSubentry")
	result.SupportedCapabilities = decoder.texts("supportedCapabilities")
	result.SupportedControls = decoder.texts("supportedControl")
	result.SupportedLDAPPolicies = decoder.texts("supportedLDAPPolicies")
	result.SupportedSASLMechanisms = decoder.texts("supportedSASLMechanisms")
	for _, text := range decoder.texts("supportedLDAPVersion") {
		value, err := parseUint32(text)
		if err != nil {
			decoder.invalid("supportedLDAPVersion")
			continue
		}
		result.SupportedLDAPVersions = append(result.SupportedLDAPVersions, value)
	}
	return result, errors.Join(decoder.errors...)
}

type rootDSEDecoder struct {
	attributes map[string][][]byte
	errors     []error
}

func (d *rootDSEDecoder) invalid(name string) {
	d.errors = append(d.errors, fmt.Errorf("%w: attribute %s has invalid syntax or cardinality", ErrInvalidResult, name))
}

func (d *rootDSEDecoder) texts(name string) []string {
	values, found := d.attributes[strings.ToLower(name)]
	if !found {
		return nil
	}
	if len(values) == 0 {
		d.invalid(name)
		return nil
	}
	result := make([]string, 0, len(values))
	for _, value := range values {
		if !utf8.Valid(value) || strings.ContainsRune(string(value), 0) {
			d.invalid(name)
			continue
		}
		result = append(result, string(value))
	}
	return result
}

func (d *rootDSEDecoder) text(name string) *string {
	return decodeScalar(d, name, func(s string) (string, error) { return s, nil })
}

func decodeScalar[T any](d *rootDSEDecoder, name string, parse func(string) (T, error)) *T {
	if raw, found := d.attributes[strings.ToLower(name)]; found && len(raw) != 1 {
		d.invalid(name)
		return nil
	}
	values := d.texts(name)
	if values == nil {
		return nil
	}
	if len(values) != 1 {
		d.invalid(name)
		return nil
	}
	value, err := parse(values[0])
	if err != nil {
		d.invalid(name)
		return nil
	}
	return &value
}

func parseInt64(s string) (int64, error) {
	return strconv.ParseInt(s, 10, 64)
}

func parseUint32(s string) (uint32, error) {
	n, err := strconv.ParseUint(s, 10, 32)
	return uint32(n), err
}

func parseLDAPBool(s string) (bool, error) {
	switch s {
	case "TRUE":
		return true, nil
	case "FALSE":
		return false, nil
	default:
		return false, ErrInvalidResult
	}
}
