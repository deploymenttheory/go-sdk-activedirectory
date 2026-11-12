package activedirectory

import (
	"bytes"
	"errors"
	"slices"
	"testing"
	"time"
)

func TestRootDSEProjectionPreservesPresenceAndUnknownValues(t *testing.T) {
	attributes := map[string][][]byte{
		"domainfunctionality": {[]byte("0")}, "isglobalcatalogready": {[]byte("FALSE")},
		"currenttime": {[]byte("20261112123456.0Z")}, "highestcommittedusn": {[]byte("18446744073709551615")},
		"namingcontexts":       {[]byte("DC=ad,DC=sdk,DC=test"), []byte("CN=配置,DC=ad,DC=sdk,DC=test")},
		"supportedldapversion": {[]byte("3"), []byte("4")}, "supportedcapabilities": {[]byte("9.8.7.6")},
		"vendor-binary": {{0, 0xff, 1}}, "vendor-empty": {{}},
	}
	result, err := decodeRootDSE(attributes, []string{"*", "currentTime"})
	if err != nil {
		t.Fatal(err)
	}
	if result.ForestFunctionality != nil || result.DomainFunctionality == nil || *result.DomainFunctionality != 0 {
		t.Fatal("missing conflated with zero")
	}
	if result.IsGlobalCatalogReady == nil || *result.IsGlobalCatalogReady {
		t.Fatal("false conflated with missing")
	}
	if result.CurrentTime == nil || !result.CurrentTime.Equal(time.Date(2026, 11, 12, 12, 34, 56, 0, time.UTC)) {
		t.Fatal("generalized time was not decoded")
	}
	if result.HighestCommittedUSN == nil || *result.HighestCommittedUSN != ^uint64(0) {
		t.Fatal("large USN truncated")
	}
	if len(result.NamingContexts) != 2 || !slices.Equal(result.SupportedLDAPVersions, []uint32{3, 4}) {
		t.Fatal("multivalued attribute truncated")
	}
	if !bytes.Equal(result.Attributes["vendor-binary"][0], []byte{0, 0xff, 1}) || len(result.Attributes["vendor-empty"]) != 1 {
		t.Fatal("raw binary/empty values lost")
	}
}

func TestRootDSERejectsMalformedTypedValues(t *testing.T) {
	for name, values := range map[string][][]byte{
		"domainfunctionality": {[]byte("4294967296")}, "isglobalcatalogready": {[]byte("1")},
		"currenttime": {[]byte("not-time")}, "dnshostname": {{0xff}},
		"highestcommittedusn": {[]byte("-1")}, "defaultnamingcontext": {[]byte("one"), []byte("two")},
	} {
		t.Run(name, func(t *testing.T) {
			result, err := decodeRootDSE(map[string][][]byte{name: values}, nil)
			if !errors.Is(err, ErrInvalidResult) || len(result.Attributes[name]) != len(values) {
				t.Fatalf("malformed value was lost or accepted: %v", err)
			}
		})
	}
}

func TestRootDSEAttributeSelection(t *testing.T) {
	properties, err := (RootDSEOptions{Properties: []string{"DNSHOSTNAME", "*", "vendor-data;binary", "*"}}).attributes()
	if err != nil {
		t.Fatal(err)
	}
	if len(properties) != len(defaultRootDSEAttributes())+2 {
		t.Fatal("selection did not deduplicate or preserve defaults")
	}
	for _, name := range []string{"", "+", "1.1", "name\x00other", "a)(objectClass=*)", "name;range=0-*", "with space"} {
		if name == "1.1" {
			continue
		} // A valid numeric OID; additive defaults remain.
		if _, err := (RootDSEOptions{Properties: []string{name}}).attributes(); !errors.Is(err, ErrInvalidProperty) {
			t.Errorf("accepted invalid selection %q", name)
		}
	}
}
