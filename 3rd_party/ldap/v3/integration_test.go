package ldap

import (
	"os"
	"testing"
)

func requireDirectoryFixture(t *testing.T) {
	t.Helper()
	if os.Getenv("ADSDK_VENDOR_LDAP_INTEGRATION") != "1" {
		t.Skip("requires an explicitly owned upstream LDAP fixture")
	}
	if ldapServer == "" || ldapsServer == "" {
		t.Fatal("LDAP_TEST_URL and LDAPS_TEST_URL must explicitly name the owned fixture")
	}
}
