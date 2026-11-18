package acceptance

import (
	"errors"
	"fmt"
	"strings"
	"testing"

	admodel "github.com/deploymenttheory/go-sdk-activedirectory/activedirectory/internal/model"
)

func TestKerberosInputsAndErrorsRedactAcrossEveryFormattingVerb(t *testing.T) {
	credential := admodel.KerberosCredentials{
		Source: admodel.KerberosPassword, Username: "private-user", Realm: "PRIVATE.TEST", SPN: "ldap/private.example.test",
		Password: []byte("private-key-bytes"), KeytabPath: "private-keytab-path", CachePath: "private-cache-path",
	}
	err := admodel.InternalKerberosError(7, errors.New("private-error-cause"))
	for _, value := range []any{credential, &credential, err, struct{ Value any }{credential}, struct{ Value any }{err}} {
		for _, format := range []string{"%v", "%+v", "%#v", "%d", "%x", "%X", "%q", "%s", "%f"} {
			rendered := fmt.Sprintf(format, value)
			if strings.Contains(rendered, "private-") || strings.Contains(rendered, "PRIVATE.TEST") || strings.Contains(rendered, "707269766174652d") {
				t.Fatalf("format %s disclosed secret data", format)
			}
			if !strings.Contains(rendered, "redacted") && !strings.Contains(rendered, "explicit Kerberos authentication failed") {
				t.Fatalf("format %s bypassed the safe representation", format)
			}
		}
	}
}
