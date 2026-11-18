package acceptance

import (
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/deploymenttheory/go-sdk-activedirectory/activedirectory/config"
	adengine "github.com/deploymenttheory/go-sdk-activedirectory/activedirectory/internal/engine"
	admodel "github.com/deploymenttheory/go-sdk-activedirectory/activedirectory/internal/model"
)

func TestPortableKerberosInvalidFileNeverConnectsOrUsesAmbientCredentials(t *testing.T) {
	t.Setenv("KRB5CCNAME", "must-not-use-ambient-cache")
	t.Setenv("KRB5_KTNAME", "must-not-use-ambient-keytab")
	for _, source := range []config.KerberosCredentialSource{config.KerberosKeytabFile, config.KerberosCredentialCacheFile} {
		for _, kind := range []string{"missing", "directory", "malformed", "oversized"} {
			t.Run(fmt.Sprintf("source-%d/%s", source, kind), func(t *testing.T) {
				options := kerberosContractConfig(source)
				path := filepath.Join(t.TempDir(), "credential-private-path")
				switch kind {
				case "directory":
					if err := os.Mkdir(path, 0o700); err != nil {
						t.Fatal(err)
					}
				case "malformed":
					if err := os.WriteFile(path, []byte{1, 2, 3}, 0o600); err != nil {
						t.Fatal(err)
					}
				case "oversized":
					file, err := os.OpenFile(path, os.O_CREATE|os.O_RDWR, 0o600)
					if err != nil {
						t.Fatal(err)
					}
					err = file.Truncate(16*1024*1024 + 1)
					if closeErr := file.Close(); err != nil || closeErr != nil {
						t.Fatal(errors.Join(err, closeErr))
					}
				}
				if source == config.KerberosKeytabFile {
					options.Kerberos.KeytabPath = path
				} else {
					options.Kerberos.CachePath = path
				}
				dialer := new(portableRejectDialer)
				session, err := adengine.InternalDialPortableWithDial(t.Context(), options, dialer)
				var protocol *admodel.LDAPError
				if session != nil || err == nil || !errors.Is(err, admodel.ErrKerberosAuthentication) || errors.As(err, &protocol) || dialer.calls != 0 {
					t.Fatalf("invalid selected source connected, fell back or invented LDAP status: session=%v err=%v calls=%d", session, err, dialer.calls)
				}
				for _, rendered := range []string{fmt.Sprint(err), fmt.Sprintf("%+v", err), fmt.Sprintf("%#v", err)} {
					if strings.Contains(rendered, "credential-private-path") || strings.Contains(rendered, "contract-user") {
						t.Fatal("ordinary authentication error formatting disclosed credential input")
					}
				}
			})
		}
	}
}
