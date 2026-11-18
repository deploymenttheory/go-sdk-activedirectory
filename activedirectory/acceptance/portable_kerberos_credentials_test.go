package acceptance

import (
	"bytes"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

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

func TestPortableKerberosCacheWrongIdentityOrExpiryNeverConnectsOrRenews(t *testing.T) {
	for _, scenario := range []string{"wrong-client", "expired"} {
		t.Run(scenario, func(t *testing.T) {
			kdc := newPortableKerberosKDC(t)
			client, end := portableKerberosUser, time.Now().Add(time.Hour)
			if scenario == "wrong-client" {
				client = "another-owned-client"
			} else {
				end = time.Now().Add(-time.Second)
			}
			data := portableKerberosCacheFile(t, kdc, client, true, end)
			defer clear(data)
			path := filepath.Join(t.TempDir(), "owned.ccache")
			if err := os.WriteFile(path, data, 0o600); err != nil {
				t.Fatal(err)
			}
			options := kerberosContractConfig(config.KerberosCredentialCacheFile)
			options.Kerberos.Username = portableKerberosUser
			options.Kerberos.CachePath = path
			dialer := new(portableRejectDialer)
			session, err := adengine.InternalDialPortableWithDial(t.Context(), options, dialer)
			if session != nil || err == nil || dialer.calls != 0 || kdc.requests.Load() != 0 {
				t.Fatalf("invalid cache changed source or renewed: %v", err)
			}
			if scenario == "expired" && !errors.Is(err, admodel.ErrKerberosExpired) {
				t.Fatalf("expired cache lost precise cause: %v", err)
			}
			after, err := os.ReadFile(path)
			if err != nil || !bytes.Equal(data, after) {
				t.Fatal("SDK modified caller credential cache")
			}
			clear(after)
		})
	}
}
