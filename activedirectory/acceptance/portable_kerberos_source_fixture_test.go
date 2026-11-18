package acceptance

import (
	"encoding/binary"
	"math"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/deploymenttheory/go-sdk-activedirectory/3rd_party/gokrb5/v8/keytab"
	"github.com/deploymenttheory/go-sdk-activedirectory/3rd_party/gokrb5/v8/messages"
	"github.com/deploymenttheory/go-sdk-activedirectory/3rd_party/gokrb5/v8/types"
	admodel "github.com/deploymenttheory/go-sdk-activedirectory/activedirectory/internal/model"
)

func portableKerberosSource(t *testing.T, kdc *portableKerberosKDC, source admodel.KerberosCredentialSource, includeService bool) *admodel.KerberosCredentials {
	t.Helper()
	k := &admodel.KerberosCredentials{Source: source, Username: portableKerberosUser, Realm: portableKerberosRealm, SPN: "ldap/" + portableTLSHost}
	switch source {
	case admodel.KerberosPassword:
		k.Password = []byte(portableKerberosPassword)
	case admodel.KerberosKeytabFile:
		kt := keytab.New()
		if err := kt.AddEntry(portableKerberosUser, portableKerberosRealm, portableKerberosPassword, time.Now().Add(-time.Hour), 1, 18); err != nil {
			t.Fatal(err)
		}
		data, err := kt.Marshal()
		if err != nil {
			t.Fatal(err)
		}
		t.Cleanup(func() {
			clear(data)
			for i := range kt.Entries {
				clear(kt.Entries[i].Key.KeyValue)
			}
		})
		k.KeytabPath = filepath.Join(t.TempDir(), "owned.keytab")
		if err := os.WriteFile(k.KeytabPath, data, 0o600); err != nil {
			t.Fatal(err)
		}
	case admodel.KerberosCredentialCacheFile:
		data := portableKerberosCacheFile(t, kdc, portableKerberosUser, includeService, time.Now().Add(time.Hour))
		defer clear(data)
		k.CachePath = filepath.Join(t.TempDir(), "owned.ccache")
		if err := os.WriteFile(k.CachePath, data, 0o600); err != nil {
			t.Fatal(err)
		}
	}
	return k
}

// Encode MIT FILE version4 directly from its documented independent format:
// https://web.mit.edu/kerberos/krb5-latest/doc/formats/ccache_file_format.html
// This is test-only credential creation; the SDK runtime never writes caches.
func portableKerberosCacheFile(t *testing.T, kdc *portableKerberosKDC, client string, includeService bool, end time.Time) []byte {
	t.Helper()
	out := &portableKerberosCacheWriter{t: t, data: []byte{5, 4, 0, 0}}
	out.principal(client)
	services := []string{"krbtgt/" + portableKerberosRealm}
	if includeService {
		services = append(services, "ldap/"+portableTLSHost)
	}
	for _, service := range services {
		now := time.Now().UTC().Truncate(time.Second)
		start := now.Add(-time.Minute)
		ticket, key, err := messages.NewTicket(types.NewPrincipalName(1, portableKerberosUser), portableKerberosRealm, types.NewPrincipalName(2, service),
			portableKerberosRealm, types.NewKrbFlags(), kdc.keys, 18, 1, start, start, end, time.Time{})
		if err != nil {
			t.Fatal(err)
		}
		wire, err := ticket.Marshal()
		if err != nil {
			t.Fatal(err)
		}
		out.principal(client)
		out.principal(service)
		out.data = binary.BigEndian.AppendUint16(out.data, 18)
		out.counted(key.KeyValue)
		clear(key.KeyValue)
		out.timestamp(start)
		out.timestamp(start)
		out.timestamp(end)
		out.u32(0) // No renewal permission or SDK renewal side effect.
		out.data = append(out.data, 0)
		out.u32(0) // Ticket flags.
		out.u32(0) // Addresses.
		out.u32(0) // Authorization data.
		out.counted(wire)
		out.counted(nil)
	}
	return out.data
}

type portableKerberosCacheWriter struct {
	t    *testing.T
	data []byte
}

func (w *portableKerberosCacheWriter) u32(value uint32) {
	w.data = binary.BigEndian.AppendUint32(w.data, value)
}

func (w *portableKerberosCacheWriter) counted(value []byte) {
	if uint64(len(value)) > math.MaxUint32 {
		w.t.Fatal("owned cache field exceeds format limit")
	}
	w.u32(uint32(len(value)))
	w.data = append(w.data, value...)
}

func (w *portableKerberosCacheWriter) timestamp(value time.Time) {
	seconds := value.Unix()
	if seconds < 0 || seconds > math.MaxUint32 {
		w.t.Fatal("owned cache timestamp exceeds format limit")
	}
	w.u32(uint32(seconds))
}

func (w *portableKerberosCacheWriter) principal(value string) {
	parts := strings.Split(value, "/")
	w.u32(1)
	if len(parts) > 2 {
		w.t.Fatal("owned cache principal exceeds fixture scope")
	}
	w.u32(uint32(len(parts)))
	w.counted([]byte(portableKerberosRealm))
	for _, part := range parts {
		w.counted([]byte(part))
	}
}
