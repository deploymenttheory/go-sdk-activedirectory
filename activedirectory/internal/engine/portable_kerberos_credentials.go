package engine

import (
	"context"
	"errors"
	"fmt"
	"io"
	"net"
	"os"
	"strings"
	"time"

	krbclient "github.com/deploymenttheory/go-sdk-activedirectory/3rd_party/gokrb5/v8/client"
	krbconfig "github.com/deploymenttheory/go-sdk-activedirectory/3rd_party/gokrb5/v8/config"
	"github.com/deploymenttheory/go-sdk-activedirectory/3rd_party/gokrb5/v8/credentials"
	"github.com/deploymenttheory/go-sdk-activedirectory/3rd_party/gokrb5/v8/iana/flags"
	"github.com/deploymenttheory/go-sdk-activedirectory/3rd_party/gokrb5/v8/keytab"
	"github.com/deploymenttheory/go-sdk-activedirectory/3rd_party/gokrb5/v8/messages"
	"github.com/deploymenttheory/go-sdk-activedirectory/3rd_party/gokrb5/v8/types"
	admodel "github.com/deploymenttheory/go-sdk-activedirectory/activedirectory/internal/model"
)

const internalKerberosFileLimit = 16 * 1024 * 1024

// No ambient krb5.conf, default credential file, environment or reverse-DNS
// setting enters this configuration. The selected LDAP DC is also the KDC;
// both identities remain bound to the caller's explicit realm/DC FQDN.
func internalPortableKerberosConfig(c admodel.Config) *krbconfig.Config {
	const aes256sha1 = "aes256-cts-hmac-sha1-96"
	const aes128sha1 = "aes128-cts-hmac-sha1-96"
	const aes256sha384 = "aes256-cts-hmac-sha384-192"
	const aes128sha256 = "aes128-cts-hmac-sha256-128"
	return &krbconfig.Config{
		LibDefaults: krbconfig.LibDefaults{
			DefaultRealm: c.Kerberos.Realm, Clockskew: 5 * time.Minute, NoAddresses: true,
			TicketLifetime: 10 * time.Hour, UDPPreferenceLimit: 1,
			DefaultTktEnctypes:   []string{aes256sha384, aes128sha256, aes256sha1, aes128sha1},
			DefaultTGSEnctypes:   []string{aes256sha384, aes128sha256, aes256sha1, aes128sha1},
			PermittedEnctypes:    []string{aes256sha384, aes128sha256, aes256sha1, aes128sha1},
			DefaultTktEnctypeIDs: []int32{20, 19, 18, 17}, DefaultTGSEnctypeIDs: []int32{20, 19, 18, 17}, PermittedEnctypeIDs: []int32{20, 19, 18, 17},
			PreferredPreauthTypes: []int{18, 17, 20, 19}, KDCDefaultOptions: types.NewKrbFlags(),
		},
		Realms:      []krbconfig.Realm{{Realm: c.Kerberos.Realm, KDC: []string{net.JoinHostPort(strings.TrimSuffix(c.Endpoint.Host, "."), "88")}}},
		DomainRealm: krbconfig.DomainRealm{},
	}
}

func internalReadKerberosFile(ctx context.Context, path string) ([]byte, error) {
	if cause := InternalConnectionContextCause(ctx); cause != nil {
		return nil, cause
	}
	info, err := os.Stat(path)
	if err != nil {
		return nil, fmt.Errorf("kerberos credential file metadata: %w", err)
	}
	if !info.Mode().IsRegular() || info.Size() <= 0 || info.Size() > internalKerberosFileLimit {
		return nil, admodel.ErrInvalidConfig
	}
	file, err := os.Open(path)
	if err != nil {
		return nil, fmt.Errorf("kerberos credential file open: %w", err)
	}
	defer file.Close()
	opened, err := file.Stat()
	if err != nil {
		return nil, fmt.Errorf("kerberos opened credential file metadata: %w", err)
	}
	if !opened.Mode().IsRegular() || opened.Size() > internalKerberosFileLimit {
		return nil, admodel.ErrInvalidConfig
	}
	data, err := io.ReadAll(io.LimitReader(file, internalKerberosFileLimit+1))
	if err != nil || len(data) > internalKerberosFileLimit {
		clear(data)
		return nil, errors.Join(err, admodel.ErrInvalidConfig)
	}
	if cause := InternalConnectionContextCause(ctx); cause != nil {
		clear(data)
		return nil, cause
	}
	return data, nil
}

// internalPortableKerberosClient parses only the selected credential source.
// It performs no network I/O and returns cleanup for its owned key material.
func internalPortableKerberosClient(ctx context.Context, c admodel.Config, cfg *krbconfig.Config, dialer InternalPortableDialer) (*krbclient.Client, func(), error) {
	settings := []func(*krbclient.Settings){krbclient.WithContext(ctx), krbclient.WithDialer(dialer), krbclient.StrictRealm(c.Kerberos.Realm), krbclient.DisablePAFXFAST(true)}
	k := c.Kerberos
	switch k.Source {
	case admodel.KerberosPassword:
		cl := krbclient.NewWithPassword(k.Username, k.Realm, string(k.Password), cfg, settings...)
		return cl, cl.Destroy, nil
	case admodel.KerberosKeytabFile:
		data, err := internalReadKerberosFile(ctx, k.KeytabPath)
		if err != nil {
			return nil, nil, err
		}
		defer clear(data)
		kt := keytab.New()
		if err := kt.Unmarshal(data); err != nil {
			return nil, nil, err
		}
		clearKeys := func() {
			for i := range kt.Entries {
				clear(kt.Entries[i].Key.KeyValue)
			}
		}
		selected := kt.Entries[:0]
		for _, entry := range kt.Entries {
			if entry.Principal.Realm == k.Realm && strings.Join(entry.Principal.Components, "/") == k.Username && internalPortableKerberosKey(entry.Key) {
				selected = append(selected, entry)
			} else {
				clear(entry.Key.KeyValue)
			}
		}
		kt.Entries = selected
		if len(selected) == 0 {
			clearKeys()
			return nil, nil, admodel.ErrInvalidConfig
		}
		cl := krbclient.NewWithKeytab(k.Username, k.Realm, kt, cfg, settings...)
		return cl, func() { cl.Destroy(); clearKeys() }, nil
	case admodel.KerberosCredentialCacheFile:
		data, err := internalReadKerberosFile(ctx, k.CachePath)
		if err != nil {
			return nil, nil, err
		}
		defer clear(data)
		cache := new(credentials.CCache)
		if err := cache.Unmarshal(data); err != nil {
			return nil, nil, err
		}
		clearKeys := func() {
			for _, entry := range cache.Credentials {
				clear(entry.Key.KeyValue)
				clear(entry.Ticket)
				clear(entry.SecondTicket)
			}
		}
		if err := internalPortableKerberosCache(cache, k); err != nil {
			clearKeys()
			return nil, nil, err
		}
		cl, err := krbclient.NewFromCCache(cache, cfg, settings...)
		if err != nil {
			clearKeys()
			return nil, nil, err
		}
		return cl, func() { cl.Destroy(); clearKeys() }, nil
	default:
		return nil, nil, admodel.ErrInvalidConfig
	}
}

func internalPortableKerberosKey(key types.EncryptionKey) bool {
	switch key.KeyType {
	case 17, 19:
		return len(key.KeyValue) == 16
	case 18, 20:
		return len(key.KeyValue) == 32
	default:
		return false
	}
}

func internalPortableKerberosCache(cache *credentials.CCache, k *admodel.KerberosCredentials) error {
	if cache.GetClientRealm() != k.Realm || cache.GetClientPrincipalName().PrincipalNameString() != k.Username {
		return admodel.ErrInvalidConfig
	}
	tgt := "krbtgt/" + k.Realm
	seen := map[string]bool{}
	selected := cache.Credentials[:0]
	for _, entry := range cache.GetEntries() {
		service := entry.Server.PrincipalName.PrincipalNameString()
		if service != tgt && service != k.SPN {
			clear(entry.Key.KeyValue)
			clear(entry.Ticket)
			clear(entry.SecondTicket)
			continue
		}
		if seen[service] || entry.Client.Realm != k.Realm || entry.Client.PrincipalName.PrincipalNameString() != k.Username || entry.Server.Realm != k.Realm ||
			!internalPortableKerberosKey(entry.Key) || entry.IsSKey || len(entry.SecondTicket) != 0 || types.IsFlagSet(&entry.TicketFlags, flags.Invalid) {
			return admodel.ErrInvalidConfig
		}
		start := entry.StartTime
		if start.IsZero() {
			start = entry.AuthTime
		}
		now := time.Now().UTC()
		if start.IsZero() || start.After(now) || !entry.EndTime.After(now) || !entry.EndTime.After(start) {
			return admodel.ErrKerberosExpired
		}
		var ticket messages.Ticket
		if err := ticket.Unmarshal(entry.Ticket); err != nil {
			return err
		}
		if ticket.TktVNO != 5 || ticket.Realm != k.Realm || !ticket.SName.Equal(entry.Server.PrincipalName) {
			return admodel.ErrInvalidConfig
		}
		seen[service] = true
		selected = append(selected, entry)
	}
	if !seen[tgt] {
		return admodel.ErrInvalidConfig
	}
	cache.Credentials = selected
	return nil
}
