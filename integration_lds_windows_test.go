//go:build windows && (amd64 || arm64)

package activedirectory

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"io"
	"os"
	"strings"
	"testing"
	"time"
	"unsafe"

	"github.com/deploymenttheory/go-bindings-win32/bindings/win32/networking/ldap"
	"github.com/deploymenttheory/go-bindings-win32/bindings/win32/security/authentication/identity"
)

// The runner supplies secrets through redirected stdin and keeps its fixture
// manifest separately. This test writes only observations to the result file.
func TestADLDSLab(t *testing.T) {
	if os.Getenv("ADSDK_LDS_LAB") != "1" {
		t.Skip("requires the isolated LDS fixture and redirected input")
	}
	var input struct {
		Server, Partition, BindDN, Marker                  string
		LDAPPort, SSLPort, ReplicaLDAPPort, ReplicaSSLPort uint16
		Password                                           []byte
	}
	payload, err := io.ReadAll(io.LimitReader(os.Stdin, 16385))
	defer clear(payload)
	if err != nil || len(payload) > 16384 {
		t.Fatal("invalid LDS fixture input")
	}
	decoder := json.NewDecoder(bytes.NewReader(payload))
	decoder.DisallowUnknownFields()
	if err := decoder.Decode(&input); err != nil {
		t.Fatal("invalid LDS fixture encoding")
	}
	defer clear(input.Password)
	if !strings.HasSuffix(strings.ToLower(input.Server), ".ad.sdk.test") || !strings.HasPrefix(input.Marker, "ad-sdk-lds:") || input.Partition == "" || input.BindDN == "" || len(input.Password) == 0 || input.LDAPPort == 0 || input.SSLPort == 0 || input.ReplicaLDAPPort == 0 || input.ReplicaSSLPort == 0 {
		t.Fatal("incomplete fixture or outside isolated LDS namespace")
	}
	ctx, cancel := context.WithTimeout(context.Background(), 3*time.Minute)
	defer cancel()
	rows := []map[string]any{}
	for _, mode := range []struct {
		name              string
		transport         Transport
		port, replicaPort uint16
	}{
		{"ldaps", TransportLDAPS, input.SSLPort, input.ReplicaSSLPort},
		{"starttls", TransportStartTLS, input.LDAPPort, input.ReplicaLDAPPort},
	} {
		config := Config{
			Endpoint: Endpoint{Host: input.Server, Port: mode.port}, Transport: mode.transport,
			Authentication: AuthenticationSimple, Partition: input.Partition,
			Credentials: &Credentials{Username: input.BindDN, Password: input.Password}, Timeout: 5 * time.Second,
		}
		client, err := Dial(ctx, config)
		if err != nil {
			t.Fatalf("%s SIMPLE bind: %v", mode.name, err)
		}
		row := func() (row map[string]any) {
			defer func() {
				if err := client.Close(); err != nil {
					t.Error(err)
				}
			}()
			root, err := client.RootDSE(ctx, RootDSEOptions{})
			if err != nil {
				t.Fatal(err)
			}
			partition, err := client.Partition(ctx)
			if err != nil || partition.DistinguishedName == "" || partition.InstanceType&1 == 0 {
				t.Fatalf("%s partition: %+v, %v", mode.name, partition, err)
			}
			capabilities, err := client.Capabilities(ctx)
			if err != nil || capabilities.Type != DirectoryADLDS {
				t.Fatalf("%s capabilities: %+v, %v", mode.name, capabilities, err)
			}
			var guard *DirectoryCapabilityError
			if err := client.RequireADDS(ctx, "domain operation"); !errors.Is(err, ErrUnsupportedDirectory) || !errors.As(err, &guard) || guard.Actual != DirectoryADLDS {
				t.Fatalf("%s DS prerequisite: %v", mode.name, err)
			}
			session := client.session.(*ldapSession)
			var connection identity.SecPkgContext_ConnectionInfo
			var flags, ssl uint32
			for _, query := range []struct {
				option uint32
				value  unsafe.Pointer
			}{
				{ldap.LDAP_OPT_SSL_INFO, unsafe.Pointer(&connection)},
				{ldap.LDAP_OPT_SCH_FLAGS, unsafe.Pointer(&flags)},
				{ldap.LDAP_OPT_SSL, unsafe.Pointer(&ssl)},
			} {
				if status := session.api.getOption(session.handle, int32(query.option), query.value); status != 0 {
					t.Fatalf("TLS evidence option %d: LDAP %d", query.option, status)
				}
			}
			return map[string]any{
				"transport": mode.name, "port": mode.port, "partition": partition.DistinguishedName,
				"instance_type": partition.InstanceType, "root_attributes": root.Attributes,
				"directory_type": capabilities.Type.String(), "ds_only_rejected": true,
				"protocol": connection.DwProtocol, "cipher_strength": connection.DwCipherStrength,
				"schannel_flags": flags, "ssl_option": ssl,
			}
		}()
		rows = append(rows, row)
		defaultConfig := config
		defaultConfig.Partition = ""
		defaultClient, err := Dial(ctx, defaultConfig)
		if err != nil {
			t.Fatalf("%s default-partition bind: %v", mode.name, err)
		}
		defaultPartition, readErr := defaultClient.Partition(ctx)
		if err := errors.Join(readErr, defaultClient.Close()); err != nil {
			t.Fatalf("%s default partition: %v", mode.name, err)
		}
		if defaultPartition.DistinguishedName != row["partition"] {
			t.Fatal("discovered default differs from the explicit fixture partition")
		}

		for _, selection := range []struct {
			name, partition string
			want            error
			code            uint32
		}{
			{"missing", "CN=ADSDK-MissingPartition," + input.Partition, nil, 32},
			{"subtree", input.BindDN, ErrNotNamingContext, 0},
		} {
			selected := config
			selected.Partition = selection.partition
			client, err := Dial(ctx, selected)
			if err != nil {
				t.Fatalf("%s %s bind: %v", mode.name, selection.name, err)
			}
			_, failure := client.Partition(ctx)
			if err := client.Close(); err != nil {
				t.Fatal(err)
			}
			if selection.want != nil && !errors.Is(failure, selection.want) || selection.code != 0 && !hasLDAPCode(failure, selection.code) {
				t.Fatalf("%s %s partition: %v", mode.name, selection.name, failure)
			}
		}

		wrong := append([]byte(nil), input.Password...)
		wrong = append(wrong, '-', 'w', 'r', 'o', 'n', 'g')
		invalid := config
		invalid.Credentials = &Credentials{Username: input.BindDN, Password: wrong}
		failed, failure := Dial(ctx, invalid)
		clear(wrong)
		if failed != nil {
			_ = failed.Close()
			t.Fatal("wrong password authenticated")
		}
		if !hasLDAPCode(failure, 49) {
			t.Fatalf("%s invalid credentials: %v", mode.name, failure)
		}

		// The second replica shares credentials and data but deliberately has no
		// default naming context configured on its local nTDSDSA object.
		replica := config
		replica.Endpoint.Port = mode.replicaPort
		for _, explicit := range []bool{true, false} {
			if !explicit {
				replica.Partition = ""
			}
			client, err := Dial(ctx, replica)
			if err != nil {
				t.Fatalf("%s no-default replica bind: %v", mode.name, err)
			}
			root, readErr := client.RootDSE(ctx, RootDSEOptions{})
			_, partitionErr := client.Partition(ctx)
			closeErr := client.Close()
			if err := errors.Join(readErr, closeErr); err != nil {
				t.Fatal(err)
			}
			if root.DefaultNamingContext != nil && *root.DefaultNamingContext != "" {
				t.Fatal("replica advertises a default naming context")
			}
			if explicit && partitionErr != nil || !explicit && !errors.Is(partitionErr, ErrNoDefaultPartition) {
				t.Fatalf("%s replica explicit=%v: %v", mode.name, explicit, partitionErr)
			}
		}

		negotiate := config
		negotiate.Authentication, negotiate.Credentials = AuthenticationNegotiate, nil
		current, err := Dial(ctx, negotiate)
		if err != nil {
			t.Fatalf("%s current-identity Negotiate: %v", mode.name, err)
		}
		_, readErr = current.RootDSE(ctx, RootDSEOptions{})
		if err := errors.Join(readErr, current.Close()); err != nil {
			t.Fatal(err)
		}
	}
	if t.Failed() {
		return
	}
	path := os.Getenv("ADSDK_LDS_RESULT")
	if path == "" {
		t.Fatal("missing nonsecret LDS result destination")
	}
	artifact := map[string]any{
		"passed": true, "server": input.Server, "reads": rows,
		"wrong_password_ldap_code": 49, "missing_partition_ldap_code": 32,
		"non_nc_rejected": true, "no_default_rejected": true,
		"default_partition_discovered":     true,
		"explicit_partition_on_no_default": true, "current_identity_tls_negotiate": true,
	}
	encoded, err := json.MarshalIndent(artifact, "", "  ")
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(path, append(encoded, '\n'), 0600); err != nil {
		t.Fatal(err)
	}
}
