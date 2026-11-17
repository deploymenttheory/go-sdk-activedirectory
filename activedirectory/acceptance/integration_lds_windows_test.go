//go:build windows && (amd64 || arm64)

package acceptance

import (
	"bytes"
	"context"
	"encoding/base64"
	"encoding/json"
	"errors"
	"io"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
	"time"
	"unsafe"

	"github.com/deploymenttheory/go-bindings-win32/bindings/win32/networking/ldap"
	"github.com/deploymenttheory/go-bindings-win32/bindings/win32/security/authentication/identity"
	adengine "github.com/deploymenttheory/go-sdk-activedirectory/activedirectory/internal/engine"
	admodel "github.com/deploymenttheory/go-sdk-activedirectory/activedirectory/internal/model"
)

func TestADLDSFixtureRejectsMalformedInputWithoutDisclosure(t *testing.T) {
	const secret = "synthetic-lds-fixture-input-secret"
	encoded := base64.StdEncoding.EncodeToString([]byte(secret))
	for _, payload := range []string{
		`{"Password":"` + encoded + `","` + secret + `":true}`,
		`{"Password":"` + encoded + `"} {"extra":"` + secret + `"}`,
		`{"Server":"outside.invalid","Password":"` + encoded + `"}`,
	} {
		ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
		resultPath := filepath.Join(t.TempDir(), "result.json")
		command := exec.CommandContext(ctx, os.Args[0], "-test.run=^TestADLDSLab$")
		command.Env = append(os.Environ(), "ADSDK_LDS_LAB=1", "ADSDK_LDS_RESULT="+resultPath)
		command.Stdin = strings.NewReader(payload)
		output, err := command.CombinedOutput()
		cancel()
		var exit *exec.ExitError
		if !errors.As(err, &exit) || exit.ExitCode() != 1 ||
			!bytes.Contains(output, []byte("FAIL")) {
			t.Fatal("malformed fixture was not rejected by the isolated test process")
		}
		if bytes.Contains(output, []byte(secret)) || bytes.Contains(output, []byte(encoded)) {
			t.Fatal("fixture rejection disclosed synthetic credential material")
		}
		if _, err := os.Stat(resultPath); !errors.Is(err, os.ErrNotExist) {
			t.Fatal("rejected fixture created a success artifact")
		}
	}
}

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
	// Decode can allocate Password before rejecting a later malformed field.
	defer func() { clear(input.Password) }()
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
	if err := decoder.Decode(new(any)); !errors.Is(err, io.EOF) {
		t.Fatal("LDS fixture must contain exactly one JSON object")
	}
	if !strings.HasSuffix(strings.ToLower(input.Server), ".ad.sdk.test") ||
		!strings.HasPrefix(input.Marker, "ad-sdk-lds:") ||
		input.Partition == "" ||
		input.BindDN == "" ||
		len(input.Password) == 0 ||
		input.LDAPPort == 0 ||
		input.SSLPort == 0 ||
		input.ReplicaLDAPPort == 0 ||
		input.ReplicaSSLPort == 0 {
		t.Fatal("incomplete fixture or outside isolated LDS namespace")
	}
	ctx, cancel := context.WithTimeout(context.Background(), 3*time.Minute)
	defer cancel()
	rows := []map[string]any{}
	for _, mode := range []struct {
		InternalName                      string
		InternalTransport                 admodel.Transport
		InternalPort, InternalReplicaPort uint16
	}{
		{"ldaps", admodel.TransportLDAPS, input.SSLPort, input.ReplicaSSLPort},
		{"starttls", admodel.TransportStartTLS, input.LDAPPort, input.ReplicaLDAPPort},
	} {
		config := admodel.Config{
			Endpoint: admodel.Endpoint{
				Host: input.Server,
				Port: mode.InternalPort,
			},
			Transport:      mode.InternalTransport,
			Authentication: admodel.AuthenticationSimple,
			Partition:      input.Partition,
			Credentials: &admodel.Credentials{
				Username: input.BindDN,
				Password: input.Password,
			},
			Timeout: 5 * time.Second,
		}
		client, err := adengine.Dial(ctx, config)
		if err != nil {
			t.Fatalf("%s SIMPLE bind: %v", mode.InternalName, err)
		}
		row := func() (row map[string]any) {
			defer func() {
				if err := client.Close(); err != nil {
					t.Error(err)
				}
			}()
			root, err := client.RootDSE(ctx, admodel.RootDSEOptions{})
			if err != nil {
				t.Fatal(err)
			}
			partition, err := client.Partition(ctx)
			if err != nil || partition.DistinguishedName == "" || partition.InstanceType&1 == 0 {
				t.Fatalf("%s partition: %+v, %v", mode.InternalName, partition, err)
			}
			capabilities, err := client.Capabilities(ctx)
			if err != nil || capabilities.Type != admodel.DirectoryADLDS {
				t.Fatalf("%s capabilities: %+v, %v", mode.InternalName, capabilities, err)
			}
			var guard *admodel.DirectoryCapabilityError
			if err := client.RequireADDS(
				ctx,
				"domain operation",
			); !errors.Is(err, admodel.ErrUnsupportedDirectory) || !errors.As(err, &guard) ||
				guard.Actual != admodel.DirectoryADLDS {
				t.Fatalf("%s DS prerequisite: %v", mode.InternalName, err)
			}
			session := adengine.InternalClientSession(client).(*adengine.InternalLdapSession)
			var connection identity.SecPkgContext_ConnectionInfo
			var flags, ssl uint32
			for _, query := range []struct {
				InternalOption uint32
				InternalValue  unsafe.Pointer
			}{
				{ldap.LDAP_OPT_SSL_INFO, unsafe.Pointer(&connection)},
				{ldap.LDAP_OPT_SCH_FLAGS, unsafe.Pointer(&flags)},
				{ldap.LDAP_OPT_SSL, unsafe.Pointer(&ssl)},
			} {
				if status := session.InternalApi.InternalGetOption(
					session.InternalHandle,
					int32(query.InternalOption),
					query.InternalValue,
				); status != 0 {
					t.Fatalf("TLS evidence option %d: LDAP %d", query.InternalOption, status)
				}
			}
			return map[string]any{
				"transport":        mode.InternalName,
				"port":             mode.InternalPort,
				"partition":        partition.DistinguishedName,
				"instance_type":    partition.InstanceType,
				"root_attributes":  root.Attributes,
				"directory_type":   capabilities.Type.String(),
				"ds_only_rejected": true,
				"protocol":         connection.DwProtocol,
				"cipher_strength":  connection.DwCipherStrength,
				"schannel_flags":   flags,
				"ssl_option":       ssl,
			}
		}()
		rows = append(rows, row)
		defaultConfig := config
		defaultConfig.Partition = ""
		defaultClient, err := adengine.Dial(ctx, defaultConfig)
		if err != nil {
			t.Fatalf("%s default-partition bind: %v", mode.InternalName, err)
		}
		defaultPartition, readErr := defaultClient.Partition(ctx)
		if err := errors.Join(readErr, defaultClient.Close()); err != nil {
			t.Fatalf("%s default partition: %v", mode.InternalName, err)
		}
		if defaultPartition.DistinguishedName != row["partition"] {
			t.Fatal("discovered default differs from the explicit fixture partition")
		}

		for _, selection := range []struct {
			InternalName, InternalPartition string
			InternalWant                    error
			InternalCode                    uint32
		}{
			{"missing", "CN=ADSDK-MissingPartition," + input.Partition, nil, 32},
			{"subtree", input.BindDN, admodel.ErrNotNamingContext, 0},
		} {
			selected := config
			selected.Partition = selection.InternalPartition
			client, err := adengine.Dial(ctx, selected)
			if err != nil {
				t.Fatalf("%s %s bind: %v", mode.InternalName, selection.InternalName, err)
			}
			_, failure := client.Partition(ctx)
			if err := client.Close(); err != nil {
				t.Fatal(err)
			}
			if selection.InternalWant != nil && !errors.Is(failure, selection.InternalWant) ||
				selection.InternalCode != 0 &&
					!InternalHasLDAPCode(failure, selection.InternalCode) {
				t.Fatalf("%s %s partition: %v", mode.InternalName, selection.InternalName, failure)
			}
		}

		wrong := make([]byte, len(input.Password)+len("-wrong"))
		copy(wrong, input.Password)
		copy(wrong[len(input.Password):], "-wrong")
		invalid := config
		invalid.Credentials = &admodel.Credentials{Username: input.BindDN, Password: wrong}
		failed, failure := adengine.Dial(ctx, invalid)
		clear(wrong)
		if failed != nil {
			_ = failed.Close()
			t.Fatal("wrong password authenticated")
		}
		if !InternalHasLDAPCode(failure, 49) {
			t.Fatalf("%s invalid credentials: %v", mode.InternalName, failure)
		}

		// The second replica shares credentials and data but deliberately has no
		// default naming context configured on its local nTDSDSA object.
		replica := config
		replica.Endpoint.Port = mode.InternalReplicaPort
		for _, explicit := range []bool{true, false} {
			if !explicit {
				replica.Partition = ""
			}
			client, err := adengine.Dial(ctx, replica)
			if err != nil {
				t.Fatalf("%s no-default replica bind: %v", mode.InternalName, err)
			}
			root, readErr := client.RootDSE(ctx, admodel.RootDSEOptions{})
			_, partitionErr := client.Partition(ctx)
			closeErr := client.Close()
			if err := errors.Join(readErr, closeErr); err != nil {
				t.Fatal(err)
			}
			if root.DefaultNamingContext != nil && *root.DefaultNamingContext != "" {
				t.Fatal("replica advertises a default naming context")
			}
			if explicit && partitionErr != nil ||
				!explicit && !errors.Is(partitionErr, admodel.ErrNoDefaultPartition) {
				t.Fatalf("%s replica explicit=%v: %v", mode.InternalName, explicit, partitionErr)
			}
		}

		negotiate := config
		negotiate.Authentication, negotiate.Credentials = admodel.AuthenticationNegotiate, nil
		current, err := adengine.Dial(ctx, negotiate)
		if err != nil {
			t.Fatalf("%s current-identity Negotiate: %v", mode.InternalName, err)
		}
		_, readErr = current.RootDSE(ctx, admodel.RootDSEOptions{})
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
	if err := os.WriteFile(path, append(encoded, '\n'), 0o600); err != nil {
		t.Fatal(err)
	}
}
