package engine

import (
	"context"
	"errors"
	"path/filepath"
	"reflect"
	"testing"

	admodel "github.com/deploymenttheory/go-sdk-activedirectory/activedirectory/internal/model"
)

func TestReplicationBackendPreservesExplicitNativeResult(t *testing.T) {
	sentinel := &admodel.NativeStatusError{Operation: "DsReplicaGetInfo2W", Code: 8453}
	want := map[admodel.InternalReplicationInfo]admodel.InternalReplicationNativeReply{
		admodel.InternalReplicationConnectFailures: {},
		admodel.InternalReplicationLinkFailures:    {InternalErr: sentinel},
	}
	request := admodel.InternalReplicationRequest{InternalKinds: []admodel.InternalReplicationInfo{
		admodel.InternalReplicationConnectFailures, admodel.InternalReplicationLinkFailures,
	}}
	root := admodel.RootDSE{}
	instance := []byte{1, 2, 3}
	calls := 0
	got, err := internalReadReplicationBackend(context.Background(), admodel.Config{
		Endpoint: admodel.Endpoint{Host: "dc.example.test"},
	}, root, instance, request, func(
		_ context.Context, config admodel.Config, gotRoot admodel.RootDSE, gotInstance []byte, gotRequest admodel.InternalReplicationRequest,
	) (map[admodel.InternalReplicationInfo]admodel.InternalReplicationNativeReply, error) {
		calls++
		if config.Backend != admodel.BackendNative || config.Authentication != admodel.AuthenticationNegotiate ||
			!reflect.DeepEqual(gotRoot, root) || !reflect.DeepEqual(gotInstance, instance) || !reflect.DeepEqual(gotRequest, request) {
			t.Fatal("native request or identity changed at dispatch")
		}
		return want, sentinel
	})
	if calls != 1 || err != sentinel || !reflect.DeepEqual(got, want) {
		t.Fatalf("native partial result changed: calls=%d err=%v", calls, err)
	}
}

func TestReplicationPortableDispatchRequiresAuthenticatedIdentityBeforeCredentialsOrNative(t *testing.T) {
	for _, source := range []admodel.KerberosCredentialSource{
		admodel.KerberosPassword, admodel.KerberosKeytabFile, admodel.KerberosCredentialCacheFile,
	} {
		t.Run(string(rune('0'+source)), func(t *testing.T) {
			credentials := &admodel.KerberosCredentials{
				Source: source, Username: "reader", Realm: "EXAMPLE.TEST", SPN: "ldap/dc.example.test",
			}
			switch source {
			case admodel.KerberosPassword:
				credentials.Password = []byte("owned-unit-fixture")
			case admodel.KerberosKeytabFile:
				credentials.KeytabPath = filepath.Join(t.TempDir(), "does-not-exist.keytab")
			case admodel.KerberosCredentialCacheFile:
				credentials.CachePath = filepath.Join(t.TempDir(), "does-not-exist.ccache")
			}
			config := admodel.Config{
				Endpoint: admodel.Endpoint{Host: "dc.example.test"}, Backend: admodel.BackendPortable,
				Authentication: admodel.AuthenticationKerberos, Kerberos: credentials,
			}
			calls := 0
			got, err := internalReadReplicationBackend(context.Background(), config, admodel.RootDSE{SupportedCapabilities: []string{admodel.CapabilityActiveDirectory}}, nil,
				admodel.InternalReplicationRequest{InternalKinds: []admodel.InternalReplicationInfo{admodel.InternalReplicationNeighbors}},
				func(context.Context, admodel.Config, admodel.RootDSE, []byte, admodel.InternalReplicationRequest) (
					map[admodel.InternalReplicationInfo]admodel.InternalReplicationNativeReply, error,
				) {
					calls++
					return nil, nil
				})
			if calls != 0 || !errors.Is(err, admodel.ErrInvalidConfig) || errors.Is(err, admodel.ErrKerberosAuthentication) || len(got) != 1 ||
				!errors.Is(got[admodel.InternalReplicationNeighbors].InternalErr, admodel.ErrIncompleteResult) {
				t.Fatalf("portable dispatch crossed the identity/credential boundary: native calls=%d err=%v", calls, err)
			}
		})
	}
}

func TestReplicationBackendRejectsInvalidAuthenticationAndCancellation(t *testing.T) {
	cancelled, cancel := context.WithCancel(context.Background())
	cancel()
	for _, test := range []struct {
		name   string
		ctx    context.Context
		config admodel.Config
		want   error
	}{
		{"portable-negotiate", context.Background(), admodel.Config{
			Endpoint: admodel.Endpoint{Host: "dc.example.test"}, Backend: admodel.BackendPortable,
		}, admodel.ErrInvalidConfig},
		{"cancelled-native", cancelled, admodel.Config{Endpoint: admodel.Endpoint{Host: "dc.example.test"}}, context.Canceled},
		{"unknown-backend", context.Background(), admodel.Config{
			Endpoint: admodel.Endpoint{Host: "dc.example.test"}, Backend: 255,
		}, admodel.ErrInvalidConfig},
	} {
		t.Run(test.name, func(t *testing.T) {
			called := false
			_, err := internalReadReplicationBackend(test.ctx, test.config, admodel.RootDSE{}, nil,
				admodel.InternalReplicationRequest{InternalKinds: []admodel.InternalReplicationInfo{admodel.InternalReplicationPendingOperations}},
				func(context.Context, admodel.Config, admodel.RootDSE, []byte, admodel.InternalReplicationRequest) (
					map[admodel.InternalReplicationInfo]admodel.InternalReplicationNativeReply, error,
				) {
					called = true
					return nil, nil
				})
			if called || !errors.Is(err, test.want) {
				t.Fatalf("invalid request reached native: called=%v err=%v", called, err)
			}
		})
	}
}
