package activedirectory_test

import (
	"context"
	"encoding/json"
	"errors"
	"reflect"
	"strings"
	"testing"

	ad "github.com/deploymenttheory/go-sdk-activedirectory/activedirectory"
	"github.com/deploymenttheory/go-sdk-activedirectory/activedirectory/client"
	"github.com/deploymenttheory/go-sdk-activedirectory/activedirectory/services/claims"
	"github.com/deploymenttheory/go-sdk-activedirectory/activedirectory/services/computers"
	"github.com/deploymenttheory/go-sdk-activedirectory/activedirectory/services/discovery"
	"github.com/deploymenttheory/go-sdk-activedirectory/activedirectory/services/groups"
	"github.com/deploymenttheory/go-sdk-activedirectory/activedirectory/services/memberships"
	"github.com/deploymenttheory/go-sdk-activedirectory/activedirectory/services/replication"
	"github.com/deploymenttheory/go-sdk-activedirectory/activedirectory/services/users"
)

func TestOpaqueValuesKeepRepresentationPrivate(t *testing.T) {
	identity, err := ad.IdentityByDN("CN=fixture,DC=example,DC=test")
	if err != nil {
		t.Fatal(err)
	}
	sid, err := ad.ParseSID("S-1-5-18")
	if err != nil {
		t.Fatal(err)
	}
	instant, err := ad.ParseGeneralizedTime("20261117120000Z")
	if err != nil {
		t.Fatal(err)
	}
	values := map[string]any{
		"identity":          identity,
		"raw-value":         ad.NewRawValue([]byte{0, 255}),
		"sid":               sid,
		"generalized-time":  instant,
		"filter":            ad.FilterEqual("cn", ad.FilterText("literal*value")),
		"filter-value":      ad.FilterBytes([]byte{0, 255}),
		"client":            client.Client{},
		"directory-service": ad.DirectoryService{},
	}
	for name, value := range values {
		t.Run(name, func(t *testing.T) {
			typ := reflect.TypeOf(value)
			for i := 0; i < typ.NumField(); i++ {
				if typ.Field(i).IsExported() {
					t.Errorf(
						"representation field %s.%s is publicly mutable",
						typ,
						typ.Field(i).Name,
					)
				}
			}
			// Identity deliberately implements text serialization. Other opaque
			// representations previously serialized as empty JSON objects.
			data, err := json.Marshal(value)
			if err != nil {
				t.Fatal(err)
			}
			want := []byte("{}")
			if name == "identity" {
				text, err := identity.MarshalText()
				if err != nil {
					t.Fatal(err)
				}
				want, err = json.Marshal(string(text))
				if err != nil {
					t.Fatal(err)
				}
			}
			if string(data) != string(want) {
				t.Fatalf("opaque JSON changed: got %s, want %s", data, want)
			}
		})
	}
}

func TestUninitializedResourceModulesAreClosed(t *testing.T) {
	identity, err := ad.IdentityByDN("CN=fixture,DC=example,DC=test")
	if err != nil {
		t.Fatal(err)
	}
	ctx := context.Background()
	userModules := map[string]*users.Service{"nil": nil, "zero": {}, "new-nil": users.New(nil)}
	for name, service := range userModules {
		t.Run("users/"+name, func(t *testing.T) {
			_, err := service.User(ctx, identity, ad.ResolveIdentityOptions{})
			if !errors.Is(err, ad.ErrClosed) {
				t.Fatalf("read: %v", err)
			}
			_, err = service.CreateUser(ctx, users.CreateUserRequest{Name: "fixture"})
			if !errors.Is(err, ad.ErrClosed) {
				t.Fatalf("create: %v", err)
			}
		})
	}
	groupModules := map[string]*groups.Service{"nil": nil, "zero": {}, "new-nil": groups.New(nil)}
	for name, service := range groupModules {
		t.Run("groups/"+name, func(t *testing.T) {
			_, err := service.Group(ctx, identity, ad.ResolveIdentityOptions{})
			if !errors.Is(err, ad.ErrClosed) {
				t.Fatalf("read: %v", err)
			}
		})
	}
	computerModules := map[string]*computers.Service{
		"nil":     nil,
		"zero":    {},
		"new-nil": computers.New(nil),
	}
	for name, service := range computerModules {
		t.Run("computers/"+name, func(t *testing.T) {
			_, err := service.Computer(ctx, identity, ad.ResolveIdentityOptions{})
			if !errors.Is(err, ad.ErrClosed) {
				t.Fatalf("read: %v", err)
			}
		})
	}
}

func TestPublicMethodSetsExcludeImplementationHelpers(t *testing.T) {
	publicTypes := []reflect.Type{
		reflect.TypeOf(client.Client{}),
		reflect.TypeOf(ad.DirectoryService{}),
		reflect.TypeOf(ad.Config{}),
		reflect.TypeOf(ad.Credentials{}),
		reflect.TypeOf(discovery.DomainName{}),
		reflect.TypeOf(discovery.DiscoveryOptions{}),
		reflect.TypeOf(ad.Filter{}),
		reflect.TypeOf(ad.FilterValue{}),
		reflect.TypeOf(replication.ReplicationSelection{}),
		reflect.TypeOf(memberships.RODCPasswordReplicationList(0)),
		reflect.TypeOf(ad.RootDSEOptions{}),
		reflect.TypeOf(ad.SearchOptions{}),
		reflect.TypeOf(claims.ClaimTransformDirection(0)),
		reflect.TypeOf(claims.ClaimTransformRuleSet{}),
	}
	// Every composed resource module is part of the public SDK interface.
	composition := reflect.TypeOf(ad.Client{})
	for i := 0; i < composition.NumField(); i++ {
		field := composition.Field(i)
		if field.IsExported() && field.Type.Kind() == reflect.Pointer {
			publicTypes = append(publicTypes, field.Type.Elem())
		}
	}
	for _, publicType := range publicTypes {
		for _, methodSet := range []reflect.Type{publicType, reflect.PointerTo(publicType)} {
			for i := 0; i < methodSet.NumMethod(); i++ {
				method := methodSet.Method(i)
				if strings.HasPrefix(method.Name, "Internal") {
					t.Errorf("%s exposes implementation helper %s", methodSet, method.Name)
				}
			}
		}
	}
}
