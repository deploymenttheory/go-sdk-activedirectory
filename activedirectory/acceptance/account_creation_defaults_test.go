package acceptance

import (
	"context"
	"errors"
	"slices"
	"strings"
	"testing"

	adengine "github.com/deploymenttheory/go-sdk-activedirectory/activedirectory/internal/engine"
	admodel "github.com/deploymenttheory/go-sdk-activedirectory/activedirectory/internal/model"
	adservice_computers "github.com/deploymenttheory/go-sdk-activedirectory/activedirectory/services/computers"
	adservice_groups "github.com/deploymenttheory/go-sdk-activedirectory/activedirectory/services/groups"
	adservice_users "github.com/deploymenttheory/go-sdk-activedirectory/activedirectory/services/users"
)

func InternalDefaultCreationFixture(
	t *testing.T,
	kind, partition, container string,
	mapping admodel.Object,
	lookupErr error,
) (*adengine.Client, *int, *[]admodel.SearchOptions) {
	t.Helper()
	writes := 0
	var queries []admodel.SearchOptions
	var created admodel.Object
	client := InternalObjectTestClient(
		t,
		nil,
		func(_ context.Context, query admodel.SearchOptions) (admodel.InternalSearchCursor, error) {
			queries = append(queries, query)
			if strings.Contains(query.Filter, "classSchema") {
				return InternalObjectTestCursor(
					admodel.Object{
						Attributes: map[string][][]byte{
							"rdnattid":            {[]byte("cn")},
							"objectclasscategory": {[]byte("1")},
						},
					},
				), nil
			}
			if query.Base == partition && writes == 0 {
				if !slices.Contains(query.Properties, "wellKnownObjects") ||
					query.Scope != admodel.ScopeBase {
					t.Fatal("default mapping must be a scoped base read", query)
				}
				return InternalTestSearchCursor{
					InternalRead: func(context.Context, uint32) ([]admodel.Object, bool, error) {
						return []admodel.Object{mapping}, lookupErr == nil, lookupErr
					},
					InternalFinish: func() error { return nil },
				}, nil
			}
			if query.Base == container && writes == 0 {
				return InternalObjectTestCursor(InternalObjectTestEntry(container)), nil
			}
			if writes == 1 && query.Base == created.DistinguishedName {
				return InternalObjectTestCursor(created), nil
			}
			t.Fatal("unexpected search", query)
			return nil, admodel.ErrInvalidResult
		},
		func(_ context.Context, request admodel.InternalLdapWriteRequest) admodel.InternalLdapWriteAttempt {
			writes++
			if request.InternalOperation != admodel.InternalLdapWriteAdd ||
				request.InternalDn != "cn=sample,"+container {
				t.Fatal("created in the wrong container", request)
			}
			created = InternalObjectTestEntry(request.InternalDn)
			for _, mod := range request.InternalModifications {
				created.Attributes[strings.ToLower(mod.InternalAttribute)] = mod.InternalValues
			}
			class := string(created.Attributes["objectclass"][0])
			if class == "computer" {
				created.Attributes["objectclass"] = [][]byte{
					[]byte("top"),
					[]byte("user"),
					[]byte("computer"),
				}
			}
			created.Attributes["name"] = [][]byte{[]byte("sample")}
			return admodel.InternalLdapWriteAttempt{State: admodel.InternalLdapWriteAccepted}
		},
	)
	session := adengine.InternalClientSession(client).(InternalObjectWriteTestSession)
	session.InternalRead = func(context.Context, []string) (map[string][][]byte, error) {
		root := InternalIdentityTestRoot(kind)
		root["namingcontexts"] = [][]byte{
			[]byte("DC=example"),
			[]byte("DC=other"),
			[]byte("CN=Schema,CN=Configuration,DC=example"),
		}
		root["schemanamingcontext"] = [][]byte{[]byte("CN=Schema,CN=Configuration,DC=example")}
		return root, nil
	}
	(*adengine.InternalClientSessionPointer(client)) = session
	return client, &writes, &queries
}

func InternalCreateDefaultTestAccount(
	ctx context.Context,
	client *adengine.Client,
	class string,
	parent admodel.Identity,
	options admodel.ObjectMutationOptions,
) (admodel.ObjectMutationResult, error) {
	switch class {
	case "user":
		result, err := adservice_users.New(client).
			CreateUser(ctx, admodel.CreateUserRequest{Name: "sample", Parent: parent, Options: options})
		return result.Creation, err
	case "computer":
		result, err := adservice_computers.New(client).
			CreateComputer(ctx, admodel.CreateComputerRequest{Name: "sample", Parent: parent, Options: options})
		return result.Creation, err
	default:
		result, err := adservice_groups.New(client).
			CreateGroup(ctx, admodel.CreateGroupRequest{Name: "sample", Parent: parent, Category: admodel.GroupSecurity, Scope: admodel.GroupGlobal, Options: options})
		return result.Mutation, err
	}
}

func TestAccountCreationDefaultsFollowRedirectedContainersAndPartitions(t *testing.T) {
	for _, class := range []string{"user", "computer", "group"} {
		for _, selection := range []string{"server-default", "config", "request-over-config", "explicit-parent"} {
			t.Run(class+"/"+selection, func(t *testing.T) {
				partition := "DC=example"
				if selection == "config" || selection == "request-over-config" {
					partition = "DC=other"
				}
				container := `OU=People: Jörg\, 李,` + partition
				key := admodel.InternalWellKnownUsers
				if class == "computer" {
					key = admodel.InternalWellKnownComputers
				}
				mapping := InternalObjectTestEntry(partition)
				mapping.Attributes["wellknownobjects"] = [][]byte{
					[]byte("B:32:" + strings.ToLower(key) + ":" + container),
				}
				client, writes, queries := InternalDefaultCreationFixture(
					t,
					admodel.CapabilityActiveDirectory,
					partition,
					container,
					mapping,
					nil,
				)
				options := admodel.ObjectMutationOptions{}
				if selection == "config" {
					(*adengine.InternalClientConfigPointer(client)).Partition = partition
				} else if selection == "request-over-config" {
					(*adengine.InternalClientConfigPointer(client)).Partition = "DC=example"
					options.Partition = partition
				}
				var parent admodel.Identity
				if selection == "explicit-parent" {
					parent, _ = admodel.IdentityByDN(container)
				}
				result, err := InternalCreateDefaultTestAccount(
					context.Background(),
					client,
					class,
					parent,
					options,
				)
				if err != nil || *writes != 1 || !result.Verified ||
					result.TargetDN != "cn=sample,"+container {
					t.Fatal(result, err, *writes)
				}
				if selection == "explicit-parent" {
					for _, query := range *queries {
						if slices.Contains(query.Properties, "wellKnownObjects") {
							t.Fatal("explicit parent triggered default discovery")
						}
					}
				}
			})
		}
	}
}

func TestAccountCreationDefaultFailuresNeverGuessOrWrite(t *testing.T) {
	for _, class := range []string{"user", "computer", "group"} {
		for _, mode := range []string{"missing", "partial-values", "duplicate", "malformed", "cross-partition", "permission", "missing-target"} {
			t.Run(class+"/"+mode, func(t *testing.T) {
				key := admodel.InternalWellKnownUsers
				if class == "computer" {
					key = admodel.InternalWellKnownComputers
				}
				container := "OU=Redirected,DC=example"
				mapping := InternalObjectTestEntry("DC=example")
				value := []byte("B:32:" + key + ":" + container)
				mapping.Attributes["wellknownobjects"] = [][]byte{value}
				var lookupErr error
				switch mode {
				case "missing":
					delete(mapping.Attributes, "wellknownobjects")
				case "partial-values":
					delete(mapping.Attributes, "wellknownobjects")
					mapping.Attributes["wellknownobjects;range=0-0"] = [][]byte{value}
				case "duplicate":
					mapping.Attributes["wellknownobjects"] = append(
						mapping.Attributes["wellknownobjects"],
						value,
					)
				case "malformed":
					mapping.Attributes["wellknownobjects"] = [][]byte{
						[]byte("B:31:" + key + ":" + container),
					}
				case "cross-partition":
					mapping.Attributes["wellknownobjects"] = [][]byte{
						[]byte("B:32:" + key + ":OU=Elsewhere,DC=other"),
					}
				case "permission":
					lookupErr = &admodel.LDAPError{Code: 50}
				case "missing-target":
					mapping.Attributes["wellknownobjects"] = [][]byte{
						[]byte("B:32:" + admodel.InternalWellKnownSystem + ":CN=System,DC=example"),
					}
				}
				client, writes, _ := InternalDefaultCreationFixture(
					t,
					admodel.CapabilityActiveDirectory,
					"DC=example",
					container,
					mapping,
					lookupErr,
				)
				result, err := InternalCreateDefaultTestAccount(
					context.Background(),
					client,
					class,
					admodel.Identity{},
					admodel.ObjectMutationOptions{},
				)
				var parentErr *admodel.AccountCreationParentError
				if !errors.As(err, &parentErr) || len(parentErr.Observation.Candidates) != 1 ||
					*writes != 0 ||
					result.State != admodel.ObjectWriteNotAttempted {
					t.Fatal(result, err, *writes)
				}
				if lookupErr != nil && !errors.Is(err, lookupErr) {
					t.Fatal("lost native lookup failure", err)
				}
			})
		}
	}
}

func TestAccountCreationDefaultLDSRolesAndMissingPartition(t *testing.T) {
	for _, class := range []string{"user", "group"} {
		mapping := InternalObjectTestEntry("DC=example")
		mapping.Attributes["wellknownobjects"] = [][]byte{
			[]byte("B:32:" + admodel.InternalWellKnownUsers + ":CN=Roles,DC=example"),
		}
		client, writes, _ := InternalDefaultCreationFixture(
			t,
			admodel.CapabilityADLDS,
			"DC=example",
			"CN=Roles,DC=example",
			mapping,
			nil,
		)
		result, err := InternalCreateDefaultTestAccount(
			context.Background(),
			client,
			class,
			admodel.Identity{},
			admodel.ObjectMutationOptions{},
		)
		if err != nil || *writes != 1 || !result.Verified {
			t.Fatal(class, result, err)
		}
	}
	client, writes, queries := InternalDefaultCreationFixture(
		t,
		admodel.CapabilityActiveDirectory,
		"DC=example",
		"CN=Users,DC=example",
		admodel.Object{},
		nil,
	)
	session := adengine.InternalClientSession(client).(InternalObjectWriteTestSession)
	original := session.InternalRead
	session.InternalRead = func(ctx context.Context, properties []string) (map[string][][]byte, error) {
		root, err := original(ctx, properties)
		delete(root, "defaultnamingcontext")
		return root, err
	}
	(*adengine.InternalClientSessionPointer(client)) = session
	_, err := InternalCreateDefaultTestAccount(
		context.Background(),
		client,
		"user",
		admodel.Identity{},
		admodel.ObjectMutationOptions{},
	)
	if !errors.Is(err, admodel.ErrNoDefaultPartition) || *writes != 0 || len(*queries) != 0 {
		t.Fatal(err, *writes, len(*queries))
	}
}
