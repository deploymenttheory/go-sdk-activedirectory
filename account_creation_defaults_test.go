package activedirectory

import (
	"context"
	"errors"
	"slices"
	"strings"
	"testing"
)

func defaultCreationFixture(t *testing.T, kind, partition, container string, mapping Object, lookupErr error) (*Client, *int, *[]SearchOptions) {
	t.Helper()
	writes := 0
	var queries []SearchOptions
	var created Object
	client := objectTestClient(t, nil, func(_ context.Context, query SearchOptions) (searchCursor, error) {
		queries = append(queries, query)
		if strings.Contains(query.Filter, "classSchema") {
			return objectTestCursor(Object{Attributes: map[string][][]byte{"rdnattid": {[]byte("cn")}, "objectclasscategory": {[]byte("1")}}}), nil
		}
		if query.Base == partition && writes == 0 {
			if !slices.Contains(query.Properties, "wellKnownObjects") || query.Scope != ScopeBase {
				t.Fatal("default mapping must be a scoped base read", query)
			}
			return testSearchCursor{read: func(context.Context, uint32) ([]Object, bool, error) {
				return []Object{mapping}, lookupErr == nil, lookupErr
			}, finish: func() error { return nil }}, nil
		}
		if query.Base == container && writes == 0 {
			return objectTestCursor(objectTestEntry(container)), nil
		}
		if writes == 1 && query.Base == created.DistinguishedName {
			return objectTestCursor(created), nil
		}
		t.Fatal("unexpected search", query)
		return nil, ErrInvalidResult
	}, func(_ context.Context, request ldapWriteRequest) ldapWriteAttempt {
		writes++
		if request.operation != ldapWriteAdd || request.dn != "cn=sample,"+container {
			t.Fatal("created in the wrong container", request)
		}
		created = objectTestEntry(request.dn)
		for _, mod := range request.modifications {
			created.Attributes[strings.ToLower(mod.attribute)] = mod.values
		}
		class := string(created.Attributes["objectclass"][0])
		if class == "computer" {
			created.Attributes["objectclass"] = [][]byte{[]byte("top"), []byte("user"), []byte("computer")}
		}
		created.Attributes["name"] = [][]byte{[]byte("sample")}
		return ldapWriteAttempt{State: ldapWriteAccepted}
	})
	session := client.session.(objectWriteTestSession)
	session.read = func(context.Context, []string) (map[string][][]byte, error) {
		root := identityTestRoot(kind)
		root["namingcontexts"] = [][]byte{[]byte("DC=example"), []byte("DC=other"), []byte("CN=Schema,CN=Configuration,DC=example")}
		root["schemanamingcontext"] = [][]byte{[]byte("CN=Schema,CN=Configuration,DC=example")}
		return root, nil
	}
	client.session = session
	return client, &writes, &queries
}

func createDefaultTestAccount(ctx context.Context, client *Client, class string, parent Identity, options ObjectMutationOptions) (ObjectMutationResult, error) {
	switch class {
	case "user":
		result, err := client.CreateUser(ctx, CreateUserRequest{Name: "sample", Parent: parent, Options: options})
		return result.Creation, err
	case "computer":
		result, err := client.CreateComputer(ctx, CreateComputerRequest{Name: "sample", Parent: parent, Options: options})
		return result.Creation, err
	default:
		result, err := client.CreateGroup(ctx, CreateGroupRequest{Name: "sample", Parent: parent, Category: GroupSecurity, Scope: GroupGlobal, Options: options})
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
				key := wellKnownUsers
				if class == "computer" {
					key = wellKnownComputers
				}
				mapping := objectTestEntry(partition)
				mapping.Attributes["wellknownobjects"] = [][]byte{[]byte("B:32:" + strings.ToLower(key) + ":" + container)}
				client, writes, queries := defaultCreationFixture(t, CapabilityActiveDirectory, partition, container, mapping, nil)
				options := ObjectMutationOptions{}
				if selection == "config" {
					client.config.Partition = partition
				} else if selection == "request-over-config" {
					client.config.Partition = "DC=example"
					options.Partition = partition
				}
				var parent Identity
				if selection == "explicit-parent" {
					parent, _ = IdentityByDN(container)
				}
				result, err := createDefaultTestAccount(context.Background(), client, class, parent, options)
				if err != nil || *writes != 1 || !result.Verified || result.TargetDN != "cn=sample,"+container {
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
				key := wellKnownUsers
				if class == "computer" {
					key = wellKnownComputers
				}
				container := "OU=Redirected,DC=example"
				mapping := objectTestEntry("DC=example")
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
					mapping.Attributes["wellknownobjects"] = append(mapping.Attributes["wellknownobjects"], value)
				case "malformed":
					mapping.Attributes["wellknownobjects"] = [][]byte{[]byte("B:31:" + key + ":" + container)}
				case "cross-partition":
					mapping.Attributes["wellknownobjects"] = [][]byte{[]byte("B:32:" + key + ":OU=Elsewhere,DC=other")}
				case "permission":
					lookupErr = &LDAPError{Code: 50}
				case "missing-target":
					mapping.Attributes["wellknownobjects"] = [][]byte{[]byte("B:32:" + wellKnownSystem + ":CN=System,DC=example")}
				}
				client, writes, _ := defaultCreationFixture(t, CapabilityActiveDirectory, "DC=example", container, mapping, lookupErr)
				result, err := createDefaultTestAccount(context.Background(), client, class, Identity{}, ObjectMutationOptions{})
				var parentErr *AccountCreationParentError
				if !errors.As(err, &parentErr) || len(parentErr.Observation.Candidates) != 1 || *writes != 0 || result.State != ObjectWriteNotAttempted {
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
		mapping := objectTestEntry("DC=example")
		mapping.Attributes["wellknownobjects"] = [][]byte{[]byte("B:32:" + wellKnownUsers + ":CN=Roles,DC=example")}
		client, writes, _ := defaultCreationFixture(t, CapabilityADLDS, "DC=example", "CN=Roles,DC=example", mapping, nil)
		result, err := createDefaultTestAccount(context.Background(), client, class, Identity{}, ObjectMutationOptions{})
		if err != nil || *writes != 1 || !result.Verified {
			t.Fatal(class, result, err)
		}
	}
	client, writes, queries := defaultCreationFixture(t, CapabilityActiveDirectory, "DC=example", "CN=Users,DC=example", Object{}, nil)
	session := client.session.(objectWriteTestSession)
	original := session.read
	session.read = func(ctx context.Context, properties []string) (map[string][][]byte, error) {
		root, err := original(ctx, properties)
		delete(root, "defaultnamingcontext")
		return root, err
	}
	client.session = session
	_, err := createDefaultTestAccount(context.Background(), client, "user", Identity{}, ObjectMutationOptions{})
	if !errors.Is(err, ErrNoDefaultPartition) || *writes != 0 || len(*queries) != 0 {
		t.Fatal(err, *writes, len(*queries))
	}
}
