//go:build windows && (amd64 || arm64)

package activedirectory

import (
	"context"
	"encoding/json"
	"fmt"
	"os"
	"runtime"
	"strconv"
	"strings"
	"testing"
	"time"
)

// The read-side sweep qualified endpoint-and-partition by reading. This is the
// write half, and the half that matters more: a read sent to the wrong
// partition returns nothing, while a write sent to the wrong partition could
// change the wrong directory.
//
// It reuses lifecycleTargets() rather than declaring its own table, so the two
// mutating harnesses cannot drift apart on which operation does what.

// writeEndpointRole names which lifecycle entry point an observation covers.
// Each operation in the contract gets its own row, so the artifact says which
// of create, update, delete or rename was observed rather than crediting a
// class as a whole.
type writeEndpointRole string

const (
	writeRoleCreate writeEndpointRole = "create"
	writeRoleUpdate writeEndpointRole = "update"
	writeRoleDelete writeEndpointRole = "delete"
	writeRoleRename writeEndpointRole = "rename"
)

type writeEndpointObservation struct {
	Cmdlet string            `json:"cmdlet"`
	Role   writeEndpointRole `json:"role"`

	// The success half: the write is submitted to the explicitly named server
	// and lands in the explicitly named partition. Both are asserted, because
	// accepting the options and honouring them are different claims.
	ExplicitServer    string `json:"explicit_server"`
	ExplicitPartition string `json:"explicit_partition"`
	ExplicitWrote     bool   `json:"explicit_endpoint_wrote"`
	LandedInPartition bool   `json:"landed_in_requested_partition"`
	ExplicitDetail    string `json:"explicit_detail,omitempty"`

	// The failure half, in both identity forms, because the SDK can only
	// detect the mismatch cheaply in one of them and the difference matters to
	// a caller.
	//
	// A distinguished name can be compared against the requested naming
	// context without touching the directory, so the refusal is a scope error:
	// the request was wrong. A GUID cannot, so the SDK searches the requested
	// partition, does not find the object, and says so — which is the contract
	// being honoured, because the one thing it must not do is find the object
	// in some other partition instead.
	//
	// Both are recorded. Measured live: the DN form reports invalid-request
	// (identity is outside the selected naming context) and the GUID form
	// reports not-found.
	MismatchPartition string `json:"mismatched_partition"`
	MismatchDNRefused bool   `json:"mismatched_partition_refused_by_dn"`
	MismatchDNClass   string `json:"mismatched_partition_dn_error_class"`
	MismatchDNDetail  string `json:"mismatched_partition_dn_detail,omitempty"`
	MismatchRefused   bool   `json:"mismatched_partition_refused_by_guid"`
	MismatchClass     string `json:"mismatched_partition_guid_error_class"`
	MismatchDetail    string `json:"mismatched_partition_guid_detail,omitempty"`
	MismatchNoWrite   bool   `json:"mismatched_partition_wrote_nothing"`

	Allocations int    `json:"native_allocations_remaining"`
	Detail      string `json:"detail,omitempty"`
	Passed      bool   `json:"passed"`
}

// qualifies requires both halves in both identity forms, and the allocation
// balance. A refusal for the wrong reason is a different observation.
//
// The distinguished-name form must report a request-level refusal: the SDK had
// everything it needed to reject the call without asking the directory. The
// GUID form must report not-found, which is the honest answer for a search of
// the requested partition and the proof that no other partition was consulted.
// Neither may report denied or uncertain — both of those would mean the write
// had been attempted somewhere.
func (o writeEndpointObservation) qualifies() bool {
	dn := o.MismatchDNRefused &&
		(o.MismatchDNClass == ClassInvalidRequest.String() ||
			o.MismatchDNClass == ClassUnsupported.String())
	guid := o.MismatchRefused && o.MismatchClass == ClassNotFound.String()
	return o.ExplicitWrote && o.LandedInPartition && dn && guid &&
		o.MismatchNoWrite && o.Allocations == 0
}

// writeEndpointUSN reads the target's uSNChanged. Any committed modification
// bumps it, so comparing it across a refused call is how "nothing reached the
// directory" is established without depending on the SDK's own accounting.
//
// A missing object reports zero rather than an error, because for a create the
// absence of the object is itself the proof.
func writeEndpointUSN(ctx context.Context, c *Client, id Identity) (uint64, bool) {
	observed, err := c.ResolveIdentity(ctx, id, ResolveIdentityOptions{Properties: []string{"uSNChanged"}})
	if err != nil || observed.Object == nil {
		return 0, false
	}
	value, err := observed.Object.Values("uSNChanged").Single()
	if err != nil {
		return 0, false
	}
	usn, err := value.Int64()
	if err != nil || usn < 0 {
		return 0, false
	}
	return uint64(usn), true
}

// The outer harness supplies the endpoint and the write authorization only
// inside an owned run. This test mutates the directory: it creates one
// container of fixtures and removes it. Ordinary go test invocations skip it.
//
// It qualifies endpoint-and-partition across the sixteen mutating operations a
// caller would use to manage the five resource classes, recording both halves.
func TestDirectoryWriteEndpointSweepLab(t *testing.T) {
	endpoint := os.Getenv("ADSDK_WRITE_ENDPOINT")
	if endpoint == "" {
		t.Skip("requires the opt-in isolated directory write-endpoint harness")
	}
	if os.Getenv("ADSDK_WRITE_ALLOW_WRITES") != "yes" {
		t.Fatal("this harness mutates the directory and requires explicit write authorization")
	}
	resultPath := os.Getenv("ADSDK_WRITE_RESULT")
	runID := os.Getenv("ADSDK_WRITE_RUN_ID")
	if resultPath == "" || runID == "" {
		t.Fatal("an endpoint, a run identity and a fresh result path are required")
	}

	artifact := struct {
		SchemaVersion       int                        `json:"schema_version"`
		Scope               string                     `json:"scope"`
		RunID               string                     `json:"run_id"`
		Endpoint            string                     `json:"endpoint"`
		RuntimeOS           string                     `json:"runtime_os"`
		RuntimeArchitecture string                     `json:"runtime_architecture"`
		Started             time.Time                  `json:"started"`
		Finished            time.Time                  `json:"finished"`
		Passed              bool                       `json:"passed"`
		FullTicketComplete  bool                       `json:"full_ticket_complete"`
		FailureStage        string                     `json:"failure_stage,omitempty"`
		DomainPartition     string                     `json:"domain_partition"`
		ForeignPartition    string                     `json:"foreign_partition"`
		FixtureRoot         string                     `json:"fixture_root"`
		FixtureRootRemoved  bool                       `json:"fixture_root_removed"`
		Operations          []writeEndpointObservation `json:"operations"`
	}{
		SchemaVersion: 1, Scope: "directory-write-endpoint-and-partition", RunID: runID,
		Endpoint: endpoint, RuntimeOS: runtime.GOOS, RuntimeArchitecture: runtime.GOARCH,
		Started: time.Now().UTC(), Operations: []writeEndpointObservation{},
	}
	stage := "start"
	failedAt := ""
	fail := func(format string, args ...any) {
		if failedAt == "" {
			failedAt = stage
		}
		t.Errorf(format, args...)
	}
	defer func() {
		artifact.Finished = time.Now().UTC()
		artifact.Passed = !t.Failed()
		if t.Failed() {
			artifact.FailureStage = failedAt
		}
		data, err := json.MarshalIndent(artifact, "", "  ")
		if err != nil {
			t.Error("cannot encode write-endpoint artifact")
			return
		}
		file, err := os.OpenFile(resultPath, os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0600)
		if err != nil {
			t.Error("cannot create fresh write-endpoint artifact")
			return
		}
		_, writeErr := file.Write(append(data, '\n'))
		if closeErr := file.Close(); writeErr != nil || closeErr != nil {
			t.Error("cannot finish write-endpoint artifact")
		}
	}()

	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Minute)
	defer cancel()

	client, err := Dial(ctx, Config{Endpoint: Endpoint{Host: endpoint, Port: 389}, Timeout: 60 * time.Second})
	if err != nil {
		t.Fatal("native dial failed")
	}
	defer func() {
		if closeErr := client.Close(); closeErr != nil {
			t.Error("the client did not close cleanly")
		}
	}()

	stage = "partitions"
	root, err := client.RootDSE(ctx, RootDSEOptions{})
	if err != nil || root.DefaultNamingContext == nil || root.ConfigurationNamingContext == nil {
		t.Fatal("the connection did not report both a default and a configuration naming context")
	}
	domain, foreign := *root.DefaultNamingContext, *root.ConfigurationNamingContext
	if domain == "" || foreign == "" || strings.EqualFold(domain, foreign) {
		t.Fatal("the two partitions must be distinct for the mismatch half to mean anything")
	}
	artifact.DomainPartition, artifact.ForeignPartition = domain, foreign

	// The foreign partition is a real naming context this server holds, so a
	// refusal cannot be mistaken for the partition simply not existing. The
	// fixtures all live in the domain partition.
	stage = "fixture-root"
	domainIdentity, err := IdentityByDN(domain)
	if err != nil {
		t.Fatal("the default naming context is not a usable identity")
	}
	// An organizational unit, not a container: an organizationalUnit cannot be
	// created inside a container at all — the directory refuses it with LDAP 64
	// — so a container root would make the unit's own operations unobservable.
	// Cleanup is installed from whatever the create reported, before any
	// decision about whether it succeeded, so a create that wrote the object
	// and then failed cannot leak it.
	rootResult, rootErr := client.CreateOrganizationalUnit(ctx, CreateOrganizationalUnitRequest{
		Parent: domainIdentity, Name: "sdk-writeendpoint-" + runID,
		ProtectedFromAccidentalDeletion: new(bool),
	})
	if rootResult.Object.TargetGUID != nil {
		artifact.FixtureRoot = rootResult.Object.TargetDN
		root := objectGUIDIdentity(*rootResult.Object.TargetGUID)
		defer func() {
			removal, removeErr := client.DeleteOrganizationalUnit(ctx,
				DeleteOrganizationalUnitRequest{Identity: root, Recursive: true})
			artifact.FixtureRootRemoved = removeErr == nil && removal.AbsentAfter &&
				lifecycleAbsent(ctx, client, root)
			if !artifact.FixtureRootRemoved {
				t.Errorf("the fixture root was not proved removed: err=%v absentAfter=%v",
					removeErr, removal.AbsentAfter)
			}
		}()
	}
	if rootErr != nil || rootResult.Object.TargetGUID == nil {
		t.Fatalf("cannot create the fixture root: %v", rootErr)
	}
	fixtureRoot := objectGUIDIdentity(*rootResult.Object.TargetGUID)
	fixtureRootDN, err := IdentityByDN(rootResult.Object.TargetDN)
	if err != nil {
		t.Fatal("the fixture root distinguished name is not a usable identity")
	}

	explicit := func(partition string) ObjectMutationOptions {
		return ObjectMutationOptions{Partition: partition, Properties: []string{"uSNChanged"}}
	}

	stage = "write-endpoint-sweep"
	for index, target := range lifecycleTargets() {
		var counts searchNativeCounts
		client.session.(*ldapSession).api = countedSearchAPI(&counts)
		name := fmt.Sprintf("sdkwe%d", index)
		if target.kind == "computer" {
			name = "SDKWE" + strconv.Itoa(index)
		}

		// --- create ------------------------------------------------------
		create := writeEndpointObservation{
			Cmdlet: target.createCmdlet, Role: writeRoleCreate,
			ExplicitServer: endpoint, ExplicitPartition: domain, MismatchPartition: foreign,
		}
		// The mismatches are attempted first, so their "wrote nothing" check is
		// the absence of an object that the success half then goes on to create.
		_, dnErr := target.create(ctx, client, fixtureRootDN, name, explicit(foreign))
		create.MismatchDNRefused = dnErr != nil
		create.MismatchDNClass = lifecycleClass(dnErr)
		create.MismatchDNDetail = lifecycleDetail(dnErr)
		_, mismatchErr := target.create(ctx, client, fixtureRoot, name, explicit(foreign))
		create.MismatchRefused = mismatchErr != nil
		create.MismatchClass = lifecycleClass(mismatchErr)
		create.MismatchDetail = lifecycleDetail(mismatchErr)

		created, createErr := target.create(ctx, client, fixtureRoot, name, explicit(domain))
		create.ExplicitWrote = createErr == nil && created.TargetGUID != nil && created.Verified
		create.ExplicitDetail = lifecycleDetail(createErr)
		if created.TargetGUID == nil {
			// Nothing downstream is observable without the object.
			create.Detail = "create did not produce an object"
			create.Allocations = sweepAllocations(counts)
			fail("%s: %s", target.createCmdlet, create.Detail)
			artifact.Operations = append(artifact.Operations, create)
			continue
		}
		subject := objectGUIDIdentity(*created.TargetGUID)
		create.LandedInPartition = strings.HasSuffix(strings.ToLower(created.TargetDN),
			strings.ToLower(domain)) && created.Partition != "" &&
			strings.EqualFold(created.Partition, domain)
		// Exactly one object exists, so neither refused create wrote anything.
		// Had either written, this create would have been refused as a
		// duplicate — which is a stronger proof than counting requests, and it
		// does not depend on this create succeeding for any other reason.
		// Neither refused create wrote anything, proved by this one succeeding:
		// had either written, this create would have been refused as a
		// duplicate. That is a stronger proof than counting requests.
		create.MismatchNoWrite = createErr == nil
		create.Allocations = sweepAllocations(counts)
		create.Passed = create.qualifies()
		if !create.Passed {
			fail("%s: endpoint observation incomplete: %+v", target.createCmdlet, create)
		}
		artifact.Operations = append(artifact.Operations, create)

		// --- update ------------------------------------------------------
		counts = searchNativeCounts{}
		update := writeEndpointObservation{
			Cmdlet: target.updateCmdlet, Role: writeRoleUpdate,
			ExplicitServer: endpoint, ExplicitPartition: domain, MismatchPartition: foreign,
		}
		change := []AttributeChange{{Attribute: lifecycleMultiValued, Kind: AttributeSet,
			Values: lifecycleRawValues("endpoint")}}
		before, ok := writeEndpointUSN(ctx, client, subject)
		if !ok {
			update.Detail = "uSNChanged unreadable before the refused update"
		}
		subjectDN, dnIdentityErr := IdentityByDN(created.TargetDN)
		if dnIdentityErr != nil {
			update.Detail = "the created distinguished name is not a usable identity"
		}
		_, dnErr = target.updateRaw(ctx, client, subjectDN, change, explicit(foreign))
		update.MismatchDNRefused = dnErr != nil
		update.MismatchDNClass = lifecycleClass(dnErr)
		update.MismatchDNDetail = lifecycleDetail(dnErr)
		_, mismatchErr = target.updateRaw(ctx, client, subject, change, explicit(foreign))
		update.MismatchRefused = mismatchErr != nil
		update.MismatchClass = lifecycleClass(mismatchErr)
		update.MismatchDetail = lifecycleDetail(mismatchErr)
		after, stillThere := writeEndpointUSN(ctx, client, subject)
		update.MismatchNoWrite = ok && stillThere && after == before

		updated, updateErr := target.updateRaw(ctx, client, subject, change, explicit(domain))
		update.ExplicitWrote = updateErr == nil && updated.Verified
		update.ExplicitDetail = lifecycleDetail(updateErr)
		update.LandedInPartition = updated.After != nil &&
			strings.HasSuffix(strings.ToLower(updated.After.DistinguishedName), strings.ToLower(domain))
		update.Allocations = sweepAllocations(counts)
		update.Passed = update.qualifies()
		if !update.Passed {
			fail("%s: endpoint observation incomplete: %+v", target.updateCmdlet, update)
		}
		artifact.Operations = append(artifact.Operations, update)

		// --- rename, for the one operation that has it -------------------
		if target.kind == "object" {
			counts = searchNativeCounts{}
			rename := writeEndpointObservation{
				Cmdlet: "Rename-ADObject", Role: writeRoleRename,
				ExplicitServer: endpoint, ExplicitPartition: domain, MismatchPartition: foreign,
			}
			before, ok = writeEndpointUSN(ctx, client, subject)
			_, dnErr = client.RenameObject(ctx, RenameObjectRequest{
				Identity: subjectDN, Name: name + "-renamed", Options: explicit(foreign)})
			rename.MismatchDNRefused = dnErr != nil
			rename.MismatchDNClass = lifecycleClass(dnErr)
			rename.MismatchDNDetail = lifecycleDetail(dnErr)
			_, mismatchErr = client.RenameObject(ctx, RenameObjectRequest{
				Identity: subject, Name: name + "-renamed", Options: explicit(foreign)})
			rename.MismatchRefused = mismatchErr != nil
			rename.MismatchClass = lifecycleClass(mismatchErr)
			rename.MismatchDetail = lifecycleDetail(mismatchErr)
			after, stillThere = writeEndpointUSN(ctx, client, subject)
			rename.MismatchNoWrite = ok && stillThere && after == before

			renamed, renameErr := client.RenameObject(ctx, RenameObjectRequest{
				Identity: subject, Name: name + "-renamed", Options: explicit(domain)})
			rename.ExplicitWrote = renameErr == nil && renamed.Verified
			rename.ExplicitDetail = lifecycleDetail(renameErr)
			rename.LandedInPartition = renamed.After != nil &&
				strings.HasSuffix(strings.ToLower(renamed.After.DistinguishedName), strings.ToLower(domain))
			rename.Allocations = sweepAllocations(counts)
			rename.Passed = rename.qualifies()
			if !rename.Passed {
				fail("Rename-ADObject: endpoint observation incomplete: %+v", rename)
			}
			artifact.Operations = append(artifact.Operations, rename)
		}

		// --- delete ------------------------------------------------------
		counts = searchNativeCounts{}
		remove := writeEndpointObservation{
			Cmdlet: target.removeCmdlet, Role: writeRoleDelete,
			ExplicitServer: endpoint, ExplicitPartition: domain, MismatchPartition: foreign,
		}
		if target.protectedByDefault && target.unprotect != nil {
			if err := target.unprotect(ctx, client, subject, explicit(domain)); err != nil {
				remove.Detail = "unprotect: " + err.Error()
			}
		}
		before, ok = writeEndpointUSN(ctx, client, subject)
		_, dnErr = target.remove(ctx, client, subjectDN, false, explicit(foreign))
		remove.MismatchDNRefused = dnErr != nil
		remove.MismatchDNClass = lifecycleClass(dnErr)
		remove.MismatchDNDetail = lifecycleDetail(dnErr)
		_, mismatchErr = target.remove(ctx, client, subject, false, explicit(foreign))
		remove.MismatchRefused = mismatchErr != nil
		remove.MismatchClass = lifecycleClass(mismatchErr)
		remove.MismatchDetail = lifecycleDetail(mismatchErr)
		after, stillThere = writeEndpointUSN(ctx, client, subject)
		// Survival is the load-bearing part here: a refused delete that
		// deleted would read as absent.
		remove.MismatchNoWrite = ok && stillThere && after == before

		deleted, deleteErr := target.remove(ctx, client, subject, false, explicit(domain))
		remove.ExplicitWrote = deleteErr == nil && deleted.AbsentAfter &&
			lifecycleAbsent(ctx, client, subject)
		remove.ExplicitDetail = lifecycleDetail(deleteErr)
		// A delete has no surviving object to place, so the partition claim is
		// the one the request carried and the SDK reported acting within.
		remove.LandedInPartition = strings.EqualFold(deleted.Partition, domain)
		remove.Allocations = sweepAllocations(counts)
		remove.Passed = remove.qualifies()
		if !remove.Passed {
			fail("%s: endpoint observation incomplete: %+v", target.removeCmdlet, remove)
		}
		artifact.Operations = append(artifact.Operations, remove)
	}

	if !t.Failed() {
		stage = "complete"
	}
	t.Logf("write endpoint and partition sweep over %d operations on %s; full ticket qualification remains incomplete",
		len(artifact.Operations), endpoint)
}
