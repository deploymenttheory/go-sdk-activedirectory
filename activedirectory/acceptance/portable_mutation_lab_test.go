package acceptance

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"os"
	"regexp"
	"runtime"
	"strings"
	"testing"
	"time"

	ad "github.com/deploymenttheory/go-sdk-activedirectory/activedirectory"
	memberships "github.com/deploymenttheory/go-sdk-activedirectory/activedirectory/services/memberships"
	replication "github.com/deploymenttheory/go-sdk-activedirectory/activedirectory/services/replication"
	users "github.com/deploymenttheory/go-sdk-activedirectory/activedirectory/services/users"
)

var portableMutationLabBuildRevision string

type portableMutationLabStep struct {
	Role     string                  `json:"role"`
	Mutation ad.ObjectMutationResult `json:"mutation"`
	Class    ad.ErrorClass           `json:"class"`
	LDAPCode uint32                  `json:"ldap_code"`
}

type portableMutationLabCase struct {
	ID           string                        `json:"id"`
	Mutation     ad.ObjectMutationResult       `json:"mutation"`
	Steps        []portableMutationLabStep     `json:"steps,omitempty"`
	Class        ad.ErrorClass                 `json:"class"`
	LDAPCode     uint32                        `json:"ldap_code"`
	ErrorFacts   portableMutationLabErrorFacts `json:"error_facts"`
	Unverifiable bool                          `json:"unverifiable"`
	Contradicted bool                          `json:"contradicted"`
	Complete     bool                          `json:"complete"`
	Passed       bool                          `json:"passed"`
}

// Sentinel facts omit diagnostic strings, matched DNs and arbitrary error values.
type portableMutationLabErrorFacts struct {
	LDAPStatus    bool `json:"ldap_status_observed"`
	Readback      bool `json:"readback_failed"`
	Incomplete    bool `json:"incomplete"`
	References    bool `json:"search_references"`
	Connection    bool `json:"connection_failed"`
	Closed        bool `json:"closed"`
	InvalidResult bool `json:"invalid_result"`
	IdentityScope bool `json:"identity_scope"`
	Canceled      bool `json:"canceled"`
	Deadline      bool `json:"deadline"`
}

type portableMutationLabReport struct {
	SchemaVersion int                        `json:"schema_version"`
	RunID         string                     `json:"run_id"`
	Source        string                     `json:"source_revision"`
	Platform      string                     `json:"platform"`
	GoVersion     string                     `json:"go_version"`
	ActorScope    string                     `json:"actor_scope"`
	Protection    ad.SessionProtection       `json:"protection"`
	Cases         []*portableMutationLabCase `json:"cases"`
	Passed        bool                       `json:"passed"`
}

func portableMutationLabDN(run, role string) (string, string) {
	parent := "OU=sdk09-" + run + "," + portableMutationDomain
	site := "CN=sdk09-" + run + ",CN=Sites,CN=Configuration," + portableMutationDomain
	switch role {
	case "parent":
		return parent, "organizationalUnit"
	case "site":
		return site, "site"
	case "settings":
		return "CN=NTDS Site Settings," + site, "nTDSSiteSettings"
	case "group-allowed", "group-denied":
		return "CN=" + role + "," + parent, "group"
	default:
		return "CN=" + role + "," + parent, "user"
	}
}

func portableMutationLabTargets(input portablePolicyLabInput) (map[string]portablePolicyLabTarget, bool, error) {
	if !regexp.MustCompile(`^[A-Za-z0-9-]{1,40}$`).MatchString(input.RunID) {
		return nil, false, errors.New("invalid owned mutation run identity")
	}
	roles := []string{"parent", "subject", "manager", "hidden", "group-allowed", "group-denied", "site", "settings", "delete-unverified"}
	privileged := len(input.Targets) == 2
	if privileged {
		roles = []string{"parent", "delete-verified"}
	}
	if len(input.Targets) != len(roles) {
		return nil, false, errors.New("mutation fixture target count differs")
	}
	result, seen := make(map[string]portablePolicyLabTarget), make(map[ad.GUID]bool)
	for _, target := range input.Targets {
		dn, _ := portableMutationLabDN(input.RunID, target.Role)
		guid, err := ad.ParseGUID(target.GUID)
		if err != nil || guid == (ad.GUID{}) || seen[guid] || result[target.Role].Role != "" || !strings.EqualFold(dn, target.DN) {
			return nil, false, errors.New("owned mutation target GUID or DN differs")
		}
		seen[guid], result[target.Role] = true, target
	}
	for _, role := range roles {
		if result[role].Role != role {
			return nil, false, errors.New("owned mutation fixture role missing or replaced")
		}
	}
	return result, privileged, nil
}

// TestPortableMutationContractsLab uses public Dial and resource APIs only.
// The ordinary actor and privileged deletion invocation are separate inputs,
// connections and reports. No wrapper, credential fallback or timed ACL change
// changes the SDK's observations. The outer runner owns fixtures and cleanup.
func TestPortableMutationContractsLab(t *testing.T) {
	if os.Getenv("ADSDK_MUTATION_LAB_INPUT") == "" {
		t.Skip("requires explicit owned mutation fixtures and JSON stdin")
	}
	if os.Getenv("ADSDK_MUTATION_LAB_INPUT") != "stdin" {
		t.Fatal("mutation lab input mode must be stdin")
	}
	input, err := portableReadPolicyLabInput(os.Stdin)
	if err != nil {
		t.Fatal(err)
	}
	defer clear(input.Password)
	config, err := portablePolicyLabConfig(input)
	if err != nil || portableMutationLabBuildRevision == "" || input.SourceRevision != portableMutationLabBuildRevision {
		t.Fatal("invalid explicit Kerberos Seal configuration or source label")
	}
	targets, privileged, err := portableMutationLabTargets(input)
	if err != nil {
		t.Fatal(err)
	}
	output, err := os.OpenFile(input.Result, os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0o600)
	if err != nil {
		t.Fatal("create fresh mutation lab artifact:", err)
	}
	report := portableMutationLabReport{
		SchemaVersion: 1, RunID: input.RunID, Source: portableMutationLabBuildRevision,
		Platform: runtime.GOOS + "/" + runtime.GOARCH, GoVersion: runtime.Version(), ActorScope: "ordinary",
	}
	if privileged {
		report.ActorScope = "privileged-owned-deletion-only"
	}
	defer func() {
		report.Passed = !t.Failed()
		if err := json.NewEncoder(output).Encode(report); err != nil {
			t.Error("write mutation lab artifact:", err)
		}
		if err := output.Close(); err != nil {
			t.Error("close mutation lab artifact:", err)
		}
	}()
	ctx, cancel := context.WithTimeout(t.Context(), 3*time.Minute)
	defer cancel()
	client := portableReaderLabDial(t, ctx, config, &report.Protection)
	defer func() { _ = client.Close() }()
	root, err := client.Directory.RootDSE(ctx, ad.RootDSEOptions{})
	if err != nil || root.DNSHostName == nil || !strings.EqualFold(*root.DNSHostName, config.Endpoint.Host) ||
		root.DefaultNamingContext == nil || *root.DefaultNamingContext != portableMutationDomain || root.ConfigurationNamingContext == nil ||
		*root.ConfigurationNamingContext != "CN=Configuration,"+portableMutationDomain || root.Capabilities().RequireADDS("mutation lab") != nil {
		t.Fatal("mutation lab directory identity differs", err)
	}
	for _, target := range input.Targets {
		portableMutationLabGuard(t, ctx, client, input.RunID, target)
	}
	if privileged {
		portableMutationLabDelete(t, ctx, client, targets["delete-verified"], true, &report)
		return
	}
	portableMutationLabValues(t, ctx, client, targets, &report)
	portableMutationLabMembership(t, ctx, client, targets, &report)
	portableMutationLabSite(t, ctx, client, targets, &report)
	portableMutationLabDelete(t, ctx, client, targets["delete-unverified"], false, &report)
}

func portableMutationLabGuard(t *testing.T, ctx context.Context, client *ad.Client, run string, target portablePolicyLabTarget) {
	t.Helper()
	observed, err := client.Directory.Search(ctx, ad.SearchOptions{
		Base: target.DN, Scope: ad.ScopeBase, PageSize: 2, ResultLimit: 2,
		Properties: []string{"objectGUID", "objectClass", "description", "userAccountControl", "sAMAccountName"},
	})
	if err != nil || !observed.Complete || len(observed.Objects) != 1 {
		t.Fatal("owned mutation fixture read incomplete", target.Role)
	}
	object := observed.Objects[0]
	value, err := object.Values("objectGUID").Single()
	if err != nil {
		t.Fatal("owned mutation fixture GUID missing", target.Role)
	}
	guid, err := value.GUID()
	if err != nil || !strings.EqualFold(guid.String(), target.GUID) {
		t.Fatal("owned mutation fixture GUID replaced", target.Role)
	}
	_, class := portableMutationLabDN(run, target.Role)
	found := false
	for _, value := range object.Values("objectClass").Values {
		found = found || strings.EqualFold(string(value.Bytes()), class)
	}
	if !found {
		t.Fatal("owned mutation fixture class differs", target.Role)
	}
	if target.Role == "parent" {
		value, err := object.Values("description").Single()
		if err != nil || string(value.Bytes()) != "sdk09-mutations:"+run {
			t.Fatal("owned mutation parent marker differs")
		}
	}
	if class == "user" {
		value, err := object.Values("userAccountControl").Single()
		if err != nil {
			t.Fatal("owned mutation user disabled state unavailable")
		}
		flags, err := value.Flags32()
		if err != nil || !flags.Has(2) {
			t.Fatal("owned mutation user must remain disabled")
		}
	}
	if class == "user" || class == "group" {
		value, err := object.Values("sAMAccountName").Single()
		if err != nil || string(value.Bytes()) != portableMutationLabSAM(run, target.Role) {
			t.Fatal("owned mutation fixture account name differs", target.Role)
		}
	}
}

func portableMutationLabCapture(entry *portableMutationLabCase, mutation ad.ObjectMutationResult, err error) {
	entry.Mutation, entry.Class = mutation, ad.Classify(err)
	entry.Unverifiable, entry.Contradicted = errors.Is(err, ad.ErrObjectUnverifiable), errors.Is(err, ad.ErrObjectVerification)
	entry.ErrorFacts = portableMutationLabErrorFacts{
		Readback: errors.Is(err, ad.ErrObjectReadback), Incomplete: errors.Is(err, ad.ErrIncompleteResult), References: errors.Is(err, ad.ErrSearchReferences),
		Connection: errors.Is(err, ad.ErrConnection), Closed: errors.Is(err, ad.ErrClosed), InvalidResult: errors.Is(err, ad.ErrInvalidResult),
		IdentityScope: errors.Is(err, ad.ErrIdentityScope), Canceled: errors.Is(err, context.Canceled), Deadline: errors.Is(err, context.DeadlineExceeded),
	}
	var status *ad.LDAPError
	if errors.As(err, &status) {
		entry.LDAPCode = status.Code
		entry.ErrorFacts.LDAPStatus = true
	}
}

func portableMutationLabIdentity(t *testing.T, target portablePolicyLabTarget) ad.Identity {
	t.Helper()
	identity, err := ad.IdentityByGUID(target.GUID)
	if err != nil {
		t.Fatal("invalid pinned mutation fixture GUID")
	}
	return identity
}

func portableMutationLabValues(t *testing.T, ctx context.Context, client *ad.Client, targets map[string]portablePolicyLabTarget, report *portableMutationLabReport) {
	t.Helper()
	manager := strings.NewReplacer("CN=", "cn=", "OU=", "ou=", "DC=", "dc=").Replace(targets["manager"].DN)
	entry := &portableMutationLabCase{ID: "schema-proven-manager-normalization"}
	report.Cases = append(report.Cases, entry)
	result, err := client.Users.UpdateUser(ctx, users.UpdateUserRequest{
		Identity: portableMutationLabIdentity(t, targets["subject"]), Properties: users.UserProperties{ManagerDN: &manager},
	})
	portableMutationLabCapture(entry, result.Mutation, err)
	entry.Passed = entry.Mutation.State == ad.ObjectWriteAccepted && !entry.Mutation.Verified && entry.Unverifiable && entry.Class == ad.ClassUnverified &&
		result.User != nil && result.User.ManagerDN != nil && *result.User.ManagerDN != manager && strings.EqualFold(*result.User.ManagerDN, manager)
	if !entry.Passed {
		t.Fatal("public normalized manager mutation contract failed")
	}
	for _, hidden := range []bool{false, true} {
		role, id := "subject", "accepted-description-clear"
		change := ad.AttributeChange{Attribute: "description", Kind: ad.AttributeClear}
		if hidden {
			role, id = "hidden", "accepted-hidden-description-readback"
			change.Kind, change.Values = ad.AttributeSet, []ad.RawValue{ad.NewRawValue([]byte("sdk09-hidden-value"))}
		}
		entry := &portableMutationLabCase{ID: id}
		report.Cases = append(report.Cases, entry)
		mutation, err := client.Directory.UpdateObject(ctx, ad.UpdateObjectRequest{Identity: portableMutationLabIdentity(t, targets[role]), Changes: []ad.AttributeChange{change}})
		portableMutationLabCapture(entry, mutation, err)
		entry.Passed = mutation.State == ad.ObjectWriteAccepted && !mutation.Verified && mutation.TargetGUID != nil && mutation.Before != nil &&
			mutation.After != nil && mutation.ReadbackComplete
		if hidden {
			entry.Passed = entry.Passed && entry.Contradicted && entry.Class == ad.ClassUncertain
		} else {
			entry.Passed = entry.Passed && entry.Unverifiable && entry.Class == ad.ClassUnverified
		}
		if !entry.Passed {
			t.Fatal("public accepted clear/hidden readback contract failed", id)
		}
	}
}

func portableMutationLabMembership(t *testing.T, ctx context.Context, client *ad.Client,
	targets map[string]portablePolicyLabTarget, report *portableMutationLabReport,
) {
	t.Helper()
	entry := &portableMutationLabCase{ID: "accepted-group-then-denied-group"}
	report.Cases = append(report.Cases, entry)
	result, err := client.Memberships.AddPrincipalGroupMembership(ctx, memberships.PrincipalGroupMembershipRequest{
		Principal: portableMutationLabIdentity(t, targets["subject"]), Mode: memberships.GroupMembershipStrict,
		Groups: []memberships.PrincipalMembershipTarget{
			{Identity: portableMutationLabIdentity(t, targets["group-allowed"])}, {Identity: portableMutationLabIdentity(t, targets["group-denied"])},
		},
	})
	portableMutationLabCapture(entry, result.Mutation, err)
	entry.Complete = result.Complete
	for i, outcome := range result.Outcomes {
		step := portableMutationLabStep{Role: []string{"group-allowed", "group-denied"}[i], Mutation: outcome.Result.Mutation, Class: ad.Classify(outcome.Error)}
		var status *ad.LDAPError
		if errors.As(outcome.Error, &status) {
			step.LDAPCode = status.Code
		}
		entry.Steps = append(entry.Steps, step)
	}
	entry.Passed = !result.Complete && result.Processed == 2 && entry.Class == ad.ClassUncertain && entry.LDAPCode == 50 &&
		result.Mutation.State == ad.ObjectWriteAccepted && result.Mutation.PartialEffectsPossible && result.Mutation.TargetGUID == nil &&
		errors.Is(err, memberships.ErrPrincipalMembershipIncomplete) && len(entry.Steps) == 2 &&
		entry.Steps[0].Mutation.State == ad.ObjectWriteAccepted && entry.Steps[1].Mutation.State == ad.ObjectWriteRejected
	if !entry.Passed {
		t.Fatal("public non-atomic membership contract failed")
	}
}

func portableMutationLabSite(t *testing.T, ctx context.Context, client *ad.Client, targets map[string]portablePolicyLabTarget, report *portableMutationLabReport) {
	t.Helper()
	entry := &portableMutationLabCase{ID: "accepted-site-then-denied-settings"}
	report.Cases = append(report.Cases, entry)
	description := "sdk09-accepted-site-description"
	result, err := client.Replication.UpdateReplicationSite(ctx, replication.UpdateReplicationSiteRequest{
		Identity: portableMutationLabIdentity(t, targets["site"]), Description: &description,
		Settings: &replication.ReplicationSiteSettingsPatch{SetOptions: replication.SiteDisableAutomaticTopology},
	})
	portableMutationLabCapture(entry, result.Mutation, err)
	entry.Complete = result.Complete
	for _, outcome := range result.Steps {
		step := portableMutationLabStep{Role: outcome.Name, Mutation: outcome.Mutation, Class: ad.Classify(outcome.Error)}
		var status *ad.LDAPError
		if errors.As(outcome.Error, &status) {
			step.LDAPCode = status.Code
		}
		entry.Steps = append(entry.Steps, step)
	}
	entry.Passed = !result.Complete && entry.Class == ad.ClassUncertain && entry.LDAPCode == 50 &&
		result.Mutation.State == ad.ObjectWriteAccepted && result.Mutation.PartialEffectsPossible && result.Mutation.TargetGUID != nil &&
		strings.EqualFold(result.Mutation.TargetGUID.String(), targets["site"].GUID) && result.Mutation.After != nil &&
		errors.Is(err, replication.ErrReplicationTopologyIncomplete) && len(entry.Steps) == 2 &&
		entry.Steps[0].Mutation.State == ad.ObjectWriteAccepted && entry.Steps[0].Mutation.Verified && entry.Steps[1].Mutation.State == ad.ObjectWriteRejected
	if !entry.Passed {
		t.Fatal("public non-atomic site contract failed")
	}
}

func portableMutationLabDelete(t *testing.T, ctx context.Context, client *ad.Client, target portablePolicyLabTarget, verified bool, report *portableMutationLabReport) {
	t.Helper()
	entry := &portableMutationLabCase{ID: target.Role}
	report.Cases = append(report.Cases, entry)
	mutation, err := client.Directory.DeleteObject(ctx, ad.DeleteObjectRequest{Identity: portableMutationLabIdentity(t, target)})
	portableMutationLabCapture(entry, mutation, err)
	entry.Passed = mutation.State == ad.ObjectWriteAccepted && mutation.AbsentAfter && mutation.Before != nil && mutation.TargetGUID != nil &&
		strings.EqualFold(mutation.TargetGUID.String(), target.GUID) && mutation.After == nil
	if verified {
		entry.Passed = entry.Passed && err == nil && mutation.Verified && mutation.DeletionReadback != nil &&
			mutation.DeletionReadback.Complete && len(mutation.DeletionReadback.Objects) == 1
	} else {
		entry.Passed = entry.Passed && !mutation.Verified && portableMutationLabInvisibleProof(entry, err)
	}
	if !entry.Passed {
		t.Fatal("public controlled deletion contract failed", target.Role)
	}
}

func portableMutationLabInvisibleProof(entry *portableMutationLabCase, err error) bool {
	if entry.ErrorFacts.References || entry.ErrorFacts.Connection || entry.ErrorFacts.Closed || entry.ErrorFacts.InvalidResult ||
		entry.ErrorFacts.IdentityScope || entry.ErrorFacts.Canceled || entry.ErrorFacts.Deadline {
		return false
	}
	if !((entry.Unverifiable && entry.Class == ad.ClassUnverified) ||
		(entry.ErrorFacts.Readback && entry.Class == ad.ClassUncertain && entry.ErrorFacts.LDAPStatus && (entry.LDAPCode == 32 || entry.LDAPCode == 50))) {
		return false
	}
	return portableMutationLabVisibilityCausesOnly(err)
}

// Reject mixed or unknown causes; a denial joined to a transport/decoder failure
// must not turn a broken proof request into a passing visibility scenario.
func portableMutationLabVisibilityCausesOnly(err error) bool {
	if err == nil {
		return false
	}
	if joined, ok := err.(interface{ Unwrap() []error }); ok {
		for _, cause := range joined.Unwrap() {
			if cause != nil && !portableMutationLabVisibilityCausesOnly(cause) {
				return false
			}
		}
		return true
	}
	if wrapped, ok := err.(interface{ Unwrap() error }); ok {
		return portableMutationLabVisibilityCausesOnly(wrapped.Unwrap())
	}
	if status, ok := err.(*ad.LDAPError); ok {
		return status.Code == 32 || status.Code == 50
	}
	return errors.Is(err, ad.ErrObjectUnverifiable) || errors.Is(err, ad.ErrObjectReadback) ||
		errors.Is(err, ad.ErrIncompleteResult) || errors.Is(err, ad.ErrObjectWritePermission)
}

func portableMutationLabSAM(run, role string) string {
	digest := sha256.Sum256([]byte(run + ":" + role))
	return "sd9" + hex.EncodeToString(digest[:6])
}
