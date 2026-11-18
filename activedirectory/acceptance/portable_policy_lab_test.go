package acceptance

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"reflect"
	"regexp"
	"runtime"
	"strings"
	"testing"
	"time"

	ad "github.com/deploymenttheory/go-sdk-activedirectory/activedirectory"
	authpolicies "github.com/deploymenttheory/go-sdk-activedirectory/activedirectory/services/authentication_policies"
	centralaccess "github.com/deploymenttheory/go-sdk-activedirectory/activedirectory/services/central_access"
	"github.com/deploymenttheory/go-sdk-activedirectory/conditions"
)

var portablePolicyLabBuildRevision string

const (
	portablePolicyLabCurrent   = "msAuthz-EffectiveSecurityPolicy"
	portablePolicyLabProposed  = "msAuthz-ProposedSecurityPolicy"
	portablePolicyLabPrevious  = "msAuthz-LastEffectiveSecurityPolicy"
	portablePolicyLabCondition = "msAuthz-ResourceCondition"
)

type portablePolicyLabTarget struct {
	Role string `json:"role"`
	DN   string `json:"dn"`
	GUID string `json:"guid"`
}

type portablePolicyLabInput struct {
	CredentialSource string                    `json:"credential_source"`
	Password         []byte                    `json:"password_base64,omitempty"`
	Endpoint         string                    `json:"endpoint"`
	Realm            string                    `json:"realm"`
	SPN              string                    `json:"spn"`
	Username         string                    `json:"username"`
	CachePath        string                    `json:"cache_path"`
	RunID            string                    `json:"run_id"`
	SourceRevision   string                    `json:"source_revision"`
	Result           string                    `json:"result"`
	Targets          []portablePolicyLabTarget `json:"targets"`
}

func (portablePolicyLabInput) String() string   { return "PolicyLabInput{redacted}" }
func (portablePolicyLabInput) GoString() string { return "PolicyLabInput{redacted}" }
func (portablePolicyLabInput) Format(state fmt.State, _ rune) {
	_, _ = io.WriteString(state, "PolicyLabInput{redacted}")
}

func (portablePolicyLabInput) MarshalJSON() ([]byte, error) { return []byte(`{"redacted":true}`), nil }

func (portablePolicyLabInput) MarshalText() ([]byte, error) {
	return []byte("PolicyLabInput{redacted}"), nil
}

type portablePolicyLabCase struct {
	ID              string                  `json:"id"`
	Target          portablePolicyLabTarget `json:"target"`
	State           ad.ObjectWriteState     `json:"state"`
	Verified        bool                    `json:"verified"`
	LDAPCode        uint32                  `json:"ldap_code"`
	ValidationError bool                    `json:"validation_error"`
	Before          map[string][][]byte     `json:"before_base64"`
	Submitted       map[string][][]byte     `json:"submitted_base64"`
	After           map[string][][]byte     `json:"after_base64"`
	Passed          bool                    `json:"passed"`
}

type portablePolicyLabReport struct {
	SchemaVersion int                      `json:"schema_version"`
	RunID         string                   `json:"run_id"`
	Source        string                   `json:"source_revision"`
	Platform      string                   `json:"platform"`
	GoVersion     string                   `json:"go_version"`
	Protection    ad.SessionProtection     `json:"protection"`
	Cases         []*portablePolicyLabCase `json:"cases"`
	Passed        bool                     `json:"passed"`
}

func portableReadPolicyLabInput(reader io.Reader) (portablePolicyLabInput, error) {
	data, err := io.ReadAll(io.LimitReader(reader, 128*1024+1))
	defer clear(data)
	if err != nil || len(data) > 128*1024 || len(bytes.TrimSpace(data)) == 0 || bytes.TrimSpace(data)[0] != '{' {
		return portablePolicyLabInput{}, errors.New("invalid bounded policy lab input")
	}
	decoder := json.NewDecoder(bytes.NewReader(data))
	decoder.DisallowUnknownFields()
	var input portablePolicyLabInput
	if err := decoder.Decode(&input); err != nil {
		clear(input.Password)
		return portablePolicyLabInput{}, errors.New("invalid policy lab input object")
	}
	if err := decoder.Decode(new(any)); !errors.Is(err, io.EOF) {
		clear(input.Password)
		return portablePolicyLabInput{}, errors.New("policy lab input must contain one object")
	}
	return input, nil
}

func portablePolicyLabConfig(input portablePolicyLabInput) (ad.Config, error) {
	return portableReaderLabConfig(portableReaderLabInput{
		CredentialSource: input.CredentialSource, Password: input.Password, Endpoint: input.Endpoint,
		Realm: input.Realm, SPN: input.SPN, Username: input.Username, CachePath: input.CachePath,
	})
}

func portablePolicyLabTargets(input portablePolicyLabInput) (map[string]portablePolicyLabTarget, error) {
	if !regexp.MustCompile(`^[A-Za-z0-9-]{1,40}$`).MatchString(input.RunID) || len(input.Targets) != 4 {
		return nil, errors.New("invalid owned policy run ID or target count")
	}
	result := make(map[string]portablePolicyLabTarget, 4)
	seen := make(map[string]bool, 4)
	for _, target := range input.Targets {
		parent := "CN=AuthN Policies,CN=AuthN Policy Configuration,CN=Services," + portablePolicyConfiguration
		switch target.Role {
		case "auth", "auth-denied":
		case "rule", "rule-denied":
			parent = "CN=Central Access Rules,CN=Claims Configuration,CN=Services," + portablePolicyConfiguration
		default:
			return nil, errors.New("unknown owned policy target role")
		}
		guid, err := ad.ParseGUID(target.GUID)
		if err != nil || guid == (ad.GUID{}) || seen[guid.String()] || result[target.Role].Role != "" ||
			!strings.EqualFold(target.DN, "CN=sdk08-"+input.RunID+"-"+target.Role+","+parent) {
			return nil, errors.New("policy target identity differs from explicit owned fixture")
		}
		seen[guid.String()], result[target.Role] = true, target
	}
	return result, nil
}

// TestPortablePolicyConditionsLab uses public Dial and policy services only.
// The outer runner owns four unassigned/unlinked fixture objects and their ACLs.
// No test wrapper, fault factory, policy assignment or enforcement is installed.
func TestPortablePolicyConditionsLab(t *testing.T) {
	if os.Getenv("ADSDK_POLICY_LAB_INPUT") == "" {
		t.Skip("requires explicit owned policy fixtures and JSON stdin")
	}
	if os.Getenv("ADSDK_POLICY_LAB_INPUT") != "stdin" {
		t.Fatal("policy lab input mode must be stdin")
	}
	input, err := portableReadPolicyLabInput(os.Stdin)
	if err != nil {
		t.Fatal(err)
	}
	defer clear(input.Password)
	config, err := portablePolicyLabConfig(input)
	if err != nil || portablePolicyLabBuildRevision == "" || input.SourceRevision != portablePolicyLabBuildRevision {
		t.Fatal("invalid explicit Kerberos Seal configuration or source label")
	}
	targets, err := portablePolicyLabTargets(input)
	if err != nil {
		t.Fatal(err)
	}
	output, err := os.OpenFile(input.Result, os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0o600)
	if err != nil {
		t.Fatal("create fresh policy lab artifact:", err)
	}
	report := portablePolicyLabReport{
		SchemaVersion: 1, RunID: input.RunID, Source: portablePolicyLabBuildRevision,
		Platform: runtime.GOOS + "/" + runtime.GOARCH, GoVersion: runtime.Version(),
	}
	defer func() {
		report.Passed = !t.Failed()
		if err := json.NewEncoder(output).Encode(report); err != nil {
			t.Error("write policy lab artifact:", err)
		}
		if err := output.Close(); err != nil {
			t.Error("close policy lab artifact:", err)
		}
	}()
	ctx, cancel := context.WithTimeout(t.Context(), 3*time.Minute)
	defer cancel()
	client := portableReaderLabDial(t, ctx, config, &report.Protection)
	defer func() { _ = client.Close() }()
	root, err := client.Directory.RootDSE(ctx, ad.RootDSEOptions{})
	if err != nil || root.DNSHostName == nil || !strings.EqualFold(*root.DNSHostName, config.Endpoint.Host) ||
		root.ConfigurationNamingContext == nil || !strings.EqualFold(*root.ConfigurationNamingContext, portablePolicyConfiguration) ||
		root.Capabilities().RequireADDS("policy lab") != nil {
		t.Fatal("policy lab directory identity guard failed", err)
	}
	for _, role := range []string{"auth", "rule", "auth-denied", "rule-denied", "auth-invalid", "rule-invalid"} {
		kind, invalid := strings.TrimSuffix(role, "-invalid"), strings.HasSuffix(role, "-invalid")
		target := targets[kind]
		entry := &portablePolicyLabCase{ID: role, Target: target}
		report.Cases = append(report.Cases, entry)
		portablePolicyLabApply(t, ctx, client, input.RunID, entry, invalid)
	}
}

func portablePolicyLabRead(t *testing.T, ctx context.Context, client *ad.Client, run string, target portablePolicyLabTarget) map[string][][]byte {
	t.Helper()
	properties := []string{"objectGUID", "objectClass", "description", "msDS-AuthNPolicyEnforced"}
	for _, name := range portablePolicyLabAttributes(strings.HasPrefix(target.Role, "auth")) {
		properties = append(properties, name)
	}
	result, err := client.Directory.Search(ctx, ad.SearchOptions{Base: target.DN, Scope: ad.ScopeBase, PageSize: 2, ResultLimit: 2, Properties: properties})
	if err != nil || !result.Complete || len(result.Objects) != 1 {
		t.Fatal("owned policy fixture read incomplete", err)
	}
	object := result.Objects[0]
	guidValue, err := object.Values("objectGUID").Single()
	if err != nil {
		t.Fatal("owned policy fixture GUID missing", err)
	}
	guid, err := guidValue.GUID()
	if err != nil || !strings.EqualFold(guid.String(), target.GUID) {
		t.Fatal("owned policy fixture GUID differs", err)
	}
	marker, err := object.Values("description").Single()
	if err != nil || string(marker.Bytes()) != "sdk08-condition:"+run+":"+target.Role {
		t.Fatal("owned policy fixture marker differs", err)
	}
	if strings.HasPrefix(target.Role, "auth") {
		flag, err := object.Values("msDS-AuthNPolicyEnforced").Single()
		if err != nil || string(flag.Bytes()) != "FALSE" {
			t.Fatal("owned authentication policy must remain audit-only", err)
		}
	}
	values := make(map[string][][]byte)
	for _, name := range portablePolicyLabAttributes(strings.HasPrefix(target.Role, "auth")) {
		for _, value := range object.Values(name).Values {
			values[name] = append(values[name], value.Bytes())
		}
	}
	return values
}

func portablePolicyLabAttributes(auth bool) []string {
	if auth {
		return []string{
			"msDS-UserAllowedToAuthenticateFrom", "msDS-UserAllowedToAuthenticateTo", "msDS-ComputerAllowedToAuthenticateTo",
			"msDS-ServiceAllowedToAuthenticateFrom", "msDS-ServiceAllowedToAuthenticateTo",
		}
	}
	return []string{portablePolicyLabCurrent, portablePolicyLabProposed, portablePolicyLabPrevious, portablePolicyLabCondition}
}

func portablePolicyLabApply(t *testing.T, ctx context.Context, client *ad.Client, run string, entry *portablePolicyLabCase, invalid bool) {
	t.Helper()
	entry.Before = portablePolicyLabRead(t, ctx, client, run, entry.Target)
	identity, err := ad.IdentityByDN(entry.Target.DN)
	if err != nil {
		t.Fatal(err)
	}
	var mutation ad.ObjectMutationResult
	if strings.HasPrefix(entry.Target.Role, "auth") {
		mutation, err = portablePolicyLabAuthentication(t, ctx, client, identity, entry, invalid)
	} else {
		mutation, err = portablePolicyLabCentral(t, ctx, client, identity, entry, invalid)
	}
	entry.State, entry.Verified = mutation.State, mutation.Verified
	entry.ValidationError = errors.Is(err, conditions.ErrInvalidExpression)
	var status *ad.LDAPError
	if errors.As(err, &status) {
		entry.LDAPCode = status.Code
	}
	entry.After = portablePolicyLabRead(t, ctx, client, run, entry.Target)
	switch {
	case invalid:
		entry.Passed = entry.State == ad.ObjectWriteNotAttempted && entry.ValidationError && reflect.DeepEqual(entry.Before, entry.After)
	case strings.HasSuffix(entry.Target.Role, "-denied"):
		entry.Passed = entry.State == ad.ObjectWriteRejected && entry.LDAPCode == 50 && errors.Is(err, ad.ErrObjectWritePermission) &&
			reflect.DeepEqual(entry.Before, entry.After)
	default:
		entry.Passed = err == nil && entry.State == ad.ObjectWriteAccepted && entry.Verified
		for name, values := range entry.Submitted {
			entry.Passed = entry.Passed && reflect.DeepEqual(entry.After[name], values)
		}
	}
	if !entry.Passed {
		t.Fatal("public portable policy case failed", entry.ID, "state", entry.State, "ldap", entry.LDAPCode, "validation", entry.ValidationError)
	}
}

func portablePolicyLabAuthentication(t *testing.T, ctx context.Context, client *ad.Client, identity ad.Identity,
	entry *portablePolicyLabCase, invalid bool,
) (ad.ObjectMutationResult, error) {
	t.Helper()
	from, err := conditions.Compile(conditions.ACE{TrusteeSID: "S-1-1-0", AccessMask: 0x100, Condition: conditions.MemberOf(true, "S-1-1-0")})
	if err != nil {
		t.Fatal(err)
	}
	to, err := conditions.Compile(conditions.ACE{TrusteeSID: "S-1-1-0", AccessMask: 0x100, Condition: conditions.MemberOf(false, "S-1-1-0")})
	if err != nil {
		t.Fatal(err)
	}
	entry.Submitted = make(map[string][][]byte)
	for _, name := range portablePolicyLabAttributes(true) {
		sddl := to
		if strings.HasSuffix(name, "From") {
			sddl = from
		}
		raw, err := conditions.DescriptorBytes(sddl)
		if err != nil {
			t.Fatal(err)
		}
		entry.Submitted[name] = [][]byte{raw}
	}
	if invalid {
		to = `D:(XA;;CR;;;WD;(@User.Score Matches 7))`
		entry.Submitted = nil
	}
	result, err := client.AuthenticationPolicies.UpdateAuthenticationPolicy(ctx, authpolicies.UpdateAuthenticationPolicyRequest{
		Identity: identity, Properties: authpolicies.AuthenticationPolicyProperties{
			UserAllowedToAuthenticateFrom: &from, UserAllowedToAuthenticateTo: &to, ComputerAllowedToAuthenticateTo: &to,
			ServiceAllowedToAuthenticateFrom: &from, ServiceAllowedToAuthenticateTo: &to,
		},
	})
	return result.Mutation, err
}

func portablePolicyLabCentral(t *testing.T, ctx context.Context, client *ad.Client, identity ad.Identity,
	entry *portablePolicyLabCase, invalid bool,
) (ad.ObjectMutationResult, error) {
	t.Helper()
	current := `O:SYG:SYD:(XA;;FR;;;WD;(Member_of {SID(S-1-1-0)}))`
	proposed := `O:SYG:SYD:(XD;;FW;;;WD;(Device_Member_of {SID(S-1-1-0)}))`
	conditionText := `@Resource.Department == "Finance"`
	if invalid {
		conditionText = `@Resource.Department Matches "Finance"`
	}
	condition := conditions.Raw(conditionText)
	entry.Submitted = map[string][][]byte{
		portablePolicyLabCurrent: {[]byte(current)}, portablePolicyLabProposed: {[]byte(proposed)},
		portablePolicyLabCondition: {[]byte(conditionText)}, portablePolicyLabPrevious: entry.Before[portablePolicyLabCurrent],
	}
	result, err := client.CentralAccess.UpdateCentralAccessRule(ctx, centralaccess.UpdateCentralAccessRuleRequest{
		Identity: identity, CurrentACL: &current, ProposedACL: &proposed, ResourceCondition: &condition,
	})
	return result.Mutation, err
}
