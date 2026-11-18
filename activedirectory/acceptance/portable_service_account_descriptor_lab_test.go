package acceptance

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net"
	"os"
	"regexp"
	"runtime"
	"slices"
	"strings"
	"testing"
	"time"

	ad "github.com/deploymenttheory/go-sdk-activedirectory/activedirectory"
	adengine "github.com/deploymenttheory/go-sdk-activedirectory/activedirectory/internal/engine"
	admodel "github.com/deploymenttheory/go-sdk-activedirectory/activedirectory/internal/model"
	"github.com/deploymenttheory/go-sdk-activedirectory/conditions"
)

// The outer source/binary manifest independently proves actual build inputs.
// This linker label prevents attributing a result to another labelled binary.
var portableDescriptorLabBuildRevision string

type portableReaderLabInput struct {
	CredentialSource string `json:"credential_source"`
	Password         []byte `json:"password_base64,omitempty"`
	Endpoint         string `json:"endpoint"`
	Realm            string `json:"realm"`
	SPN              string `json:"spn"`
	Username         string `json:"username"`
	CachePath        string `json:"cache_path"`
	RunID            string `json:"run_id"`
	SourceRevision   string `json:"source_revision"`
	Result           string `json:"result"`
	FixtureOU        string `json:"fixture_ou"`
	FixtureGUID      string `json:"fixture_guid"`
	MatchingGUID     string `json:"matching_guid"`
	StaleGUID        string `json:"stale_guid"`
	ReaderDN         string `json:"reader_dn"`
	ReaderGUID       string `json:"reader_guid"`
}

func (portableReaderLabInput) String() string   { return "DescriptorLabInput{redacted}" }
func (portableReaderLabInput) GoString() string { return "DescriptorLabInput{redacted}" }
func (portableReaderLabInput) Format(state fmt.State, _ rune) {
	_, _ = io.WriteString(state, "DescriptorLabInput{redacted}")
}

func (portableReaderLabInput) MarshalJSON() ([]byte, error) { return []byte(`{"redacted":true}`), nil }

func (portableReaderLabInput) MarshalText() ([]byte, error) {
	return []byte("DescriptorLabInput{redacted}"), nil
}

type portableReaderLabCase struct {
	ID                 string                   `json:"id"`
	Interposed         bool                     `json:"private_test_wrapper"`
	State              admodel.ObjectWriteState `json:"state"`
	Verified           bool                     `json:"verified"`
	LDAPCode           uint32                   `json:"ldap_code"`
	Concurrency        bool                     `json:"concurrency_error"`
	Before             []byte                   `json:"before_base64,omitempty"`
	Proposed           []byte                   `json:"proposed_base64,omitempty"`
	ConcurrentProposed []byte                   `json:"concurrent_proposed_base64,omitempty"`
	Current            []byte                   `json:"current_base64,omitempty"`
	After              []byte                   `json:"after_base64,omitempty"`
	UnownedPreserved   bool                     `json:"unowned_components_preserved"`
	ConcurrentAccepted bool                     `json:"independent_concurrent_cas_accepted"`
	Passed             bool                     `json:"passed"`
}

type portableReaderLabReport struct {
	CredentialSource string                    `json:"credential_source,omitempty"`
	SchemaVersion    int                       `json:"schema_version"`
	RunID            string                    `json:"run_id"`
	Source           string                    `json:"source_revision"`
	Platform         string                    `json:"platform"`
	GoVersion        string                    `json:"go_version"`
	Protection       admodel.SessionProtection `json:"protection"`
	Actor            admodel.SessionProtection `json:"independent_actor_protection"`
	Cases            []*portableReaderLabCase  `json:"cases"`
	Passed           bool                      `json:"passed"`
}

func portableReadReaderLabInput(reader io.Reader) (portableReaderLabInput, error) {
	data, err := io.ReadAll(io.LimitReader(reader, 128*1024+1))
	defer clear(data)
	if err != nil || len(data) > 128*1024 || len(bytes.TrimSpace(data)) == 0 || bytes.TrimSpace(data)[0] != '{' {
		return portableReaderLabInput{}, errors.New("invalid bounded descriptor lab input")
	}
	decoder := json.NewDecoder(bytes.NewReader(data))
	decoder.DisallowUnknownFields()
	var input portableReaderLabInput
	if err := decoder.Decode(&input); err != nil {
		clear(input.Password)
		return portableReaderLabInput{}, errors.New("invalid descriptor lab input object")
	}
	if err := decoder.Decode(new(any)); !errors.Is(err, io.EOF) {
		clear(input.Password)
		return portableReaderLabInput{}, errors.New("descriptor lab input must contain one object")
	}
	return input, nil
}

// TestPortableServiceAccountDescriptorLab uses public Dial/UpdateServiceAccount.
// Only the stale case wraps the real session to insert one independent real CAS
// after the workflow snapshot and before forwarding its actual mutation. The
// outer collector provisions/delegates/reconciles every marker/GUID-owned object.
func TestPortableServiceAccountDescriptorLab(t *testing.T) {
	if os.Getenv("ADSDK_DESCRIPTOR_LAB_INPUT") == "" {
		t.Skip("requires explicit owned lab fixtures and JSON stdin")
	}
	if os.Getenv("ADSDK_DESCRIPTOR_LAB_INPUT") != "stdin" {
		t.Fatal("descriptor lab input mode must be stdin")
	}
	input, err := portableReadReaderLabInput(os.Stdin)
	if err != nil {
		t.Fatal(err)
	}
	defer clear(input.Password)
	if !regexp.MustCompile(`^[A-Za-z0-9-]{1,64}$`).MatchString(input.RunID) || portableDescriptorLabBuildRevision == "" ||
		input.SourceRevision != portableDescriptorLabBuildRevision {
		t.Fatal("invalid run ID or source label mismatch")
	}
	output, err := os.OpenFile(input.Result, os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0o600)
	if err != nil {
		t.Fatal("create fresh descriptor lab artifact:", err)
	}
	report := portableReaderLabReport{
		SchemaVersion: 1, RunID: input.RunID, Source: portableDescriptorLabBuildRevision,
		Platform: runtime.GOOS + "/" + runtime.GOARCH, GoVersion: runtime.Version(),
	}
	defer func() {
		report.Passed = !t.Failed()
		if err := json.NewEncoder(output).Encode(report); err != nil {
			t.Error("write descriptor lab artifact:", err)
		}
		if err := output.Close(); err != nil {
			t.Error("close descriptor lab artifact:", err)
		}
	}()
	config, err := portableReaderLabConfig(input)
	if err != nil {
		t.Fatal("explicit isolated-lab LDAP389 Kerberos credentials/SPN required", err)
	}
	report.CredentialSource = input.CredentialSource
	host := config.Endpoint.Host
	if !strings.HasPrefix(strings.ToLower(input.FixtureOU), "ou=sdk06-") ||
		!strings.HasSuffix(strings.ToLower(input.FixtureOU), ",dc=ad,dc=sdk,dc=test") {
		t.Fatal("descriptor fixture must be an owned SDK06 lab OU")
	}
	ctx, cancel := context.WithTimeout(t.Context(), 2*time.Minute)
	defer cancel()
	client := portableReaderLabDial(t, ctx, config, &report.Protection)
	defer func() { _ = client.Close() }()
	root, err := client.Directory.RootDSE(ctx, ad.RootDSEOptions{})
	if err != nil || root.DNSHostName == nil || !strings.EqualFold(*root.DNSHostName, host) || root.DefaultNamingContext == nil ||
		!strings.EqualFold(*root.DefaultNamingContext, "DC=ad,DC=sdk,DC=test") || root.Capabilities().RequireADDS("descriptor lab") != nil {
		t.Fatal("descriptor lab RootDSE guard failed", err)
	}
	portableReaderLabGuard(t, ctx, client, input.FixtureOU, input.FixtureGUID, "sdk06-descriptor-parent:"+input.RunID)
	reader := portableReaderLabGuard(t, ctx, client, input.ReaderDN, input.ReaderGUID, "")
	sidValue, err := reader.Values("objectSid").Single()
	if err != nil {
		t.Fatal("reader identity omitted its SID", err)
	}
	sid, err := sidValue.SID()
	if err != nil {
		t.Fatal(err)
	}
	for _, id := range []string{"matching", "stale"} {
		entry := &portableReaderLabCase{ID: id, Interposed: id == "stale"}
		report.Cases = append(report.Cases, entry)
		portableReaderLabUpdate(t, ctx, client, config, input, sid, entry, &report.Actor)
	}
}

func portableReaderLabConfig(input portableReaderLabInput) (ad.Config, error) {
	host, port, err := net.SplitHostPort(input.Endpoint)
	if err != nil || port != "389" || !strings.HasSuffix(strings.ToLower(host), ".ad.sdk.test") || input.Realm != "AD.SDK.TEST" ||
		input.SPN != "ldap/"+host || input.Username == "" {
		return ad.Config{}, ad.ErrInvalidConfig
	}
	credential := &ad.KerberosCredentials{Username: input.Username, Realm: input.Realm, SPN: input.SPN}
	switch input.CredentialSource {
	case "cache":
		if input.CachePath == "" || len(input.Password) != 0 {
			return ad.Config{}, ad.ErrInvalidConfig
		}
		credential.Source, credential.CachePath = ad.KerberosCredentialCacheFile, input.CachePath
	case "password":
		if input.CachePath != "" || len(input.Password) == 0 || len(input.Password) > 4096 {
			return ad.Config{}, ad.ErrInvalidConfig
		}
		credential.Source, credential.Password = ad.KerberosPassword, input.Password
	default:
		return ad.Config{}, ad.ErrInvalidConfig
	}
	config := ad.Config{
		Backend: ad.BackendPortable, Endpoint: ad.Endpoint{Host: host, Port: 389}, Transport: ad.TransportLDAP,
		Authentication: ad.AuthenticationKerberos, SASLProtection: ad.SASLProtectionSeal, Timeout: 20 * time.Second, Kerberos: credential,
	}
	return config, config.Validate()
}

func portableReaderLabDial(t *testing.T, ctx context.Context, config ad.Config, protection *admodel.SessionProtection) *ad.Client {
	t.Helper()
	client, err := ad.Dial(ctx, config)
	if err != nil {
		t.Fatal("explicit portable Kerberos Seal dial failed", err)
	}
	*protection, err = client.Directory.Protection(ctx)
	if err != nil || !protection.Complete || !protection.MutualAuthentication || protection.SASLProtection != ad.SASLProtectionSeal ||
		protection.SASLCipherBits < 128 || protection.SASLEncryptionType < 17 || protection.SASLEncryptionType > 20 ||
		protection.TLSVerified || protection.ChannelBindingSent || protection.ChannelBound || protection.Backend != ad.BackendPortable ||
		protection.Authentication != ad.AuthenticationKerberos {
		_ = client.Close()
		t.Fatal("actual Kerberos Seal observations were not established", err)
	}
	return client
}

func portableReaderLabGuard(t *testing.T, ctx context.Context, client *ad.Client, dn, expectedGUID, marker string) admodel.Object {
	t.Helper()
	result, err := client.Directory.Search(ctx, ad.SearchOptions{
		Base: dn, Scope: ad.ScopeBase, PageSize: 2, ResultLimit: 2,
		Properties: []string{"objectGUID", "objectSid", "objectClass", "description", "userAccountControl", "msDS-GroupMSAMembership"},
	})
	if err != nil || !result.Complete || len(result.Objects) != 1 {
		t.Fatal("owned descriptor fixture read incomplete", err)
	}
	object := result.Objects[0]
	value, err := object.Values("objectGUID").Single()
	if err != nil {
		t.Fatal("owned fixture GUID missing", err)
	}
	guid, err := value.GUID()
	if err != nil || !strings.EqualFold(guid.String(), expectedGUID) {
		t.Fatal("owned fixture GUID differs", err)
	}
	if marker != "" {
		description, err := object.Values("description").Single()
		if err != nil || string(description.Bytes()) != marker {
			t.Fatal("owned fixture marker differs", err)
		}
	}
	return object
}

func portableReaderLabUpdate(t *testing.T, ctx context.Context, client *ad.Client, config ad.Config,
	input portableReaderLabInput, readerSID admodel.SID, entry *portableReaderLabCase, actorProtection *admodel.SessionProtection,
) {
	t.Helper()
	dn, guid := "CN="+entry.ID+","+input.FixtureOU, input.MatchingGUID
	if entry.ID == "stale" {
		guid = input.StaleGUID
	}
	object := portableReaderLabGuard(t, ctx, client, dn, guid, "sdk06-descriptor-gmsa:"+input.RunID+":"+entry.ID)
	flags, err := object.Values("userAccountControl").Single()
	if err != nil {
		t.Fatal("owned gMSA disabled state missing", err)
	}
	uac, err := flags.Flags32()
	if err != nil || !uac.Has(2) {
		t.Fatal("descriptor fixture gMSA must remain disabled", err)
	}
	entry.Before = portableReaderLabDescriptor(t, object)
	session := adengine.InternalClientSession(client.Directory)
	entry.Proposed, err = admodel.InternalReplaceServiceAccountReaders(session, entry.Before, []admodel.SID{readerSID})
	if err != nil {
		t.Fatal("derive expected owned fixture reader edit", err)
	}
	entry.UnownedPreserved = portableReaderUnownedEqual(entry.Before, entry.Proposed)
	if !entry.UnownedPreserved {
		t.Fatal("proposed descriptor did not preserve unrelated storage and ACEs")
	}
	if entry.Interposed {
		actor := portableReaderLabDial(t, ctx, config, actorProtection)
		defer func() { _ = actor.Close() }()
		base, ok := session.(portableReaderEncodingSession)
		if !ok {
			t.Fatal("portable descriptor session missing")
		}
		wrapped := &portableReaderInterposedSession{portableReaderEncodingSession: base, actor: actor, targetDN: dn, expectedGUID: guid, entry: entry}
		*adengine.InternalClientSessionPointer(client.Directory) = wrapped
		defer func() { *adengine.InternalClientSessionPointer(client.Directory) = session }()
	}
	identity, err := ad.IdentityByDN(dn)
	if err != nil {
		t.Fatal(err)
	}
	readerIdentity, err := ad.IdentityByDN(input.ReaderDN)
	if err != nil {
		t.Fatal(err)
	}
	readers := []ad.Identity{readerIdentity}
	result, updateErr := client.ServiceAccounts.UpdateServiceAccount(ctx, admodel.UpdateServiceAccountRequest{Identity: identity, PasswordReaders: &readers})
	entry.State, entry.Verified = result.Mutation.State, result.Mutation.Verified
	entry.Concurrency = errors.Is(updateErr, ad.ErrObjectConcurrency)
	var response *ad.LDAPError
	if errors.As(updateErr, &response) {
		entry.LDAPCode = response.Code
	}
	if result.Mutation.Before == nil || !bytes.Equal(entry.Before, portableReaderLabDescriptor(t, *result.Mutation.Before)) {
		t.Fatal("public workflow preflight differed from the owned fixture baseline", updateErr)
	}
	if result.Mutation.After != nil {
		entry.After = portableReaderLabDescriptor(t, *result.Mutation.After)
	}
	if entry.Interposed {
		observed := portableReaderLabGuard(t, ctx, client, dn, guid, "sdk06-descriptor-gmsa:"+input.RunID+":"+entry.ID)
		entry.After = portableReaderLabDescriptor(t, observed)
		entry.Passed = entry.ConcurrentAccepted && entry.Concurrency && entry.LDAPCode == 16 && entry.State == admodel.ObjectWriteRejected &&
			bytes.Equal(entry.After, entry.Current) && !bytes.Equal(entry.Before, entry.Current)
	} else {
		entry.Passed = updateErr == nil && entry.State == admodel.ObjectWriteAccepted && entry.Verified && bytes.Equal(entry.After, entry.Proposed)
	}
	if !entry.Passed {
		t.Fatal("actual portable reader CAS outcome failed; retain artifact and reconcile independently", updateErr)
	}
}

func portableReaderLabDescriptor(t *testing.T, object admodel.Object) []byte {
	t.Helper()
	value, err := object.Values("msDS-GroupMSAMembership").Single()
	if err != nil {
		t.Fatal("owned gMSA descriptor missing", err)
	}
	return value.Bytes()
}

type portableReaderEncodingSession interface {
	admodel.InternalLdapWriteSession
	InternalEncodeDACL([]byte, [][]byte) ([]byte, error)
}

type portableReaderInterposedSession struct {
	portableReaderEncodingSession
	actor        *ad.Client
	targetDN     string
	expectedGUID string
	entry        *portableReaderLabCase
	used         bool
}

func (s *portableReaderInterposedSession) InternalLdapWrite(ctx context.Context, request admodel.InternalLdapWriteRequest) admodel.InternalLdapWriteAttempt {
	if s.used || request.InternalOperation != admodel.InternalLdapWriteModify || len(request.InternalModifications) != 2 || len(request.InternalControls) != 0 {
		return admodel.InternalLdapWriteAttempt{Err: admodel.ErrInvalidResult}
	}
	s.used = true
	guid, err := admodel.ParseGUID(s.expectedGUID)
	if err != nil || request.InternalDn != admodel.InternalObjectGUIDTarget(guid) {
		return admodel.InternalLdapWriteAttempt{Err: admodel.ErrInvalidResult}
	}
	for i, mod := range request.InternalModifications {
		want := s.entry.Before
		if i == 1 {
			want = s.entry.Proposed
		}
		if mod.InternalOperation != uint32(1-i) || !strings.EqualFold(mod.InternalAttribute, "msDS-GroupMSAMembership") ||
			len(mod.InternalValues) != 1 || !bytes.Equal(mod.InternalValues[0], want) {
			return admodel.InternalLdapWriteAttempt{Err: admodel.ErrInvalidResult}
		}
	}
	descriptor, err := conditions.ParseDescriptor(s.entry.Before)
	if err != nil {
		return admodel.InternalLdapWriteAttempt{Err: err}
	}
	concurrent, err := conditions.ParseSDDL("D:(A;;WP;;;BU)")
	if err != nil {
		return admodel.InternalLdapWriteAttempt{Err: err}
	}
	acl := descriptor.DACL()
	acl.ACEs = append(acl.ACEs, concurrent.DACL().ACEs...)
	descriptor, err = descriptor.WithDACL(acl)
	if err != nil {
		return admodel.InternalLdapWriteAttempt{Err: err}
	}
	s.entry.ConcurrentProposed, err = descriptor.MarshalBinary()
	if err != nil {
		return admodel.InternalLdapWriteAttempt{Err: err}
	}
	actorSession := adengine.InternalClientSession(s.actor.Directory).(admodel.InternalLdapWriteSession)
	attempt := actorSession.InternalLdapWrite(ctx, admodel.InternalLdapWriteRequest{
		InternalOperation: admodel.InternalLdapWriteModify, InternalDn: request.InternalDn,
		InternalModifications: admodel.InternalAccountConditionalValue("msDS-GroupMSAMembership", s.entry.Before, s.entry.ConcurrentProposed),
	})
	s.entry.ConcurrentAccepted = attempt.State == admodel.InternalLdapWriteAccepted && attempt.Err == nil
	if !s.entry.ConcurrentAccepted {
		return admodel.InternalLdapWriteAttempt{Err: errors.Join(admodel.ErrInvalidResult, attempt.Err)}
	}
	observed, err := s.actor.Directory.Search(ctx, ad.SearchOptions{
		Base: s.targetDN, Scope: ad.ScopeBase,
		Properties: []string{"objectGUID", "msDS-GroupMSAMembership"}, PageSize: 2, ResultLimit: 2,
	})
	if err != nil || !observed.Complete || len(observed.Objects) != 1 {
		return admodel.InternalLdapWriteAttempt{Err: errors.Join(admodel.ErrInvalidResult, err)}
	}
	value, err := observed.Objects[0].Values("objectGUID").Single()
	if err != nil {
		return admodel.InternalLdapWriteAttempt{Err: err}
	}
	observedGUID, err := value.GUID()
	if err != nil || observedGUID != guid {
		return admodel.InternalLdapWriteAttempt{Err: admodel.ErrInvalidResult}
	}
	value, err = observed.Objects[0].Values("msDS-GroupMSAMembership").Single()
	if err != nil {
		return admodel.InternalLdapWriteAttempt{Err: err}
	}
	s.entry.Current = value.Bytes()
	if !bytes.Equal(s.entry.Current, s.entry.ConcurrentProposed) {
		return admodel.InternalLdapWriteAttempt{Err: admodel.ErrObjectReadback}
	}
	// Forward the exact original public-workflow request; no response, status,
	// descriptor snapshot or subsequent retry is manufactured by this wrapper.
	return s.portableReaderEncodingSession.InternalLdapWrite(ctx, request)
}

func portableReaderUnownedEqual(before, after []byte) bool {
	original, err := conditions.ParseDescriptor(before)
	if err != nil {
		return false
	}
	edited, err := conditions.ParseDescriptor(after)
	if err != nil || len(after) < len(before) || !bytes.Equal(before[:16], after[:16]) || !bytes.Equal(before[20:], after[20:len(before)]) {
		return false
	}
	oldACL, newACL := original.DACL(), edited.DACL()
	return oldACL.Present == newACL.Present && oldACL.Null == newACL.Null && oldACL.Revision == newACL.Revision &&
		slices.EqualFunc(portableReaderUnownedACEs(oldACL.ACEs), portableReaderUnownedACEs(newACL.ACEs), bytes.Equal)
}

func portableReaderUnownedACEs(aces [][]byte) [][]byte {
	var retained [][]byte
	for _, ace := range aces {
		// Only ordinary explicit Read Property allow bits are owned by this API.
		if len(ace) >= 8 && ace[0] == 0 && ace[1] == 0 && ace[4]&0x10 != 0 {
			ace = bytes.Clone(ace)
			ace[4] &^= 0x10
			if bytes.Equal(ace[4:8], []byte{0, 0, 0, 0}) {
				continue
			}
		}
		retained = append(retained, ace)
	}
	return retained
}

func TestPortableDescriptorLabInputAndPreservationGuards(t *testing.T) {
	for _, input := range []string{"null", "{} {}", `{"unknown":"private-value"}`, strings.Repeat("x", 128*1024+1)} {
		_, err := portableReadReaderLabInput(strings.NewReader(input))
		if err == nil || strings.Contains(err.Error(), "private-value") {
			t.Fatal("invalid descriptor lab input succeeded or leaked input")
		}
	}
	fixture := newPortableReaderDescriptorFixture(t)
	if !portableReaderUnownedEqual(fixture.before, fixture.after) {
		t.Fatal("valid reader edit failed unrelated-component preservation check")
	}
	changed := bytes.Clone(fixture.after)
	changed[2] ^= 0x10
	if portableReaderUnownedEqual(fixture.before, changed) {
		t.Fatal("changed descriptor control was not detected")
	}
	descriptor, err := conditions.ParseDescriptor(fixture.after)
	if err != nil {
		t.Fatal(err)
	}
	acl := descriptor.DACL()
	acl.ACEs[0], acl.ACEs[1] = acl.ACEs[1], acl.ACEs[0]
	descriptor, err = descriptor.WithDACL(acl)
	if err != nil {
		t.Fatal(err)
	}
	reordered, err := descriptor.MarshalBinary()
	if err != nil || portableReaderUnownedEqual(fixture.before, reordered) {
		t.Fatal("changed unrelated ACE order was not detected", err)
	}
}

func TestPortableDescriptorLabCredentialSourcesAreExplicitAndRedacted(t *testing.T) {
	input := portableReaderLabInput{
		Endpoint: "adsdk25dc1.ad.sdk.test:389", Realm: "AD.SDK.TEST", SPN: "ldap/adsdk25dc1.ad.sdk.test",
		Username: "owned-actor", CredentialSource: "password", Password: []byte("sensitive-descriptor-lab-password"),
	}
	defer clear(input.Password)
	decoded, err := portableReadReaderLabInput(strings.NewReader(`{"credential_source":"password","password_base64":"Zml4dHVyZS1vbmx5"}`))
	if err != nil || decoded.CredentialSource != "password" || !bytes.Equal(decoded.Password, []byte("fixture-only")) {
		t.Fatal("explicit password stdin payload was not decoded", err)
	}
	clear(decoded.Password)
	config, err := portableReaderLabConfig(input)
	if err != nil || config.Kerberos.Source != ad.KerberosPassword || config.Authentication != ad.AuthenticationKerberos ||
		config.SASLProtection != ad.SASLProtectionSeal || config.Backend != ad.BackendPortable {
		t.Fatal("explicit password source did not retain public portable Kerberos Seal", err)
	}
	for _, format := range []string{"%v", "%+v", "%#v", "%d", "%x", "%s", "%q"} {
		if text := fmt.Sprintf(format, map[string]any{"nested": input}); strings.Contains(text, "sensitive") {
			t.Fatal("descriptor lab input leaked through formatting")
		}
	}
	encoded, err := json.Marshal(struct{ Input portableReaderLabInput }{input})
	if err != nil || bytes.Contains(encoded, []byte("password")) || !bytes.Contains(encoded, []byte(`"redacted":true`)) {
		t.Fatal("descriptor lab input JSON did not redact credentials", err)
	}
	input.Password = nil
	for _, source := range []string{"", "ambient", "cache", "password"} {
		input.CredentialSource = source
		if _, err := portableReaderLabConfig(input); !errors.Is(err, ad.ErrInvalidConfig) {
			t.Fatal("missing or unrecognized explicit credentials were accepted")
		}
	}
	input.CredentialSource, input.CachePath = "cache", "owned-explicit.ccache"
	config, err = portableReaderLabConfig(input)
	if err != nil || config.Kerberos.Source != ad.KerberosCredentialCacheFile {
		t.Fatal("explicit cache source failed", err)
	}
	input.Password = []byte("must-not-fallback")
	defer clear(input.Password)
	for _, source := range []string{"cache", "password"} {
		input.CredentialSource = source
		if _, err := portableReaderLabConfig(input); !errors.Is(err, ad.ErrInvalidConfig) {
			t.Fatal("conflicting password/cache sources were accepted")
		}
	}
	input.CachePath, input.CredentialSource = "", "password"
	input.Password = bytes.Repeat([]byte{'x'}, 4097)
	defer clear(input.Password)
	if _, err := portableReaderLabConfig(input); !errors.Is(err, ad.ErrInvalidConfig) {
		t.Fatal("oversized password input was accepted")
	}
}
