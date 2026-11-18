package acceptance

import (
	"bytes"
	"context"
	"crypto/x509"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net"
	"os"
	"regexp"
	"runtime"
	"slices"
	"strconv"
	"strings"
	"testing"
	"time"

	ldap "github.com/deploymenttheory/go-sdk-activedirectory/3rd_party/ldap/v3"
	adengine "github.com/deploymenttheory/go-sdk-activedirectory/activedirectory/internal/engine"
	admodel "github.com/deploymenttheory/go-sdk-activedirectory/activedirectory/internal/model"
)

type portableLabEvidence struct {
	RangeDescriptions   []string                  `json:"range_descriptions"`
	RangeValueCount     int                       `json:"range_value_count"`
	RunID               string                    `json:"run_id"`
	Revision            string                    `json:"source_revision"`
	Platform            string                    `json:"platform"`
	GoVersion           string                    `json:"go_version"`
	Endpoint            string                    `json:"endpoint"`
	Server              string                    `json:"server"`
	FixtureDN           string                    `json:"fixture_dn,omitempty"`
	FixtureGUID         string                    `json:"fixture_guid_hex,omitempty"`
	AssertionAdvertised bool                      `json:"assertion_advertised"`
	Protection          admodel.SessionProtection `json:"protection"`
	Steps               []string                  `json:"passed_steps"`
	Passed              bool                      `json:"passed"`
}

type portableLabRequest struct {
	Endpoint       string `json:"endpoint"`
	Transport      string `json:"transport"`
	CAFile         string `json:"ca_file"`
	Username       string `json:"username"`
	Password       []byte `json:"password_base64"`
	RunID          string `json:"run_id"`
	SourceRevision string `json:"source_revision"`
	Result         string `json:"result"`
	AllowWrite     bool   `json:"allow_write"`
	FixtureOU      string `json:"fixture_ou"`
}

func portableLabStdinRequest(t *testing.T) *portableLabRequest {
	t.Helper()
	mode := os.Getenv("ADSDK_PORTABLE_LAB_INPUT")
	if mode == "" {
		return nil
	}
	if mode != "stdin" {
		t.Fatal("ADSDK_PORTABLE_LAB_INPUT must be empty or stdin")
	}
	input := &io.LimitedReader{R: os.Stdin, N: 128*1024 + 1}
	decoder := json.NewDecoder(input)
	decoder.DisallowUnknownFields()
	var request portableLabRequest
	if err := decoder.Decode(&request); err != nil {
		clear(request.Password)
		t.Fatal("invalid portable lab JSON stdin request")
	}
	var extra any
	if err := decoder.Decode(&extra); !errors.Is(err, io.EOF) || input.N <= 0 {
		clear(request.Password)
		t.Fatal("portable lab stdin request must contain one JSON object within 128 KiB")
	}
	return &request
}

// TestPortableLDAPLab is an opt-in actual-client test. The collector must provide
// a fresh output path and independently verify any owned fixture after the run.
// This test never retries a write or rolls one back after an uncertain response.
func TestPortableLDAPLab(t *testing.T) {
	request := portableLabStdinRequest(t)
	input := func(name string) string { return os.Getenv("ADSDK_PORTABLE_LAB_" + name) }
	if request != nil {
		defer clear(request.Password)
		settings := map[string]string{
			"ENDPOINT": request.Endpoint, "TRANSPORT": request.Transport, "CA_FILE": request.CAFile, "USERNAME": request.Username,
			"RUN_ID": request.RunID, "SOURCE_REVISION": request.SourceRevision, "RESULT": request.Result, "FIXTURE_OU": request.FixtureOU,
		}
		if request.AllowWrite {
			settings["ALLOW_WRITE"] = "1"
		}
		input = func(name string) string { return settings[name] }
	}
	endpoint := input("ENDPOINT")
	if endpoint == "" {
		if request != nil {
			t.Fatal("portable lab stdin request requires an endpoint")
		}
		t.Skip("requires explicit ADSDK_PORTABLE_LAB_ENDPOINT and lab collector inputs")
	}
	required := func(name string) string {
		t.Helper()
		value := input(name)
		if value == "" {
			t.Fatalf("missing ADSDK_PORTABLE_LAB_%s", name)
		}
		return value
	}
	evidence := portableLabEvidence{
		RunID: required("RUN_ID"), Revision: required("SOURCE_REVISION"), Endpoint: endpoint,
		Platform: runtime.GOOS + "/" + runtime.GOARCH, GoVersion: runtime.Version(),
	}
	if !regexp.MustCompile(`^[A-Za-z0-9-]{1,48}$`).MatchString(evidence.RunID) {
		t.Fatal("run identifier must contain 1-48 ASCII letters, digits or hyphens")
	}
	output, err := os.OpenFile(required("RESULT"), os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0o600)
	if err != nil {
		t.Fatal("create fresh portable lab result:", err)
	}
	defer func() {
		evidence.Passed = !t.Failed()
		if err := json.NewEncoder(output).Encode(evidence); err != nil {
			t.Error("write portable lab result:", err)
		}
		if err := output.Close(); err != nil {
			t.Error("close portable lab result:", err)
		}
	}()
	host, portText, err := net.SplitHostPort(endpoint)
	if err != nil {
		t.Fatal("endpoint must explicitly name host:port:", err)
	}
	port, err := strconv.ParseUint(portText, 10, 16)
	if err != nil || port == 0 {
		t.Fatal("endpoint port is invalid")
	}
	transport := admodel.TransportLDAPS
	switch required("TRANSPORT") {
	case "ldaps":
	case "starttls":
		transport = admodel.TransportStartTLS
	default:
		t.Fatal("transport must be ldaps or starttls")
	}
	pem, err := os.ReadFile(required("CA_FILE"))
	if err != nil {
		t.Fatal("read explicit lab CA:", err)
	}
	roots := x509.NewCertPool()
	if !roots.AppendCertsFromPEM(pem) {
		t.Fatal("explicit lab CA contains no certificate")
	}
	var password []byte
	if request != nil {
		password = request.Password
		if len(password) == 0 {
			t.Fatal("portable lab stdin request requires nonempty password_base64")
		}
	} else {
		password = []byte(required("PASSWORD"))
	}
	defer clear(password)
	config := admodel.Config{
		Backend: admodel.BackendPortable, Endpoint: admodel.Endpoint{Host: host, Port: uint16(port)},
		Transport: transport, Authentication: admodel.AuthenticationSimple,
		TLS: &admodel.TLSOptions{RootCAs: roots}, Timeout: 20 * time.Second,
		Credentials: &admodel.Credentials{Username: required("USERNAME"), Password: password},
	}
	ctx, cancel := context.WithTimeout(t.Context(), 2*time.Minute)
	defer cancel()
	client, err := adengine.Dial(ctx, config)
	clear(password)
	config.Credentials = nil
	if err != nil {
		t.Fatal("portable verified-TLS simple dial:", err)
	}
	defer func() {
		if err := client.Close(); err != nil {
			t.Error("close portable lab client:", err)
		}
	}()
	evidence.Protection, err = client.Protection(ctx)
	if err != nil || !evidence.Protection.Complete || !evidence.Protection.TLSVerified ||
		evidence.Protection.Backend != admodel.BackendPortable || evidence.Protection.Authentication != admodel.AuthenticationSimple ||
		evidence.Protection.ChannelBound || evidence.Protection.MutualAuthentication || evidence.Protection.Delegated {
		t.Fatalf("inaccurate actual-session protection: %+v %v", evidence.Protection, err)
	}
	evidence.Steps = append(evidence.Steps, "portable-verified-tls-simple-session")
	root, err := client.RootDSE(ctx, admodel.RootDSEOptions{})
	if err != nil || root.DefaultNamingContext == nil || !strings.EqualFold(*root.DefaultNamingContext, "DC=ad,DC=sdk,DC=test") ||
		root.DNSHostName == nil || root.Capabilities().RequireADDS("portable owned lab") != nil {
		t.Fatalf("actual RootDSE did not identify the isolated AD SDK lab: %v", err)
	}
	evidence.Server = *root.DNSHostName
	evidence.Steps = append(evidence.Steps, "actual-rootdse-isolated-adds-lab")
	result, err := client.Search(ctx, admodel.SearchOptions{
		Base: "CN=Users," + *root.DefaultNamingContext, Scope: admodel.ScopeOneLevel, Filter: "(objectClass=group)",
		Properties: []string{"objectGUID"}, PageSize: 1, ResultLimit: 2,
	})
	if err != nil || len(result.Objects) != 2 || !result.LimitReached {
		t.Fatalf("actual bounded multi-page group read: count=%d limit=%v error=%v", len(result.Objects), result.LimitReached, err)
	}
	for _, object := range result.Objects {
		if len(object.Attributes["objectguid"]) != 1 || len(object.Attributes["objectguid"][0]) != 16 {
			t.Fatal("actual LDAP GUID bytes were not retained")
		}
	}
	evidence.Steps = append(evidence.Steps, "paged-binary-guid-limit-cookie-release")
	portableLabRangedRead(t, ctx, client, root, &evidence)
	if input("ALLOW_WRITE") != "1" {
		return
	}
	fixtureOU := required("FIXTURE_OU")
	if !strings.HasPrefix(strings.ToLower(fixtureOU), "ou=sdk-portable-") ||
		!strings.HasSuffix(strings.ToLower(fixtureOU), ",dc=ad,dc=sdk,dc=test") {
		t.Fatal("write fixture must be an independently provisioned OU=sdk-portable-* in the isolated lab")
	}
	parent := portableLabReadOne(t, ctx, client, fixtureOU)
	if len(parent.Attributes["description"]) != 1 || string(parent.Attributes["description"][0]) != "sdk-portable-parent:"+evidence.RunID {
		t.Fatal("write fixture OU does not carry the independently provisioned run ownership marker")
	}
	portableLabLifecycle(t, ctx, client, root, fixtureOU, &evidence)
}

func portableLabLifecycle(t *testing.T, ctx context.Context, client *adengine.Client, root admodel.RootDSE, fixtureOU string, evidence *portableLabEvidence) {
	t.Helper()
	for _, oid := range []string{"1.2.840.113556.1.4.1413", "1.2.840.113556.1.4.417"} {
		if !slices.Contains(root.SupportedControls, oid) {
			t.Fatalf("lab does not advertise required critical control %s; no fixture write submitted", oid)
		}
	}
	session := adengine.InternalClientSession(client).(admodel.InternalLdapWriteSession)
	name := "sdk-portable-" + evidence.RunID
	evidence.FixtureDN = "CN=" + name + "," + fixtureOU
	marker := []byte("sdk-portable-owned:" + evidence.RunID)
	photo := []byte{0, 0xff, 0x80, 0x41, 0, 0x42}
	mod := func(operation uint32, attribute string, values ...[]byte) admodel.InternalLdapAttributeModification {
		return admodel.InternalLdapAttributeModification{InternalOperation: operation, InternalAttribute: attribute, InternalValues: values}
	}
	write := func(request admodel.InternalLdapWriteRequest) {
		t.Helper()
		attempt := session.InternalLdapWrite(ctx, request)
		if attempt.State != admodel.InternalLdapWriteAccepted || attempt.Err != nil {
			t.Fatalf("single-attempt fixture write outcome=%d: %v; reconcile recorded owned DN independently", attempt.State, attempt.Err)
		}
	}
	write(admodel.InternalLdapWriteRequest{
		InternalOperation: admodel.InternalLdapWriteAdd, InternalDn: evidence.FixtureDN,
		InternalModifications: []admodel.InternalLdapAttributeModification{
			mod(0, "objectClass", []byte("top"), []byte("person"), []byte("organizationalPerson"), []byte("contact")),
			mod(0, "cn", []byte(name)), mod(0, "sn", []byte(name)), mod(0, "description", marker), mod(0, "thumbnailPhoto", photo),
		},
	})
	object := portableLabReadOne(t, ctx, client, evidence.FixtureDN)
	guid := object.Attributes["objectguid"]
	if len(guid) != 1 || len(guid[0]) != 16 || len(object.Attributes["thumbnailphoto"]) != 1 || !bytes.Equal(object.Attributes["thumbnailphoto"][0], photo) {
		t.Fatal("owned fixture binary photo/GUID readback differs; reconcile recorded DN independently")
	}
	evidence.FixtureGUID = hex.EncodeToString(guid[0])
	evidence.Steps = append(evidence.Steps, "add-contact-binary-photo-readback")
	assertion, err := ldap.CompileFilter("(description=" + ldap.EscapeFilter(string(marker)) + ")")
	if err != nil {
		t.Fatal(err)
	}
	assertionControl := admodel.InternalLdapWriteControl{InternalOid: "1.3.6.1.1.12", InternalCritical: true, InternalValue: assertion.Bytes()}
	evidence.AssertionAdvertised = slices.Contains(root.SupportedControls, assertionControl.InternalOid)
	if !evidence.AssertionAdvertised {
		// This is a distinct negative probe, not a fallback mutation. Its
		// requested description change is never retried without the assertion.
		attempt := session.InternalLdapWrite(ctx, admodel.InternalLdapWriteRequest{
			InternalOperation: admodel.InternalLdapWriteModify, InternalDn: evidence.FixtureDN,
			InternalModifications: []admodel.InternalLdapAttributeModification{mod(2, "description", []byte(string(marker)+":assertion-probe"))},
			InternalControls:      []admodel.InternalLdapWriteControl{assertionControl},
		})
		var refusal *admodel.LDAPError
		if attempt.State != admodel.InternalLdapWriteRejected || !errors.As(attempt.Err, &refusal) || refusal.Code != 12 {
			t.Fatalf("unadvertised critical assertion did not produce an actual rejected LDAP12 result: state=%d error=%v", attempt.State, attempt.Err)
		}
		unchanged := portableLabReadOne(t, ctx, client, evidence.FixtureDN)
		if len(unchanged.Attributes["description"]) != 1 || !bytes.Equal(unchanged.Attributes["description"][0], marker) {
			t.Fatal("rejected critical assertion changed the owned description")
		}
		evidence.Steps = append(evidence.Steps, "critical-assertion-unadvertised-refused-12-unchanged")
	}
	controls := []admodel.InternalLdapWriteControl{{InternalOid: "1.2.840.113556.1.4.1413", InternalCritical: true}}
	if evidence.AssertionAdvertised {
		controls = append([]admodel.InternalLdapWriteControl{assertionControl}, controls...)
	}
	write(admodel.InternalLdapWriteRequest{
		InternalOperation: admodel.InternalLdapWriteModify, InternalDn: evidence.FixtureDN,
		InternalModifications: []admodel.InternalLdapAttributeModification{mod(0, "description", marker)},
		InternalControls:      controls,
	})
	if evidence.AssertionAdvertised {
		evidence.Steps = append(evidence.Steps, "critical-advertised-assertion-and-permissive-modify")
	} else {
		evidence.Steps = append(evidence.Steps, "independent-critical-permissive-duplicate-add")
	}
	newRDN := "CN=" + name + "-renamed"
	write(admodel.InternalLdapWriteRequest{
		InternalOperation: admodel.InternalLdapWriteRename, InternalDn: evidence.FixtureDN,
		InternalNewRDN: newRDN, InternalDeleteOldRDN: true,
	})
	evidence.FixtureDN = newRDN + "," + fixtureOU
	renamed := portableLabReadOne(t, ctx, client, evidence.FixtureDN)
	if len(renamed.Attributes["objectguid"]) != 1 || !bytes.Equal(renamed.Attributes["objectguid"][0], guid[0]) {
		t.Fatal("rename changed owned object identity")
	}
	evidence.Steps = append(evidence.Steps, "modifydn-preserves-binary-guid")
	write(admodel.InternalLdapWriteRequest{InternalOperation: admodel.InternalLdapWriteDelete, InternalDn: evidence.FixtureDN})
	_, err = client.Search(ctx, admodel.SearchOptions{Base: evidence.FixtureDN, Scope: admodel.ScopeBase})
	var absent *admodel.LDAPError
	if !errors.As(err, &absent) || absent.Code != 32 {
		t.Fatalf("normal deleted-object read did not return LDAP noSuchObject: %v", err)
	}
	evidence.Steps = append(evidence.Steps, "delete-and-normal-no-such-object")
	filter, err := admodel.FilterEqual("objectGUID", admodel.FilterBytes(guid[0])).LDAP()
	if err != nil {
		t.Fatal(err)
	}
	options := admodel.SearchOptions{
		Base: "CN=Deleted Objects," + *root.DefaultNamingContext, Scope: admodel.ScopeOneLevel, Filter: filter,
		Properties: []string{"objectGUID", "isDeleted"}, PageSize: 1,
	}
	controlled := session.(admodel.InternalLdapControlledSearchSession)
	cursor, err := controlled.InternalStartSearchControls(ctx, options,
		[]admodel.InternalLdapWriteControl{{InternalOid: "1.2.840.113556.1.4.417", InternalCritical: true}})
	if err != nil {
		t.Fatal("start critical show-deleted read:", err)
	}
	deleted, err := admodel.InternalCollectSearch(ctx, cursor, options)
	if err != nil || !deleted.Complete || len(deleted.Objects) != 1 ||
		len(deleted.Objects[0].Attributes["isdeleted"]) != 1 || string(deleted.Objects[0].Attributes["isdeleted"][0]) != "TRUE" {
		t.Fatalf("critical show-deleted GUID read: objects=%d complete=%v error=%v", len(deleted.Objects), deleted.Complete, err)
	}
	if len(deleted.Objects[0].Attributes["objectguid"]) != 1 || !bytes.Equal(deleted.Objects[0].Attributes["objectguid"][0], guid[0]) {
		t.Fatal("deleted-object read changed the owned binary GUID")
	}
	evidence.Steps = append(evidence.Steps, "critical-show-deleted-binary-guid-tombstone")
}

func portableLabReadOne(t *testing.T, ctx context.Context, client *adengine.Client, dn string) admodel.Object {
	t.Helper()
	result, err := client.Search(ctx, admodel.SearchOptions{Base: dn, Scope: admodel.ScopeBase, Properties: []string{"objectGUID", "thumbnailPhoto", "description"}})
	if err != nil || !result.Complete || len(result.Objects) != 1 {
		t.Fatal(fmt.Sprintf("owned fixture read count=%d complete=%v error=%v", len(result.Objects), result.Complete, err))
	}
	return result.Objects[0]
}

// Verify real AD range descriptions without changing SPNs or creating a large fixture.
func portableLabRangedRead(t *testing.T, ctx context.Context, client *adengine.Client, root admodel.RootDSE, evidence *portableLabEvidence) {
	t.Helper()
	result, err := client.Search(ctx, admodel.SearchOptions{
		Base: "OU=Domain Controllers," + *root.DefaultNamingContext, Scope: admodel.ScopeOneLevel,
		Filter: "(&(objectClass=computer)(dNSHostName=" + ldap.EscapeFilter(*root.DNSHostName) + "))", Properties: []string{"distinguishedName"}, PageSize: 2, ResultLimit: 2,
	})
	if err != nil || len(result.Objects) != 1 {
		t.Fatal("could not identify exactly one actual DC computer for ranged read")
	}
	dn := result.Objects[0].DistinguishedName
	session := adengine.InternalClientSession(client)
	normal, err := session.InternalBaseObject(ctx, dn, []string{"servicePrincipalName"})
	if err != nil || len(normal["serviceprincipalname"]) < 2 {
		t.Fatal("actual DC must expose at least two SPNs for ranged read")
	}
	reader, ok := session.(interface {
		InternalRangedBaseObject(context.Context, string, []string) (map[string][][]byte, error)
	})
	if !ok {
		t.Fatal("portable session does not expose ranged base reads")
	}
	first, err := reader.InternalRangedBaseObject(ctx, dn, []string{"servicePrincipalName;range=0-0"})
	if err != nil || len(first["serviceprincipalname;range=0-0"]) != 1 {
		t.Fatal("actual DC did not return the requested nonterminal 0-0 range description")
	}
	retained := append([]byte(nil), first["serviceprincipalname;range=0-0"][0]...)
	second, err := reader.InternalRangedBaseObject(ctx, dn, []string{"servicePrincipalName;range=1-*"})
	if err != nil || len(second["serviceprincipalname;range=1-*"]) != len(normal["serviceprincipalname"])-1 {
		t.Fatal("actual DC did not return the terminal 1-* range description")
	}
	if !bytes.Equal(retained, first["serviceprincipalname;range=0-0"][0]) {
		t.Fatal("continuation overwrote retained prior range bytes")
	}
	full := make([]string, 0, len(normal["serviceprincipalname"]))
	for _, value := range normal["serviceprincipalname"] {
		full = append(full, string(value))
	}
	combined := []string{string(retained)}
	for _, value := range second["serviceprincipalname;range=1-*"] {
		combined = append(combined, string(value))
	}
	slices.Sort(full)
	slices.Sort(combined)
	if !slices.Equal(full, combined) {
		t.Fatal("combined actual range bytes differ from the ordinary bounded DC SPN read")
	}
	evidence.RangeDescriptions = []string{"servicePrincipalName;range=0-0", "servicePrincipalName;range=1-*"}
	evidence.RangeValueCount = len(combined)
	evidence.Steps = append(evidence.Steps, "actual-dc-spn-ranged-description-continuation-terminal-and-owned-bytes")
}
