package activedirectory

import (
	"context"
	"encoding/base64"
	"encoding/hex"
	"fmt"
	"slices"
	"strconv"
	"strings"
	"testing"
	"time"
)

func TestDirectoryReferenceFactsKeepOnlyAllowlistedValues(t *testing.T) {
	fixture := newTopologyFixture()
	client := fixture.client(time.Second)
	defer client.Close()
	domain, err := client.Directory().Domain(context.Background(), DomainOptions{})
	if err != nil {
		t.Fatal(err)
	}
	forest, err := client.Directory().Forest(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	controller, err := client.Directory().DomainController(context.Background(), DomainControllerOptions{})
	if err != nil {
		t.Fatal(err)
	}
	trust, err := client.Directory().Trust(context.Background(), topTrust, TrustOptions{})
	if err != nil {
		t.Fatal(err)
	}
	trust.Trust.Raw.Attributes["trustauthincoming"] = [][]byte{[]byte("synthetic-secret")}
	facts := directoryFacts{}
	domainReferenceFacts(facts, domain)
	forestReferenceFacts(facts, forest)
	controllerReferenceFacts(facts, controller.Controller)
	trustReferenceFacts(facts, trust.Trust)
	for key, want := range map[string][]string{"domain/level": {"7"}, "forest/level": {"10"}, "domain/read_only": {"dc2.example.test"}, "dc:" + strings.ToLower(topServer) + "/roles_known": {"true"}, "trust:" + strings.ToLower(topTrust) + "/attributes.schema": {"2147483656"}} {
		if !slices.Equal(facts[key], want) {
			t.Fatalf("fact %s: %v", key, facts[key])
		}
	}
	for key, values := range facts {
		if strings.Contains(key, "trustauth") || slices.Contains(values, "synthetic-secret") {
			t.Fatal("raw secret entered the evidence allowlist")
		}
	}
}

// This allowlist is shared by the opt-in lab comparison and portable harness
// tests. No raw Object/RootDSE map or arbitrary selected property is serialized.
type directoryFacts map[string][]string

type directoryReference struct {
	SchemaVersion      int                          `json:"schema_version"`
	FixtureID          string                       `json:"fixture_id"`
	Profile            string                       `json:"profile"`
	Server             string                       `json:"server"`
	SDKRevision        string                       `json:"sdk_revision"`
	ServerVersionLabel string                       `json:"server_version_label"`
	Facts              directoryFacts               `json:"facts"`
	TrustVerification  []directoryTrustVerification `json:"trust_verification"`
}

type directoryTrustVerification struct {
	Partner        string `json:"partner"`
	TrustingDomain string `json:"trusting_domain"`
	TrustedDomain  string `json:"trusted_domain"`
	Method         string `json:"method"`
	ExitCode       *int   `json:"exit_code"`
}

func putFact(f directoryFacts, key string, values ...string) {
	key = strings.ToLower(key)
	values = slices.Clone(values)
	if !strings.HasSuffix(key, ".binary") {
		for i := range values {
			values[i] = strings.ToLower(values[i])
		}
	}
	slices.Sort(values)
	if values == nil {
		values = []string{}
	}
	f[key] = values
}

func scalarFact[T any](f directoryFacts, key string, value *T) {
	if value == nil {
		putFact(f, key)
		return
	}
	putFact(f, key, fmt.Sprint(*value))
}

func binaryFact(f directoryFacts, key string, value []byte) {
	if value == nil {
		putFact(f, key)
		return
	}
	putFact(f, key, base64.StdEncoding.EncodeToString(value))
}

func ownerFact(f directoryFacts, key string, owner *RoleOwner) {
	if owner == nil {
		putFact(f, key)
		return
	}
	scalarFact(f, key, owner.HostName)
}

func domainReferenceFacts(f directoryFacts, d Domain) {
	putFact(f, "domain/dn", d.Raw.DistinguishedName)
	binaryFact(f, "domain/guid.binary", d.ObjectGUID)
	binaryFact(f, "domain/sid.binary", d.ObjectSID)
	scalarFact(f, "domain/name", d.Name)
	scalarFact(f, "domain/dns_root", d.DNSRoot)
	scalarFact(f, "domain/netbios", d.NetBIOSName)
	scalarFact(f, "domain/forest", d.ForestDNSRoot)
	scalarFact(f, "domain/level", d.FunctionalLevel)
	scalarFact(f, "domain/managed_by", d.ManagedBy)
	putFact(f, "domain/allowed_suffixes", d.AllowedDNSSuffixes...)
	putFact(f, "domain/subrefs", d.SubordinateReferences...)
	ownerFact(f, "domain/pdc", d.PDCEmulator)
	ownerFact(f, "domain/rid", d.RIDMaster)
	ownerFact(f, "domain/infrastructure", d.InfrastructureMaster)
	var parent *string
	if d.Parent != nil {
		parent = d.Parent.DNSRoot
	}
	scalarFact(f, "domain/parent", parent)
	var children, writable, readOnly []string
	for _, child := range d.Children {
		if child.DNSRoot != nil {
			children = append(children, *child.DNSRoot)
		}
	}
	for _, replica := range d.Replicas {
		if replica.HostName == nil || replica.IsReadOnly == nil {
			continue
		}
		if *replica.IsReadOnly {
			readOnly = append(readOnly, *replica.HostName)
		} else {
			writable = append(writable, *replica.HostName)
		}
	}
	putFact(f, "domain/children", children...)
	putFact(f, "domain/writable", writable...)
	putFact(f, "domain/read_only", readOnly...)
	for _, id := range []string{"AA312825768811D1ADED00C04FD8D5CD", "A9D1CA15768811D1ADED00C04FD8D5CD", "A361B2FFFFD211D1AA4B00C04FD7D83A", "18E2EA80684F11D2B9AA00C04F79F805", "22B70C67D56E4EFB91E9300FCA3DC1AA", "AB8153B7768811D1ADED00C04FD8D5CD", "6227F0AF1FC2410D8E3BB10615BB5B0F", wellKnownSystem} {
		if dn := d.WellKnownContainers[id]; dn != "" {
			putFact(f, "domain/container/"+id, dn)
		} else {
			putFact(f, "domain/container/"+id)
		}
	}
}

func forestReferenceFacts(f directoryFacts, v Forest) {
	scalarFact(f, "forest/name", v.Name)
	scalarFact(f, "forest/level", v.FunctionalLevel)
	putFact(f, "forest/upn_suffixes", v.UPNSuffixes...)
	putFact(f, "forest/spn_suffixes", v.SPNSuffixes...)
	ownerFact(f, "forest/schema", v.SchemaMaster)
	ownerFact(f, "forest/naming", v.DomainNamingMaster)
	var domains, apps, external, sites, gcs []string
	for _, ref := range v.Domains {
		if ref.DNSRoot != nil {
			domains = append(domains, *ref.DNSRoot)
		}
	}
	for _, ref := range v.ApplicationPartitions {
		if ref.NamingContext != nil {
			apps = append(apps, *ref.NamingContext)
		}
	}
	for _, ref := range v.ExternalReferences {
		external = append(external, ref.Raw.DistinguishedName)
	}
	for _, site := range v.Sites {
		if site.Name != nil {
			sites = append(sites, *site.Name)
		}
	}
	for _, gc := range v.GlobalCatalogs {
		if gc.HostName != nil {
			gcs = append(gcs, *gc.HostName)
		}
	}
	putFact(f, "forest/domains", domains...)
	putFact(f, "forest/applications", apps...)
	putFact(f, "forest/external", external...)
	putFact(f, "forest/sites", sites...)
	putFact(f, "forest/gcs", gcs...)
}

func controllerReferenceFacts(f directoryFacts, v DomainController) {
	p := "dc:" + v.Server.DistinguishedName + "/"
	putFact(f, p+"server_dn", v.Server.DistinguishedName)
	putFact(f, p+"dsa_dn", v.Settings.DistinguishedName)
	putFact(f, p+"computer_dn", v.Computer.DistinguishedName)
	scalarFact(f, p+"host", v.HostName)
	scalarFact(f, p+"site", v.SiteName)
	scalarFact(f, p+"enabled", v.Enabled)
	scalarFact(f, p+"gc", v.IsGlobalCatalog)
	scalarFact(f, p+"read_only", v.IsReadOnly)
	scalarFact(f, p+"os", v.OperatingSystem)
	scalarFact(f, p+"os_version", v.OperatingSystemVersion)
	scalarFact(f, p+"service_pack", v.OperatingSystemServicePack)
	scalarFact(f, p+"generation.schema", v.Functionality)
	binaryFact(f, p+"server_guid.binary", v.ServerObjectGUID)
	binaryFact(f, p+"dsa_guid.binary", v.NTDSSettingsObjectGUID)
	binaryFact(f, p+"invocation.binary", v.InvocationID)
	putFact(f, p+"partitions", v.Partitions...)
	var roles []string
	for _, role := range v.OperationMasterRoles {
		roles = append(roles, string(role))
	}
	putFact(f, p+"roles", roles...)
	putFact(f, p+"roles_known", strconv.FormatBool(v.OperationMasterRolesKnown))
}

func trustReferenceFacts(f directoryFacts, v Trust) {
	p := "trust:" + v.Raw.DistinguishedName + "/"
	putFact(f, p+"dn", v.Raw.DistinguishedName)
	binaryFact(f, p+"guid.binary", v.ObjectGUID)
	binaryFact(f, p+"sid.binary", v.SecurityIdentifier)
	scalarFact(f, p+"partner", v.Partner)
	scalarFact(f, p+"flat_name", v.FlatName)
	scalarFact(f, p+"direction.schema", v.Direction)
	scalarFact(f, p+"type.schema", v.Type)
	scalarFact(f, p+"attributes.schema", v.AttributesMask)
	scalarFact(f, p+"encryption.schema", v.SupportedEncryptionTypes)
}

func compareDirectoryFacts(expected, actual directoryFacts) []string {
	var mismatches []string
	for key, want := range expected {
		if got, ok := actual[key]; !ok || !slices.Equal(want, got) {
			mismatches = append(mismatches, key)
		}
	}
	for key := range actual {
		if _, ok := expected[key]; !ok {
			mismatches = append(mismatches, key)
		}
	}
	slices.Sort(mismatches)
	return mismatches
}

func validateDirectoryReference(ref directoryReference) error {
	if ref.SchemaVersion != 1 || ref.FixtureID == "" || !validServerHost(ref.Server) || len(ref.SDKRevision) != 40 {
		return fmt.Errorf("incomplete reference identity")
	}
	if _, err := hex.DecodeString(ref.SDKRevision); err != nil {
		return fmt.Errorf("invalid SDK revision")
	}
	switch ref.ServerVersionLabel {
	case "2016", "2019", "2022", "2025":
	default:
		return fmt.Errorf("missing server version label")
	}
	switch ref.Profile {
	case "core", "trust", "topology", "extended":
	default:
		return fmt.Errorf("unknown reference profile")
	}
	for _, key := range []string{"domain/dn", "domain/dns_root", "forest/name"} {
		if len(ref.Facts[key]) != 1 || ref.Facts[key][0] == "" {
			return fmt.Errorf("missing reference %s", key)
		}
	}
	domainGUID := ref.Facts["domain/guid.binary"]
	if len(domainGUID) != 1 {
		return fmt.Errorf("missing domain GUID")
	}
	if decoded, err := base64.StdEncoding.DecodeString(domainGUID[0]); err != nil || len(decoded) != 16 {
		return fmt.Errorf("invalid domain GUID")
	}
	controllers, ro, gc, nonGC := 0, false, false, false
	for key, values := range ref.Facts {
		if !strings.HasPrefix(key, "dc:") {
			continue
		}
		if strings.HasSuffix(key, "/server_dn") {
			if len(values) != 1 || values[0] == "" {
				return fmt.Errorf("missing controller identity")
			}
			controllers++
		}
		if slices.Equal(values, []string{"true"}) {
			if strings.HasSuffix(key, "/read_only") {
				ro = true
			}
			if strings.HasSuffix(key, "/gc") {
				gc = true
			}
		}
		if strings.HasSuffix(key, "/gc") && slices.Equal(values, []string{"false"}) {
			nonGC = true
		}
	}
	if controllers == 0 {
		return fmt.Errorf("positive controller fixture is required")
	}
	if ref.Profile == "topology" || ref.Profile == "extended" {
		if !ro || !gc || !nonGC || len(ref.Facts["forest/domains"]) < 2 {
			return fmt.Errorf("topology profile requires RODC, GC/non-GC and multiple domains")
		}
	}
	if ref.Profile == "trust" || ref.Profile == "extended" {
		qualified := false
		for key, values := range ref.Facts {
			if !strings.HasPrefix(key, "trust:") || !strings.HasSuffix(key, "/partner") || len(values) != 1 {
				continue
			}
			prefix := strings.TrimSuffix(key, "partner")
			if !slices.Equal(ref.Facts[prefix+"type.schema"], []string{"2"}) {
				continue
			}
			if dn := ref.Facts[prefix+"dn"]; len(dn) != 1 || dn[0] == "" {
				continue
			}
			guid, sid := ref.Facts[prefix+"guid.binary"], ref.Facts[prefix+"sid.binary"]
			if len(guid) != 1 || len(sid) != 1 {
				continue
			}
			guidBytes, guidErr := base64.StdEncoding.DecodeString(guid[0])
			sidBytes, sidErr := base64.StdEncoding.DecodeString(sid[0])
			if guidErr != nil || sidErr != nil || len(guidBytes) != 16 || len(sidBytes) == 0 {
				continue
			}
			attrs := ref.Facts[prefix+"attributes.schema"]
			direction := ref.Facts[prefix+"direction.schema"]
			if len(attrs) != 1 || len(direction) != 1 {
				continue
			}
			mask, e1 := strconv.ParseUint(attrs[0], 10, 32)
			bits, e2 := strconv.ParseUint(direction[0], 10, 32)
			if e1 != nil || e2 != nil || mask&0x20 != 0 || bits < 1 || bits > 3 {
				continue
			}
			source, partner := ref.Facts["domain/dns_root"][0], values[0]
			verified := func(trusting, trusted string) bool {
				for _, v := range ref.TrustVerification {
					if v.Method == "netdom trust /verify" && v.ExitCode != nil && *v.ExitCode == 0 && strings.EqualFold(v.Partner, partner) && strings.EqualFold(v.TrustingDomain, trusting) && strings.EqualFold(v.TrustedDomain, trusted) {
						return true
					}
				}
				return false
			}
			if (bits&2 == 0 || verified(source, partner)) && (bits&1 == 0 || verified(partner, source)) {
				qualified = true
			}
		}
		if !qualified {
			return fmt.Errorf("trust profile requires an external AD trust with successful secure-channel verification in each direction")
		}
	}
	return nil
}

func TestDirectoryReferenceRejectsEmptyPositiveProfiles(t *testing.T) {
	ref := directoryReference{SchemaVersion: 1, FixtureID: "synthetic-harness-test", Profile: "core", Server: "dc.example.test", SDKRevision: strings.Repeat("a", 40), ServerVersionLabel: "2025", Facts: directoryFacts{"domain/dn": {topDomain}, "domain/dns_root": {"example.test"}, "domain/guid.binary": {base64.StdEncoding.EncodeToString(make([]byte, 16))}, "forest/name": {"example.test"}, "dc:one/server_dn": {"CN=one"}}}
	if err := validateDirectoryReference(ref); err != nil {
		t.Fatal(err)
	}
	for _, profile := range []string{"trust", "topology", "extended"} {
		ref.Profile = profile
		if validateDirectoryReference(ref) == nil {
			t.Fatalf("empty %s fixture passed", profile)
		}
	}
	ref.Profile = "trust"
	ref.Facts["trust:one/partner"] = []string{"partner.test"}
	ref.Facts["trust:one/type.schema"] = []string{"2"}
	ref.Facts["trust:one/attributes.schema"] = []string{"0"}
	ref.Facts["trust:one/direction.schema"] = []string{"3"}
	ref.Facts["trust:one/dn"] = []string{"CN=partner," + topSystem}
	ref.Facts["trust:one/guid.binary"] = []string{base64.StdEncoding.EncodeToString(make([]byte, 16))}
	ref.Facts["trust:one/sid.binary"] = []string{base64.StdEncoding.EncodeToString([]byte{1, 2, 3})}
	zero := 0
	ref.TrustVerification = []directoryTrustVerification{{Partner: "partner.test", TrustingDomain: "example.test", TrustedDomain: "partner.test", Method: "netdom trust /verify", ExitCode: &zero}}
	if validateDirectoryReference(ref) == nil {
		t.Fatal("one half of a two-way trust passed")
	}
	ref.TrustVerification = append(ref.TrustVerification, directoryTrustVerification{Partner: "partner.test", TrustingDomain: "partner.test", TrustedDomain: "example.test", Method: "netdom trust /verify", ExitCode: &zero})
	if err := validateDirectoryReference(ref); err != nil {
		t.Fatal(err)
	}
	ref.Facts["trust:one/attributes.schema"] = []string{"32"}
	if validateDirectoryReference(ref) == nil {
		t.Fatal("within-forest relationship counted as external trust")
	}
}

func TestDirectoryReferenceComparisonIsStrictAndOrderIndependent(t *testing.T) {
	a, b := directoryFacts{}, directoryFacts{}
	putFact(a, "names", "DC2", "DC1")
	putFact(b, "names", "dc1", "dc2")
	putFact(a, "id.binary", "AbC=")
	putFact(b, "id.binary", "abc=")
	if mismatches := compareDirectoryFacts(a, b); !slices.Equal(mismatches, []string{"id.binary"}) {
		t.Fatal(mismatches)
	}
	delete(b, "names")
	putFact(b, "unexpected", "x")
	if mismatches := compareDirectoryFacts(a, b); !slices.Equal(mismatches, []string{"id.binary", "names", "unexpected"}) {
		t.Fatal(mismatches)
	}
}
