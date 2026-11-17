package acceptance

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

	admodel "github.com/deploymenttheory/go-sdk-activedirectory/activedirectory/internal/model"
)

func TestDirectoryReferenceFactsKeepOnlyAllowlistedValues(t *testing.T) {
	fixture := InternalNewTopologyFixture()
	client := fixture.InternalClient(time.Second)
	defer client.Close()
	domain, err := client.Directory().Domain(context.Background(), admodel.DomainOptions{})
	if err != nil {
		t.Fatal(err)
	}
	forest, err := client.Directory().Forest(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	controller, err := client.Directory().
		DomainController(context.Background(), admodel.DomainControllerOptions{})
	if err != nil {
		t.Fatal(err)
	}
	trust, err := client.Directory().
		Trust(context.Background(), InternalTopTrust, admodel.TrustOptions{})
	if err != nil {
		t.Fatal(err)
	}
	trust.Trust.Raw.Attributes["trustauthincoming"] = [][]byte{[]byte("synthetic-secret")}
	facts := InternalDirectoryFacts{}
	InternalDomainReferenceFacts(facts, domain)
	InternalForestReferenceFacts(facts, forest)
	InternalControllerReferenceFacts(facts, controller.Controller)
	InternalTrustReferenceFacts(facts, trust.Trust)
	for key, want := range map[string][]string{"domain/level": {"7"}, "forest/level": {"10"}, "domain/read_only": {"dc2.example.test"}, "dc:" + strings.ToLower(InternalTopServer) + "/roles_known": {"true"}, "trust:" + strings.ToLower(InternalTopTrust) + "/attributes.schema": {"2147483656"}} {
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
type InternalDirectoryFacts map[string][]string

type InternalDirectoryReference struct {
	SchemaVersion      int                                  `json:"schema_version"`
	RunID              string                               `json:"run_id"`
	Passed             *bool                                `json:"passed"`
	FixtureID          string                               `json:"fixture_id"`
	Profile            string                               `json:"profile"`
	Server             string                               `json:"server"`
	SDKRevision        string                               `json:"sdk_revision"`
	ServerVersionLabel string                               `json:"server_version_label"`
	Facts              InternalDirectoryFacts               `json:"facts"`
	TrustVerification  []InternalDirectoryTrustVerification `json:"trust_verification"`
}

type InternalDirectoryTrustVerification struct {
	Partner        string `json:"partner"`
	TrustingDomain string `json:"trusting_domain"`
	TrustedDomain  string `json:"trusted_domain"`
	Method         string `json:"method"`
	ExitCode       *int   `json:"exit_code"`
}

func InternalPutFact(f InternalDirectoryFacts, key string, values ...string) {
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

func InternalScalarFact[T any](f InternalDirectoryFacts, key string, value *T) {
	if value == nil {
		InternalPutFact(f, key)
		return
	}
	InternalPutFact(f, key, fmt.Sprint(*value))
}

func InternalBinaryFact(f InternalDirectoryFacts, key string, value []byte) {
	if value == nil {
		InternalPutFact(f, key)
		return
	}
	InternalPutFact(f, key, base64.StdEncoding.EncodeToString(value))
}

func InternalOwnerFact(f InternalDirectoryFacts, key string, owner *admodel.RoleOwner) {
	if owner == nil {
		InternalPutFact(f, key)
		return
	}
	InternalScalarFact(f, key, owner.HostName)
}

func InternalDomainReferenceFacts(f InternalDirectoryFacts, d admodel.Domain) {
	InternalPutFact(f, "domain/dn", d.Raw.DistinguishedName)
	InternalBinaryFact(f, "domain/guid.binary", d.ObjectGUID)
	InternalBinaryFact(f, "domain/sid.binary", d.ObjectSID)
	InternalScalarFact(f, "domain/name", d.Name)
	InternalScalarFact(f, "domain/dns_root", d.DNSRoot)
	InternalScalarFact(f, "domain/netbios", d.NetBIOSName)
	InternalScalarFact(f, "domain/forest", d.ForestDNSRoot)
	InternalScalarFact(f, "domain/level", d.FunctionalLevel)
	InternalScalarFact(f, "domain/managed_by", d.ManagedBy)
	InternalPutFact(f, "domain/allowed_suffixes", d.AllowedDNSSuffixes...)
	InternalPutFact(f, "domain/subrefs", d.SubordinateReferences...)
	InternalOwnerFact(f, "domain/pdc", d.PDCEmulator)
	InternalOwnerFact(f, "domain/rid", d.RIDMaster)
	InternalOwnerFact(f, "domain/infrastructure", d.InfrastructureMaster)
	var parent *string
	if d.Parent != nil {
		parent = d.Parent.DNSRoot
	}
	InternalScalarFact(f, "domain/parent", parent)
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
	InternalPutFact(f, "domain/children", children...)
	InternalPutFact(f, "domain/writable", writable...)
	InternalPutFact(f, "domain/read_only", readOnly...)
	for _, id := range []string{"AA312825768811D1ADED00C04FD8D5CD", "A9D1CA15768811D1ADED00C04FD8D5CD", "A361B2FFFFD211D1AA4B00C04FD7D83A", "18E2EA80684F11D2B9AA00C04F79F805", "22B70C67D56E4EFB91E9300FCA3DC1AA", "AB8153B7768811D1ADED00C04FD8D5CD", "6227F0AF1FC2410D8E3BB10615BB5B0F", admodel.InternalWellKnownSystem} {
		if dn := d.WellKnownContainers[id]; dn != "" {
			InternalPutFact(f, "domain/container/"+id, dn)
		} else {
			InternalPutFact(f, "domain/container/"+id)
		}
	}
}

func InternalForestReferenceFacts(f InternalDirectoryFacts, v admodel.Forest) {
	InternalScalarFact(f, "forest/name", v.Name)
	InternalScalarFact(f, "forest/level", v.FunctionalLevel)
	InternalPutFact(f, "forest/upn_suffixes", v.UPNSuffixes...)
	InternalPutFact(f, "forest/spn_suffixes", v.SPNSuffixes...)
	InternalOwnerFact(f, "forest/schema", v.SchemaMaster)
	InternalOwnerFact(f, "forest/naming", v.DomainNamingMaster)
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
	InternalPutFact(f, "forest/domains", domains...)
	InternalPutFact(f, "forest/applications", apps...)
	InternalPutFact(f, "forest/external", external...)
	InternalPutFact(f, "forest/sites", sites...)
	InternalPutFact(f, "forest/gcs", gcs...)
}

func InternalControllerReferenceFacts(f InternalDirectoryFacts, v admodel.DomainController) {
	p := "dc:" + v.Server.DistinguishedName + "/"
	InternalPutFact(f, p+"server_dn", v.Server.DistinguishedName)
	InternalPutFact(f, p+"dsa_dn", v.Settings.DistinguishedName)
	InternalPutFact(f, p+"computer_dn", v.Computer.DistinguishedName)
	InternalScalarFact(f, p+"host", v.HostName)
	InternalScalarFact(f, p+"site", v.SiteName)
	InternalScalarFact(f, p+"enabled", v.Enabled)
	InternalScalarFact(f, p+"gc", v.IsGlobalCatalog)
	InternalScalarFact(f, p+"read_only", v.IsReadOnly)
	InternalScalarFact(f, p+"os", v.OperatingSystem)
	InternalScalarFact(f, p+"os_version", v.OperatingSystemVersion)
	InternalScalarFact(f, p+"service_pack", v.OperatingSystemServicePack)
	InternalScalarFact(f, p+"generation.schema", v.Functionality)
	InternalBinaryFact(f, p+"server_guid.binary", v.ServerObjectGUID)
	InternalBinaryFact(f, p+"dsa_guid.binary", v.NTDSSettingsObjectGUID)
	InternalBinaryFact(f, p+"invocation.binary", v.InvocationID)
	InternalPutFact(f, p+"partitions", v.Partitions...)
	var roles []string
	for _, role := range v.OperationMasterRoles {
		roles = append(roles, string(role))
	}
	InternalPutFact(f, p+"roles", roles...)
	InternalPutFact(f, p+"roles_known", strconv.FormatBool(v.OperationMasterRolesKnown))
}

func InternalTrustReferenceFacts(f InternalDirectoryFacts, v admodel.Trust) {
	p := "trust:" + v.Raw.DistinguishedName + "/"
	InternalPutFact(f, p+"dn", v.Raw.DistinguishedName)
	InternalBinaryFact(f, p+"guid.binary", v.ObjectGUID)
	InternalBinaryFact(f, p+"sid.binary", v.SecurityIdentifier)
	InternalScalarFact(f, p+"partner", v.Partner)
	InternalScalarFact(f, p+"flat_name", v.FlatName)
	InternalScalarFact(f, p+"direction.schema", v.Direction)
	InternalScalarFact(f, p+"type.schema", v.Type)
	InternalScalarFact(f, p+"attributes.schema", v.AttributesMask)
	InternalScalarFact(f, p+"encryption.schema", v.SupportedEncryptionTypes)
}

func InternalCompareDirectoryFacts(expected, actual InternalDirectoryFacts) []string {
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

func InternalValidateDirectoryReference(ref InternalDirectoryReference) error {
	if ref.SchemaVersion != 1 || ref.FixtureID == "" ||
		!admodel.InternalValidServerHost(ref.Server) ||
		len(ref.SDKRevision) != 40 {
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
	if decoded, err := base64.StdEncoding.DecodeString(
		domainGUID[0],
	); err != nil ||
		len(decoded) != 16 {
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
			if !strings.HasPrefix(key, "trust:") || !strings.HasSuffix(key, "/partner") ||
				len(values) != 1 {
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
			if strings.EqualFold(source, partner) {
				continue
			}
			verified := func(trusting, trusted string) bool {
				for _, v := range ref.TrustVerification {
					if v.Method == "netdom trust /verify" && v.ExitCode != nil &&
						*v.ExitCode == 0 &&
						strings.EqualFold(v.Partner, partner) &&
						strings.EqualFold(v.TrustingDomain, trusting) &&
						strings.EqualFold(v.TrustedDomain, trusted) {
						return true
					}
				}
				return false
			}
			if (bits&2 == 0 || verified(source, partner)) &&
				(bits&1 == 0 || verified(partner, source)) {
				qualified = true
			}
		}
		if !qualified {
			return fmt.Errorf(
				"trust profile requires an external AD trust with successful secure-channel verification in each direction",
			)
		}
	}
	return nil
}

func TestDirectoryReferenceRejectsEmptyPositiveProfiles(t *testing.T) {
	ref := InternalDirectoryReference{
		SchemaVersion:      1,
		FixtureID:          "synthetic-harness-test",
		Profile:            "core",
		Server:             "dc.example.test",
		SDKRevision:        strings.Repeat("a", 40),
		ServerVersionLabel: "2025",
		Facts: InternalDirectoryFacts{
			"domain/dn":          {InternalTopDomain},
			"domain/dns_root":    {"example.test"},
			"domain/guid.binary": {base64.StdEncoding.EncodeToString(make([]byte, 16))},
			"forest/name":        {"example.test"},
			"dc:one/server_dn":   {"CN=one"},
		},
	}
	if err := InternalValidateDirectoryReference(ref); err != nil {
		t.Fatal(err)
	}
	for _, profile := range []string{"trust", "topology", "extended"} {
		ref.Profile = profile
		if InternalValidateDirectoryReference(ref) == nil {
			t.Fatalf("empty %s fixture passed", profile)
		}
	}
	ref.Profile = "trust"
	ref.Facts["trust:one/partner"] = []string{"partner.test"}
	ref.Facts["trust:one/type.schema"] = []string{"2"}
	ref.Facts["trust:one/attributes.schema"] = []string{"0"}
	ref.Facts["trust:one/direction.schema"] = []string{"3"}
	ref.Facts["trust:one/dn"] = []string{"CN=partner," + InternalTopSystem}
	ref.Facts["trust:one/guid.binary"] = []string{
		base64.StdEncoding.EncodeToString(make([]byte, 16)),
	}
	ref.Facts["trust:one/sid.binary"] = []string{base64.StdEncoding.EncodeToString([]byte{1, 2, 3})}
	zero := 0
	ref.TrustVerification = []InternalDirectoryTrustVerification{
		{
			Partner:        "partner.test",
			TrustingDomain: "example.test",
			TrustedDomain:  "partner.test",
			Method:         "netdom trust /verify",
			ExitCode:       &zero,
		},
	}
	if InternalValidateDirectoryReference(ref) == nil {
		t.Fatal("one half of a two-way trust passed")
	}
	ref.TrustVerification = append(
		ref.TrustVerification,
		InternalDirectoryTrustVerification{
			Partner:        "partner.test",
			TrustingDomain: "partner.test",
			TrustedDomain:  "example.test",
			Method:         "netdom trust /verify",
			ExitCode:       &zero,
		},
	)
	if err := InternalValidateDirectoryReference(ref); err != nil {
		t.Fatal(err)
	}
	ref.Facts["trust:one/attributes.schema"] = []string{"32"}
	if InternalValidateDirectoryReference(ref) == nil {
		t.Fatal("within-forest relationship counted as external trust")
	}
}

func TestDirectoryReferenceComparisonIsStrictAndOrderIndependent(t *testing.T) {
	a, b := InternalDirectoryFacts{}, InternalDirectoryFacts{}
	InternalPutFact(a, "names", "DC2", "DC1")
	InternalPutFact(b, "names", "dc1", "dc2")
	InternalPutFact(a, "id.binary", "AbC=")
	InternalPutFact(b, "id.binary", "abc=")
	if mismatches := InternalCompareDirectoryFacts(
		a,
		b,
	); !slices.Equal(
		mismatches,
		[]string{"id.binary"},
	) {
		t.Fatal(mismatches)
	}
	delete(b, "names")
	InternalPutFact(b, "unexpected", "x")
	if mismatches := InternalCompareDirectoryFacts(
		a,
		b,
	); !slices.Equal(
		mismatches,
		[]string{"id.binary", "names", "unexpected"},
	) {
		t.Fatal(mismatches)
	}
}
