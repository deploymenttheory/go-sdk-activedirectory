package activedirectory

import (
	"context"
	"errors"
	"slices"
	"strings"
	"testing"
	"time"
)

type directoryLabCheck struct {
	Name     string  `json:"name"`
	Passed   bool    `json:"passed"`
	LDAPCode *uint32 `json:"ldap_code,omitempty"`
}

type directoryComparison struct {
	Checks     []directoryLabCheck `json:"checks"`
	Mismatches []string            `json:"mismatches"`
	Facts      directoryFacts      `json:"facts"`
}

func (r *directoryComparison) check(name string, complete bool, err error) bool {
	c := directoryLabCheck{Name: name, Passed: complete && err == nil}
	var native *LDAPError
	if errors.As(err, &native) {
		code := native.Code
		c.LDAPCode = &code
	}
	r.Checks = append(r.Checks, c)
	return c.Passed
}

func (r directoryComparison) passed() bool {
	return len(r.Checks) > 0 && len(r.Mismatches) == 0 && !slices.ContainsFunc(r.Checks, func(c directoryLabCheck) bool { return !c.Passed })
}

func prefixedDirectoryFacts(facts directoryFacts, prefix string) directoryFacts {
	result := directoryFacts{}
	prefix = strings.ToLower(prefix)
	for key, value := range facts {
		if strings.HasPrefix(key, prefix) {
			result[key] = value
		}
	}
	return result
}

// The portable runner exercises the same public operations as the native lab
// entry point. It never executes PowerShell or interprets verification receipts
// as proof of their provenance; the outer harness retains that evidence chain.
func compareDirectoryWithReference(ctx context.Context, client *Client, ref directoryReference) directoryComparison {
	r := directoryComparison{Facts: directoryFacts{}, Mismatches: []string{}}
	if err := validateDirectoryReference(ref); err != nil {
		r.check("reference-profile", false, err)
		return r
	}
	r.check("reference-profile", true, nil)
	d := client.Directory()
	domain, err := d.Domain(ctx, DomainOptions{})
	r.check("domain-default", domain.Observation.Complete, err)
	domainReferenceFacts(r.Facts, domain)
	if domain.Raw.DistinguishedName != "" {
		explicit, err := d.Domain(ctx, DomainOptions{DistinguishedName: domain.Raw.DistinguishedName})
		facts := directoryFacts{}
		domainReferenceFacts(facts, explicit)
		r.check("domain-dn", explicit.Observation.Complete && len(compareDirectoryFacts(prefixedDirectoryFacts(ref.Facts, "domain/"), facts)) == 0, err)
	}
	forest, err := d.Forest(ctx)
	r.check("forest", forest.Observation.Complete, err)
	forestReferenceFacts(r.Facts, forest)
	controllers, err := d.DomainControllers(ctx, DomainControllersQuery{PageSize: 1})
	r.check("controllers-paged", controllers.Observation.Complete && !controllers.LimitReached, err)
	for _, controller := range controllers.Controllers {
		controllerReferenceFacts(r.Facts, controller)
		identity, err := d.DomainController(ctx, DomainControllerOptions{ServerDN: controller.Server.DistinguishedName})
		facts := directoryFacts{}
		controllerReferenceFacts(facts, identity.Controller)
		prefix := "dc:" + controller.Server.DistinguishedName + "/"
		r.check("controller-server-dn", identity.Observation.Complete && len(compareDirectoryFacts(prefixedDirectoryFacts(ref.Facts, prefix), facts)) == 0, err)
	}
	connected, err := d.DomainController(ctx, DomainControllerOptions{})
	putFact(r.Facts, "connected/server_dn", connected.Controller.Server.DistinguishedName)
	scalarFact(r.Facts, "connected/gc_ready", connected.Controller.GlobalCatalogReady)
	facts := directoryFacts{}
	controllerReferenceFacts(facts, connected.Controller)
	r.check("controller-connected", connected.Observation.Complete && len(compareDirectoryFacts(prefixedDirectoryFacts(ref.Facts, "dc:"+connected.Controller.Server.DistinguishedName+"/"), facts)) == 0, err)
	for _, criterion := range []string{"gc", "read_only"} {
		for _, wanted := range []bool{false, true} {
			query := DomainControllersQuery{PageSize: 1}
			if criterion == "gc" {
				query.IsGlobalCatalog = &wanted
			} else {
				query.IsReadOnly = &wanted
			}
			filtered, err := d.DomainControllers(ctx, query)
			var actual, expected []string
			for _, c := range filtered.Controllers {
				actual = append(actual, strings.ToLower(c.Server.DistinguishedName))
			}
			for key, value := range ref.Facts {
				if strings.HasPrefix(key, "dc:") && strings.HasSuffix(key, "/"+criterion) && slices.Equal(value, []string{map[bool]string{false: "false", true: "true"}[wanted]}) {
					expected = append(expected, strings.TrimSuffix(strings.TrimPrefix(key, "dc:"), "/"+criterion))
				}
			}
			slices.Sort(actual)
			slices.Sort(expected)
			r.check("controllers-"+criterion+"-"+map[bool]string{false: "false", true: "true"}[wanted], filtered.Observation.Complete && slices.Equal(actual, expected), err)
			if len(expected) > 0 {
				query.ResultLimit = 1
				limited, err := d.DomainControllers(ctx, query)
				matches := len(limited.Controllers) == 1 && slices.Contains(expected, strings.ToLower(limited.Controllers[0].Server.DistinguishedName))
				r.check("controllers-limit-after-"+criterion, matches && limited.LimitReached && !limited.Observation.Complete, err)
			}
		}
	}
	trusts, err := d.Trusts(ctx, TrustQuery{PageSize: 1, LDAPFilter: "(objectClass=trustedDomain)"})
	r.check("trusts-ldap-paged", trusts.Observation.Complete && !trusts.LimitReached, err)
	for _, trust := range trusts.Trusts {
		trustReferenceFacts(r.Facts, trust)
		for _, properties := range [][]string{nil, {"description"}, {"*"}} {
			identity, err := d.Trust(ctx, trust.Raw.DistinguishedName, TrustOptions{Properties: properties})
			facts := directoryFacts{}
			trustReferenceFacts(facts, identity.Trust)
			matches := len(compareDirectoryFacts(prefixedDirectoryFacts(ref.Facts, "trust:"+trust.Raw.DistinguishedName+"/"), facts)) == 0
			selection := true
			if slices.Contains(properties, "description") {
				_, state := identity.Trust.Raw.Attribute("description")
				selection = state == AttributeAbsent || state == AttributePresent
			}
			r.check("trust-dn-properties", identity.Observation.Complete && matches && selection, err)
		}
	}
	r.Mismatches = compareDirectoryFacts(ref.Facts, r.Facts)
	r.check("allowlisted-differential", len(r.Mismatches) == 0, nil)
	return r
}

func TestDirectoryComparisonRunnerPreservesFailuresAndExercisesPublicReads(t *testing.T) {
	f := newTopologyFixture()
	client := f.client(time.Second)
	defer client.Close()
	facts := directoryFacts{}
	domain, err := client.Directory().Domain(context.Background(), DomainOptions{})
	if err != nil {
		t.Fatal(err)
	}
	domainReferenceFacts(facts, domain)
	forest, err := client.Directory().Forest(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	forestReferenceFacts(facts, forest)
	controllers, err := client.Directory().DomainControllers(context.Background(), DomainControllersQuery{})
	if err != nil {
		t.Fatal(err)
	}
	for _, v := range controllers.Controllers {
		controllerReferenceFacts(facts, v)
	}
	connected, err := client.Directory().DomainController(context.Background(), DomainControllerOptions{})
	if err != nil {
		t.Fatal(err)
	}
	putFact(facts, "connected/server_dn", connected.Controller.Server.DistinguishedName)
	scalarFact(facts, "connected/gc_ready", connected.Controller.GlobalCatalogReady)
	trusts, err := client.Directory().Trusts(context.Background(), TrustQuery{})
	if err != nil {
		t.Fatal(err)
	}
	for _, v := range trusts.Trusts {
		trustReferenceFacts(facts, v)
	}
	ref := directoryReference{SchemaVersion: 1, FixtureID: "synthetic-runner-test", Profile: "core", Server: "dc1.example.test", SDKRevision: strings.Repeat("a", 40), ServerVersionLabel: "2025", Facts: facts}
	result := compareDirectoryWithReference(context.Background(), client, ref)
	if !result.passed() || len(result.Checks) < 15 {
		t.Fatalf("comparison checks: %+v", result.Checks)
	}
	f.failBase = topRID
	f.failure = &LDAPError{Operation: "Search", Code: 50}
	result = compareDirectoryWithReference(context.Background(), client, ref)
	if result.passed() || !slices.ContainsFunc(result.Checks, func(c directoryLabCheck) bool { return !c.Passed && c.LDAPCode != nil && *c.LDAPCode == 50 }) {
		t.Fatal("partial permission failure was accepted")
	}
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	if compareDirectoryWithReference(ctx, client, ref).passed() {
		t.Fatal("canceled comparison passed")
	}
}
