package acceptance

import (
	"context"
	"errors"
	"slices"
	"strings"
	"testing"
	"time"

	adengine "github.com/deploymenttheory/go-sdk-activedirectory/activedirectory/internal/engine"
	admodel "github.com/deploymenttheory/go-sdk-activedirectory/activedirectory/internal/model"
)

type InternalDirectoryLabCheck struct {
	Name     string  `json:"name"`
	Passed   bool    `json:"passed"`
	LDAPCode *uint32 `json:"ldap_code,omitempty"`
}

type InternalDirectoryComparison struct {
	Checks     []InternalDirectoryLabCheck `json:"checks"`
	Mismatches []string                    `json:"mismatches"`
	Facts      InternalDirectoryFacts      `json:"facts"`
}

func (r *InternalDirectoryComparison) InternalCheck(name string, complete bool, err error) bool {
	c := InternalDirectoryLabCheck{Name: name, Passed: complete && err == nil}
	var native *admodel.LDAPError
	if errors.As(err, &native) {
		code := native.Code
		c.LDAPCode = &code
	}
	r.Checks = append(r.Checks, c)
	return c.Passed
}

func (r InternalDirectoryComparison) InternalPassed() bool {
	return len(r.Checks) > 0 && len(r.Mismatches) == 0 &&
		!slices.ContainsFunc(r.Checks, func(c InternalDirectoryLabCheck) bool { return !c.Passed })
}

func InternalPrefixedDirectoryFacts(
	facts InternalDirectoryFacts,
	prefix string,
) InternalDirectoryFacts {
	result := InternalDirectoryFacts{}
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
func InternalCompareDirectoryWithReference(
	ctx context.Context,
	client *adengine.Client,
	ref InternalDirectoryReference,
) InternalDirectoryComparison {
	r := InternalDirectoryComparison{Facts: InternalDirectoryFacts{}, Mismatches: []string{}}
	if err := InternalValidateDirectoryReference(ref); err != nil {
		r.InternalCheck("reference-profile", false, err)
		return r
	}
	r.InternalCheck("reference-profile", true, nil)
	d := client.Directory()
	domain, err := d.Domain(ctx, admodel.DomainOptions{})
	r.InternalCheck("domain-default", domain.Observation.Complete, err)
	InternalDomainReferenceFacts(r.Facts, domain)
	if domain.Raw.DistinguishedName != "" {
		explicit, err := d.Domain(
			ctx,
			admodel.DomainOptions{DistinguishedName: domain.Raw.DistinguishedName},
		)
		facts := InternalDirectoryFacts{}
		InternalDomainReferenceFacts(facts, explicit)
		r.InternalCheck(
			"domain-dn",
			explicit.Observation.Complete &&
				len(
					InternalCompareDirectoryFacts(
						InternalPrefixedDirectoryFacts(ref.Facts, "domain/"),
						facts,
					),
				) == 0,
			err,
		)
	}
	forest, err := d.Forest(ctx)
	r.InternalCheck("forest", forest.Observation.Complete, err)
	InternalForestReferenceFacts(r.Facts, forest)
	controllers, err := d.DomainControllers(ctx, admodel.DomainControllersQuery{PageSize: 1})
	r.InternalCheck(
		"controllers-paged",
		controllers.Observation.Complete && !controllers.LimitReached,
		err,
	)
	for _, controller := range controllers.Controllers {
		InternalControllerReferenceFacts(r.Facts, controller)
		identity, err := d.DomainController(
			ctx,
			admodel.DomainControllerOptions{ServerDN: controller.Server.DistinguishedName},
		)
		facts := InternalDirectoryFacts{}
		InternalControllerReferenceFacts(facts, identity.Controller)
		prefix := "dc:" + controller.Server.DistinguishedName + "/"
		r.InternalCheck(
			"controller-server-dn",
			identity.Observation.Complete &&
				len(
					InternalCompareDirectoryFacts(
						InternalPrefixedDirectoryFacts(ref.Facts, prefix),
						facts,
					),
				) == 0,
			err,
		)
	}
	connected, err := d.DomainController(ctx, admodel.DomainControllerOptions{})
	InternalPutFact(r.Facts, "connected/server_dn", connected.Controller.Server.DistinguishedName)
	InternalScalarFact(r.Facts, "connected/gc_ready", connected.Controller.GlobalCatalogReady)
	facts := InternalDirectoryFacts{}
	InternalControllerReferenceFacts(facts, connected.Controller)
	r.InternalCheck(
		"controller-connected",
		connected.Observation.Complete &&
			len(
				InternalCompareDirectoryFacts(
					InternalPrefixedDirectoryFacts(
						ref.Facts,
						"dc:"+connected.Controller.Server.DistinguishedName+"/",
					),
					facts,
				),
			) == 0,
		err,
	)
	for _, criterion := range []string{"gc", "read_only"} {
		for _, wanted := range []bool{false, true} {
			query := admodel.DomainControllersQuery{PageSize: 1}
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
				if strings.HasPrefix(key, "dc:") && strings.HasSuffix(key, "/"+criterion) &&
					slices.Equal(
						value,
						[]string{map[bool]string{false: "false", true: "true"}[wanted]},
					) {
					expected = append(
						expected,
						strings.TrimSuffix(strings.TrimPrefix(key, "dc:"), "/"+criterion),
					)
				}
			}
			slices.Sort(actual)
			slices.Sort(expected)
			r.InternalCheck(
				"controllers-"+criterion+"-"+map[bool]string{false: "false", true: "true"}[wanted],
				filtered.Observation.Complete && slices.Equal(actual, expected),
				err,
			)
			if len(expected) > 0 {
				query.ResultLimit = 1
				limited, err := d.DomainControllers(ctx, query)
				matches := len(limited.Controllers) == 1 &&
					slices.Contains(
						expected,
						strings.ToLower(limited.Controllers[0].Server.DistinguishedName),
					)
				r.InternalCheck(
					"controllers-limit-after-"+criterion,
					matches && limited.LimitReached && !limited.Observation.Complete,
					err,
				)
			}
		}
	}
	trusts, err := d.Trusts(
		ctx,
		admodel.TrustQuery{PageSize: 1, LDAPFilter: "(objectClass=trustedDomain)"},
	)
	r.InternalCheck("trusts-ldap-paged", trusts.Observation.Complete && !trusts.LimitReached, err)
	for _, trust := range trusts.Trusts {
		InternalTrustReferenceFacts(r.Facts, trust)
		for _, properties := range [][]string{nil, {"description"}, {"*"}} {
			identity, err := d.Trust(
				ctx,
				trust.Raw.DistinguishedName,
				admodel.TrustOptions{Properties: properties},
			)
			facts := InternalDirectoryFacts{}
			InternalTrustReferenceFacts(facts, identity.Trust)
			matches := len(
				InternalCompareDirectoryFacts(
					InternalPrefixedDirectoryFacts(
						ref.Facts,
						"trust:"+trust.Raw.DistinguishedName+"/",
					),
					facts,
				),
			) == 0
			selection := true
			if slices.Contains(properties, "description") {
				_, state := identity.Trust.Raw.Attribute("description")
				selection = state == admodel.AttributeAbsent || state == admodel.AttributePresent
			}
			r.InternalCheck(
				"trust-dn-properties",
				identity.Observation.Complete && matches && selection,
				err,
			)
		}
	}
	r.Mismatches = InternalCompareDirectoryFacts(ref.Facts, r.Facts)
	r.InternalCheck("allowlisted-differential", len(r.Mismatches) == 0, nil)
	return r
}

func TestDirectoryComparisonRunnerPreservesFailuresAndExercisesPublicReads(t *testing.T) {
	f := InternalNewTopologyFixture()
	client := f.InternalClient(time.Second)
	defer client.Close()
	facts := InternalDirectoryFacts{}
	domain, err := client.Directory().Domain(context.Background(), admodel.DomainOptions{})
	if err != nil {
		t.Fatal(err)
	}
	InternalDomainReferenceFacts(facts, domain)
	forest, err := client.Directory().Forest(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	InternalForestReferenceFacts(facts, forest)
	controllers, err := client.Directory().
		DomainControllers(context.Background(), admodel.DomainControllersQuery{})
	if err != nil {
		t.Fatal(err)
	}
	for _, v := range controllers.Controllers {
		InternalControllerReferenceFacts(facts, v)
	}
	connected, err := client.Directory().
		DomainController(context.Background(), admodel.DomainControllerOptions{})
	if err != nil {
		t.Fatal(err)
	}
	InternalPutFact(facts, "connected/server_dn", connected.Controller.Server.DistinguishedName)
	InternalScalarFact(facts, "connected/gc_ready", connected.Controller.GlobalCatalogReady)
	trusts, err := client.Directory().Trusts(context.Background(), admodel.TrustQuery{})
	if err != nil {
		t.Fatal(err)
	}
	for _, v := range trusts.Trusts {
		InternalTrustReferenceFacts(facts, v)
	}
	ref := InternalDirectoryReference{
		SchemaVersion:      1,
		FixtureID:          "synthetic-runner-test",
		Profile:            "core",
		Server:             "dc1.example.test",
		SDKRevision:        strings.Repeat("a", 40),
		ServerVersionLabel: "2025",
		Facts:              facts,
	}
	result := InternalCompareDirectoryWithReference(context.Background(), client, ref)
	if !result.InternalPassed() || len(result.Checks) < 15 {
		t.Fatalf("comparison checks: %+v", result.Checks)
	}
	f.InternalFailBase = InternalTopRID
	f.InternalFailure = &admodel.LDAPError{Operation: "Search", Code: 50}
	result = InternalCompareDirectoryWithReference(context.Background(), client, ref)
	if result.InternalPassed() ||
		!slices.ContainsFunc(
			result.Checks,
			func(c InternalDirectoryLabCheck) bool { return !c.Passed && c.LDAPCode != nil && *c.LDAPCode == 50 },
		) {
		t.Fatal("partial permission failure was accepted")
	}
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	if InternalCompareDirectoryWithReference(ctx, client, ref).InternalPassed() {
		t.Fatal("canceled comparison passed")
	}
}
