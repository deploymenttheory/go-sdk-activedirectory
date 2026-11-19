package discovery

import (
	"context"

	"github.com/deploymenttheory/go-sdk-activedirectory/activedirectory/client"
	"github.com/deploymenttheory/go-sdk-activedirectory/activedirectory/config"
	adengine "github.com/deploymenttheory/go-sdk-activedirectory/activedirectory/internal/engine"
	admodel "github.com/deploymenttheory/go-sdk-activedirectory/activedirectory/internal/model"
)

// DNSDiscoveryOptions supplies an explicit AD DNS domain and optional DNS site
// label. No Windows join state, user identity or DNS search suffix is inferred.
type DNSDiscoveryOptions = admodel.DNSDiscoveryOptions

// DNSSRVRecord preserves untrusted service priority, weight, target and port.
type DNSSRVRecord = admodel.DNSSRVRecord

// DNSControllerCandidate contains DNS advertisements, never authenticated facts.
type DNSControllerCandidate = admodel.DNSControllerCandidate

// DNSDiscoveryResult requires explicit endpoint selection before authentication.
// Multiple A/AAAA addresses and disjoint hostname namespaces remain supported.
type DNSDiscoveryResult = admodel.DNSDiscoveryResult

// DomainControllerSelection constrains an explicitly configured portable DC by
// actual AD domain and optional GUID/SID/site identity. DNS is never authority.
type DomainControllerSelection = admodel.DomainControllerSelection

// AuthenticatedController preserves copied partial identity/protection facts.
// Complete establishes the selection constraints, not full cmdlet parity.
type AuthenticatedController = admodel.AuthenticatedController

// ErrDiscoveryNoCandidates identifies missing usable DNS advertisements without
// claiming the domain/controller is absent from the directory.
var ErrDiscoveryNoCandidates = admodel.ErrDiscoveryNoCandidates

// ErrDiscoveryAmbiguous requires the caller to resolve an ambiguous selection.
var ErrDiscoveryAmbiguous = admodel.ErrDiscoveryAmbiguous

// ErrDiscoveryIdentity identifies a mismatch with authenticated directory data.
var ErrDiscoveryIdentity = admodel.ErrDiscoveryIdentity

// LookupDomainControllers observes SRV/canonical-name/address records for the
// explicit domain. It neither authenticates nor automatically tries candidates.
// Select one host explicitly, then configure its own credentials/realm/SPN/trust.
func LookupDomainControllers(ctx context.Context, options DNSDiscoveryOptions) (DNSDiscoveryResult, error) {
	return adengine.LookupDomainControllers(ctx, options)
}

// DialDomainController opens one explicit protected portable client and validates
// its domain/DC identity on that same session. Failed validation closes the new
// client and returns partial observations. The caller closes successful clients.
func DialDomainController(ctx context.Context, options config.Config, selection DomainControllerSelection) (*client.Client, AuthenticatedController, error) {
	return adengine.DialDomainController(ctx, options, selection)
}
