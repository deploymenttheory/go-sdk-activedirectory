package engine

import (
	"context"
	"errors"
	"fmt"
	"net"
	"net/netip"
	"strconv"
	"strings"

	admodel "github.com/deploymenttheory/go-sdk-activedirectory/activedirectory/internal/model"
)

const internalDiscoveryDNSRecordLimit = 4096

// InternalDiscoveryResolver is per-call test composition, not a global locator,
// authentication factory or public credential-bearing resolver callback.
type InternalDiscoveryResolver interface {
	LookupSRV(context.Context, string, string, string) (string, []*net.SRV, error)
	LookupCNAME(context.Context, string) (string, error)
	LookupIPAddr(context.Context, string) ([]net.IPAddr, error)
}

// LookupDomainControllers observes explicit-domain DNS candidates. It performs
// no LDAP ping, authentication, OS-domain lookup or endpoint selection/retry.
func LookupDomainControllers(ctx context.Context, options admodel.DNSDiscoveryOptions) (admodel.DNSDiscoveryResult, error) {
	return InternalLookupDomainControllers(ctx, options, internalDiscoverySystemResolver())
}

// InternalLookupDomainControllers exercises the actual DNS observation boundary
// with an owned resolver in wire tests. No credential is supplied to DNS.
func InternalLookupDomainControllers(ctx context.Context, options admodel.DNSDiscoveryOptions, resolver InternalDiscoveryResolver) (result admodel.DNSDiscoveryResult, err error) {
	options, err = admodel.InternalDNSDiscoveryNormalized(options)
	if err != nil {
		return result, err
	}
	if resolver == nil {
		return result, admodel.ErrInvalidDiscovery
	}
	result.Requested = options
	result.QueryName = admodel.InternalDNSDiscoveryQuery(options)
	bounded, cancel := context.WithTimeout(ctx, options.Timeout)
	defer cancel()
	defer func() { err = errors.Join(err, InternalConnectionContextCause(bounded)); result.Complete = err == nil }()
	if cause := InternalConnectionContextCause(bounded); cause != nil {
		return result, cause
	}
	// Empty service/proto sends this one absolute SRV name, without search-suffix
	// expansion or changing to a different service/site/domain after failure.
	srv, lookupErr := internalDiscoveryLookup(bounded, func() (internalDiscoverySRVReply, error) {
		canonical, records, queryErr := resolver.LookupSRV(bounded, "", "", result.QueryName)
		return internalDiscoverySRVReply{canonical: canonical, records: records}, queryErr
	})
	canonical, records := srv.canonical, srv.records
	result.CanonicalName = canonical
	result.Records = internalDiscoveryRecords(records)
	if lookupErr != nil {
		return result, errors.Join(admodel.ErrIncompleteResult, lookupErr)
	}
	if !strings.EqualFold(canonical, result.QueryName) {
		return result, admodel.ErrDiscoveryAmbiguous
	}
	if len(records) == 0 {
		return result, admodel.ErrDiscoveryNoCandidates
	}
	if len(records) > internalDiscoveryDNSRecordLimit {
		return result, admodel.ErrIncompleteResult
	}
	groups := make(map[string]int)
	for _, record := range records {
		if record == nil {
			return result, admodel.ErrInvalidResult
		}
		if record.Target == "." {
			if len(records) != 1 {
				return result, admodel.ErrDiscoveryAmbiguous
			}
			return result, admodel.ErrDiscoveryNoCandidates
		}
		if record.Port == 0 {
			return result, admodel.ErrDiscoveryNoCandidates
		}
		if !admodel.InternalValidDiscoveryHost(record.Target) {
			return result, admodel.ErrInvalidResult
		}
		host := strings.ToLower(strings.TrimSuffix(record.Target, "."))
		key := net.JoinHostPort(host, strconv.FormatUint(uint64(record.Port), 10))
		index, exists := groups[key]
		if !exists {
			index = len(result.Candidates)
			groups[key] = index
			result.Candidates = append(
				result.Candidates,
				admodel.DNSControllerCandidate{DomainDNS: options.DomainDNS, SiteName: options.SiteName, Endpoint: admodel.Endpoint{Host: host, Port: record.Port}},
			)
		}
		result.Candidates[index].Records = append(
			result.Candidates[index].Records,
			admodel.DNSSRVRecord{Target: record.Target, Port: record.Port, Priority: record.Priority, Weight: record.Weight},
		)
	}
	for index := range result.Candidates {
		if cause := InternalConnectionContextCause(bounded); cause != nil {
			return result, cause
		}
		candidate := &result.Candidates[index]
		absolute := candidate.Endpoint.Host + "."
		canonical, cnameErr := internalDiscoveryLookup(bounded, func() (string, error) { return resolver.LookupCNAME(bounded, absolute) })
		if cnameErr != nil {
			return result, errors.Join(admodel.ErrIncompleteResult, cnameErr)
		}
		// RFC2782 requires the target itself to have address records, not to be
		// an alias. A hostname suffix is never used as domain-membership proof.
		if !strings.EqualFold(canonical, absolute) {
			return result, fmt.Errorf("%w: SRV target is a DNS alias", admodel.ErrInvalidResult)
		}
		if cause := InternalConnectionContextCause(bounded); cause != nil {
			return result, cause
		}
		addresses, addressErr := internalDiscoveryLookup(bounded, func() ([]net.IPAddr, error) { return resolver.LookupIPAddr(bounded, absolute) })
		if addressErr != nil {
			return result, errors.Join(admodel.ErrIncompleteResult, addressErr)
		}
		if len(addresses) == 0 {
			return result, admodel.ErrDiscoveryNoCandidates
		}
		if len(addresses) > internalDiscoveryDNSRecordLimit {
			return result, admodel.ErrIncompleteResult
		}
		seen := make(map[netip.Addr]bool, len(addresses))
		for _, address := range addresses {
			value, valid := netip.AddrFromSlice(address.IP)
			if !valid || address.Zone != "" || value.IsUnspecified() || value.IsMulticast() {
				return result, admodel.ErrInvalidResult
			}
			value = value.Unmap()
			if !seen[value] {
				candidate.Addresses = append(candidate.Addresses, value)
				seen[value] = true
			}
		}
	}
	return result, nil
}

func internalDiscoveryRecords(records []*net.SRV) []admodel.DNSSRVRecord {
	var copied []admodel.DNSSRVRecord
	for _, record := range records[:min(len(records), internalDiscoveryDNSRecordLimit)] {
		if record != nil {
			copied = append(copied, admodel.DNSSRVRecord{Target: record.Target, Port: record.Port, Priority: record.Priority, Weight: record.Weight})
		}
	}
	return copied
}
