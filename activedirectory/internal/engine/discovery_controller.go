package engine

import (
	"context"
	"crypto/tls"
	"errors"
	"strings"

	admodel "github.com/deploymenttheory/go-sdk-activedirectory/activedirectory/internal/model"
)

// DialDomainController authenticates exactly the configured portable endpoint,
// then verifies its explicit domain/controller selection on the same session.
// Failed validation closes the new client and retains partial observations.
func DialDomainController(ctx context.Context, config admodel.Config, selection admodel.DomainControllerSelection) (*Client, admodel.AuthenticatedController, error) {
	return InternalDialDomainController(ctx, config, selection, Dial)
}

// InternalDialDomainController composes owned wire clients in tests. Production
// always supplies Dial; no public authentication hook or mutable factory exists.
func InternalDialDomainController(
	ctx context.Context,
	config admodel.Config,
	selection admodel.DomainControllerSelection,
	dial func(context.Context, admodel.Config) (*Client, error),
) (*Client, admodel.AuthenticatedController, error) {
	var result admodel.AuthenticatedController
	config, err := admodel.InternalConfigNormalized(config)
	if err != nil {
		return nil, result, err
	}
	selection, err = internalDiscoverySelection(config, selection)
	if err != nil {
		return nil, result, err
	}
	result.Requested = selection
	if dial == nil {
		return nil, result, admodel.ErrInvalidConfig
	}
	bounded, cancel := context.WithTimeout(ctx, config.Timeout)
	defer cancel()
	if cause := InternalConnectionContextCause(bounded); cause != nil {
		return nil, result, cause
	}
	connection, err := dial(bounded, config)
	if err != nil {
		if connection != nil {
			err = errors.Join(err, connection.Close())
		}
		return nil, result, err
	}
	if connection == nil {
		return nil, result, admodel.ErrInvalidResult
	}
	result, err = connection.Directory().ValidateDomainController(bounded, selection)
	if err = errors.Join(err, InternalConnectionContextCause(bounded)); err != nil || !result.Complete {
		result.Complete = false
		result.Observation.Complete = false
		return nil, result, errors.Join(err, admodel.ErrIncompleteResult, connection.Close())
	}
	return connection, result, nil
}

func internalDiscoverySelection(config admodel.Config, selection admodel.DomainControllerSelection) (admodel.DomainControllerSelection, error) {
	selection, err := admodel.InternalDomainControllerSelection(selection, config.Endpoint)
	if err != nil {
		return selection, err
	}
	if config.Backend != admodel.BackendPortable || config.Authentication != admodel.AuthenticationSimple && config.Authentication != admodel.AuthenticationKerberos {
		return selection, admodel.ErrInvalidConfig
	}
	if config.Partition != "" && !admodel.InternalTopologySameDN(config.Partition, internalDiscoveryDomainDN(selection.DomainDNS)) {
		return selection, admodel.ErrInvalidDiscovery
	}
	if config.Kerberos != nil {
		parts := strings.Split(config.Kerberos.SPN, "/")
		if len(parts) != 2 && len(parts) != 3 || !strings.EqualFold(parts[0], "ldap") ||
			!strings.EqualFold(strings.TrimSuffix(parts[1], "."), strings.TrimSuffix(config.Endpoint.Host, ".")) {
			return selection, admodel.ErrInvalidDiscovery
		}
	}
	return selection, nil
}

// ValidateDomainController verifies an explicit domain/DC identity through this
// already authenticated portable client. It observes actual protection before
// identity reads, follows no referral and never discovers/rebinds another host.
// The caller owns the client even when this validation returns partial data.
func (d *DirectoryService) ValidateDomainController(ctx context.Context, selection admodel.DomainControllerSelection) (result admodel.AuthenticatedController, err error) {
	if d == nil || d.client == nil || d.client.session == nil {
		return result, admodel.ErrClosed
	}
	selection, err = internalDiscoverySelection(d.client.config, selection)
	if err != nil {
		return result, err
	}
	result.Requested = selection
	result.Observation.Source = d.client.config.Endpoint
	bounded, cancel := context.WithTimeout(ctx, d.client.config.Timeout)
	defer cancel()
	defer func() {
		err = errors.Join(err, InternalConnectionContextCause(bounded))
		result.Complete = err == nil && result.Observation.Complete
		if err != nil {
			result.Observation.Complete = false
		}
	}()
	result.Protection, err = d.client.Protection(bounded)
	if err != nil {
		return result, &admodel.DirectoryReadError{Operation: "ValidateDomainController", Cause: err}
	}
	if !internalDiscoveryProtection(d.client.config, result.Protection) {
		return result, &admodel.DirectoryReadError{Operation: "ValidateDomainController", Cause: admodel.ErrInvalidResult}
	}
	read, err := InternalDirectoryServiceBegin(d, bounded, "ValidateDomainController", true)
	if err != nil {
		return result, err
	}
	defer func() { err = read.InternalFinish(&result.Observation) }()
	if read.InternalReady {
		internalValidateDiscoveryIdentity(read, selection, &result)
	}
	return result, nil
}

func internalDiscoveryProtection(config admodel.Config, observed admodel.SessionProtection) bool {
	if observed.Backend != admodel.BackendPortable || observed.Authentication != config.Authentication || observed.Transport != config.Transport || !observed.Complete {
		return false
	}
	if config.Authentication == admodel.AuthenticationKerberos && !observed.MutualAuthentication {
		return false
	}
	if config.Transport != admodel.TransportLDAP {
		return observed.TLSVerified && observed.TLSVersion >= tls.VersionTLS12 && observed.TLSCipherSuite != 0 && observed.CipherBits >= 128 &&
			(config.Authentication != admodel.AuthenticationKerberos || observed.ChannelBindingSent)
	}
	mode := config.SASLProtection
	if mode == admodel.SASLProtectionDefault {
		mode = admodel.SASLProtectionSeal
	}
	return observed.SASLProtection == mode && (mode == admodel.SASLProtectionSign || mode == admodel.SASLProtectionSeal && observed.SASLCipherBits >= 128)
}

func internalDiscoveryDomainDN(domain string) string {
	return "DC=" + strings.Join(strings.Split(domain, "."), ",DC=")
}
