package engine

import (
	"fmt"

	admodel "github.com/deploymenttheory/go-sdk-activedirectory/activedirectory/internal/model"
)

func internalReplicationAnchorPrincipals(config admodel.Config, selection admodel.ReplicationSelection) error {
	if selection.ServicePrincipals == nil {
		return nil
	}
	if config.Backend != admodel.BackendPortable || config.Authentication != admodel.AuthenticationKerberos {
		return fmt.Errorf("%w: explicit replication service identities require portable Kerberos", admodel.ErrInvalidConfig)
	}
	if anchor, ok := admodel.InternalReplicationSelectedPrincipals(selection, config.Endpoint.Host); ok && anchor.LDAP != config.Kerberos.SPN {
		return fmt.Errorf("%w: anchor LDAP principal must agree with Config.Kerberos.SPN", admodel.ErrInvalidConfig)
	}
	return nil
}

func internalReplicationServerTargets(config admodel.Config, selection admodel.ReplicationSelection) ([]admodel.Endpoint, error) {
	servers := selection.Servers
	if len(servers) == 0 {
		servers = []admodel.Endpoint{config.Endpoint}
	}
	var result []admodel.Endpoint
	for _, endpoint := range servers {
		candidate := config
		candidate.Endpoint = endpoint
		if config.Backend == admodel.BackendPortable && selection.ServicePrincipals != nil {
			if _, found := admodel.InternalReplicationSelectedPrincipals(selection, endpoint.Host); !found {
				if !admodel.InternalValidServerHost(endpoint.Host) {
					return nil, admodel.ErrInvalidReplicationQuery
				}
				if endpoint.Port == 0 {
					endpoint.Port = config.Endpoint.Port
				}
				result = admodel.InternalAppendReplicationEndpoint(result, endpoint)
				continue
			}
			var err error
			candidate, _, err = admodel.InternalReplicationTargetConfig(config, selection, endpoint, false)
			if err != nil {
				return nil, err
			}
		}
		candidate, err := admodel.InternalConfigNormalized(candidate)
		if err != nil {
			return nil, err
		}
		result = admodel.InternalAppendReplicationEndpoint(result, candidate.Endpoint)
	}
	return result, nil
}
