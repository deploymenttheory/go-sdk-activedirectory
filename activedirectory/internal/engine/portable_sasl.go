package engine

import (
	"fmt"

	ldap "github.com/deploymenttheory/go-sdk-activedirectory/3rd_party/ldap/v3"
	admodel "github.com/deploymenttheory/go-sdk-activedirectory/activedirectory/internal/model"
)

// internalPortableSASLMode translates the required policy, not an observation.
// Public model values differ from the library values, especially none and seal.
func internalPortableSASLMode(config admodel.Config) (ldap.SASLSecurityMode, error) {
	if config.Authentication != admodel.AuthenticationKerberos || config.Transport > admodel.TransportStartTLS {
		return 0, fmt.Errorf("%w: Kerberos SASL policy requires a known transport", admodel.ErrInvalidConfig)
	}
	switch config.SASLProtection {
	case admodel.SASLProtectionDefault:
		if config.Transport == admodel.TransportLDAP {
			return ldap.SASLSecuritySeal, nil
		}
		return ldap.SASLSecurityNone, nil
	case admodel.SASLProtectionNone:
		if config.Transport == admodel.TransportLDAP {
			return 0, fmt.Errorf("%w: plaintext Kerberos requires signing or sealing", admodel.ErrInvalidConfig)
		}
		return ldap.SASLSecurityNone, nil
	case admodel.SASLProtectionSign:
		return ldap.SASLSecuritySign, nil
	case admodel.SASLProtectionSeal:
		return ldap.SASLSecuritySeal, nil
	default:
		return 0, fmt.Errorf("%w: unknown required SASL protection", admodel.ErrInvalidConfig)
	}
}

// internalPortableObservedSASL maps a verified installed library layer. Callers
// must obtain it after final server acceptance and connection-layer installation.
func internalPortableObservedSASL(mode ldap.SASLSecurityMode) (admodel.SASLProtection, error) {
	switch mode {
	case ldap.SASLSecurityNone:
		return admodel.SASLProtectionNone, nil
	case ldap.SASLSecuritySign:
		return admodel.SASLProtectionSign, nil
	case ldap.SASLSecuritySeal:
		return admodel.SASLProtectionSeal, nil
	default:
		return admodel.SASLProtectionDefault, fmt.Errorf("%w: unknown observed SASL layer", admodel.ErrInvalidResult)
	}
}
