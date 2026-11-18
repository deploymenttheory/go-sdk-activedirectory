package model

import "fmt"

func InternalBackendConfigValidate(c Config) error {
	if c.Backend > BackendPortable || c.SASLProtection > SASLProtectionSeal {
		return fmt.Errorf("%w: unknown backend or SASL protection policy", ErrInvalidConfig)
	}
	if c.Authentication == AuthenticationKerberos {
		if c.Credentials != nil {
			return fmt.Errorf("%w: Kerberos and bind credentials cannot be combined", ErrInvalidConfig)
		}
		if err := InternalKerberosCredentialsValidate(c.Kerberos, c.Endpoint); err != nil {
			return err
		}
	} else if c.Kerberos != nil {
		return fmt.Errorf("%w: Kerberos credentials require Kerberos authentication", ErrInvalidConfig)
	}
	if c.SASLProtection != SASLProtectionDefault && c.Authentication != AuthenticationKerberos {
		return fmt.Errorf("%w: explicit SASL protection requires Kerberos authentication", ErrInvalidConfig)
	}
	if c.Transport == TransportLDAP && c.SASLProtection == SASLProtectionNone {
		return fmt.Errorf("%w: plaintext LDAP requires SASL signing or sealing", ErrInvalidConfig)
	}
	if c.TLS != nil && c.Transport == TransportLDAP {
		return fmt.Errorf("%w: TLS trust requires LDAPS or StartTLS", ErrInvalidConfig)
	}
	return nil
}
