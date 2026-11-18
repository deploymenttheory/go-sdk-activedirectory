package acceptance

import (
	"errors"
	"testing"

	"github.com/deploymenttheory/go-sdk-activedirectory/3rd_party/gokrb5/v8/iana/errorcode"
	adengine "github.com/deploymenttheory/go-sdk-activedirectory/activedirectory/internal/engine"
	admodel "github.com/deploymenttheory/go-sdk-activedirectory/activedirectory/internal/model"
)

func TestPortableKerberosRefusalPreservesProtocolCodeWithoutAuthenticationOrRealmFallback(t *testing.T) {
	for _, test := range []struct {
		name     string
		code     int32
		requests int32
	}{
		{"wrong-password", errorcode.KDC_ERR_PREAUTH_FAILED, 2},
		{"unknown-service", errorcode.KDC_ERR_S_PRINCIPAL_UNKNOWN, 3},
		{"foreign-realm", errorcode.KDC_ERR_WRONG_REALM, 1},
	} {
		t.Run(test.name, func(t *testing.T) {
			certificate, roots := portableKerberosTLSCertificate(t)
			kdc := newPortableKerberosKDC(t, func(k *portableKerberosKDC) {
				if test.name == "foreign-realm" {
					k.refuseAS = test.code
				}
				if test.name == "unknown-service" {
					k.refuseTGS = test.code
				}
			})
			wire := newPortableLDAPWire(t, admodel.TransportLDAPS, certificate)
			options := portableTLSConfig(admodel.TransportLDAPS, roots)
			options.Authentication, options.Credentials = admodel.AuthenticationKerberos, nil
			options.Kerberos = portableKerberosSource(t, kdc, admodel.KerberosPassword, false)
			if test.name == "wrong-password" {
				options.Kerberos.Password = []byte("different-unit-fixture-password")
			}
			session, err := adengine.InternalDialPortableWithDial(t.Context(), options, portableKerberosDialer{ldap: wire, kdc: kdc})
			var kerberos *admodel.KerberosError
			var ldap *admodel.LDAPError
			if session != nil || !errors.As(err, &kerberos) || kerberos.Code != test.code || errors.As(err, &ldap) || admodel.Classify(err) != admodel.ClassDenied {
				t.Fatalf("KDC refusal lost its protocol identity or invented an LDAP status: %v", err)
			}
			wire.wait(t)
			if kdc.requests.Load() != test.requests || wire.requests.Load() != 0 {
				t.Fatalf("refused Kerberos authentication retried: KDC=%d LDAP=%d", kdc.requests.Load(), wire.requests.Load())
			}
		})
	}
}
