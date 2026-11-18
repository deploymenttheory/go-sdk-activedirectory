package gssapi

import (
	"crypto"
	"crypto/md5" // #nosec G501 -- RFC 1964 section 1.1.1 requires MD5 of the GSS channel-binding structure.
	"crypto/x509"
	"encoding/binary"
	"fmt"
	"math"
)

// CertificateHash computes the RFC 5929 "tls-server-end-point" hash of the
// server's TLS certificate. The hash algorithm is selected based on the
// certificate's signature algorithm: SHA256 is used for MD5 and SHA1 (as
// required by the RFC), otherwise the algorithm matching the signature is used.
// Returns nil if the signature algorithm is not supported.
func CertificateHash(cert *x509.Certificate) []byte {
	return calculatePortableCertificateHash(cert)
}

// ComputeChannelBindingHash builds a gss_channel_bindings_struct with
// "tls-server-end-point:" + certHash as application data, serializes it
// per RFC 2744, and returns the MD5 hash of the serialized form.
// The resulting 16-byte hash is used as:
//   - MsvAvChannelBindings in NTLM Authenticate (MS-NLMP)
//   - Bnd field in Kerberos authenticator checksum (RFC 1964 §1.1.1)
func ComputeChannelBindingHash(certHash []byte) ([16]byte, error) {
	if int64(len(certHash)) > math.MaxUint32-int64(len("tls-server-end-point:")) {
		return [16]byte{}, fmt.Errorf("ldap: channel-binding input exceeds the GSS length field")
	}
	appData := append([]byte("tls-server-end-point:"), certHash...)

	// Serialize gss_channel_bindings_struct:
	//   initiator_addrtype  uint32 LE = 0
	//   initiator_address   length uint32 LE = 0 (no value bytes)
	//   acceptor_addrtype   uint32 LE = 0
	//   acceptor_address    length uint32 LE = 0 (no value bytes)
	//   application_data    length uint32 LE = len(appData)
	//   application_data    value  = appData
	buf := make([]byte, 20+len(appData))
	// Check the actual derived length beside its narrowing conversion as well.
	length := int64(len(appData))
	if length < 0 || length > math.MaxUint32 {
		return [16]byte{}, fmt.Errorf("ldap: channel-binding data exceeds the GSS length field")
	}
	binary.LittleEndian.PutUint32(buf[16:20], uint32(length))
	copy(buf[20:], appData)

	return md5.Sum(buf), nil // #nosec G401 -- Protocol-mandated channel-binding digest, independent of the RFC 5929 certificate hash.
}

// calculateCertificateHash implements RFC 5929 certificate hash calculation.
// https://www.rfc-editor.org/rfc/rfc5929.html#section-4.1
func calculatePortableCertificateHash(cert *x509.Certificate) []byte {
	if cert == nil {
		return nil
	}
	var hashFunc crypto.Hash

	switch cert.SignatureAlgorithm {
	case x509.SHA256WithRSA,
		x509.SHA256WithRSAPSS,
		x509.ECDSAWithSHA256,
		x509.DSAWithSHA256:

		hashFunc = crypto.SHA256
	case x509.SHA384WithRSA,
		x509.SHA384WithRSAPSS,
		x509.ECDSAWithSHA384:

		hashFunc = crypto.SHA384
	case x509.SHA512WithRSA,
		x509.SHA512WithRSAPSS,
		x509.ECDSAWithSHA512:

		hashFunc = crypto.SHA512
	case x509.MD5WithRSA,
		x509.SHA1WithRSA,
		x509.ECDSAWithSHA1,
		x509.DSAWithSHA1:

		hashFunc = crypto.SHA256
	default:
		return nil
	}

	hasher := hashFunc.New()

	// Important to hash cert in DER format.
	hasher.Write(cert.Raw)
	return hasher.Sum(nil)
}
