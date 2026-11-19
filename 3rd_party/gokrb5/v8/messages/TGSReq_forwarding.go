package messages

import (
	"github.com/deploymenttheory/go-sdk-activedirectory/3rd_party/gokrb5/v8/config"
	"github.com/deploymenttheory/go-sdk-activedirectory/3rd_party/gokrb5/v8/iana/flags"
	"github.com/deploymenttheory/go-sdk-activedirectory/3rd_party/gokrb5/v8/types"
)

// NewForwardedTGSReq requests a fresh forwardable/forwarded TGT for the explicit
// realm. Options precede setPAData so the authenticator checksum covers them.
// The existing TGT is never modified or repackaged as a forwarded credential.
func NewForwardedTGSReq(cname types.PrincipalName, realm string, cfg *config.Config, tgt Ticket, key types.EncryptionKey) (TGSReq, error) {
	service := types.NewPrincipalName(2, "krbtgt/"+realm)
	request, err := tgsReq(cname, service, realm, false, cfg)
	if err != nil {
		return request, err
	}
	types.SetFlag(&request.ReqBody.KDCOptions, flags.Forwarded)
	types.SetFlag(&request.ReqBody.KDCOptions, flags.Forwardable)
	err = request.setPAData(tgt, key)
	return request, err
}
