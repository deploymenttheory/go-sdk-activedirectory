//go:build windows && (amd64 || arm64)

package engine

import "github.com/deploymenttheory/go-sdk-activedirectory/conditions"

func (*InternalLdapSession) InternalNewDirectoryDescriptor(sddl string) ([]byte, error) {
	return conditions.DescriptorBytes(sddl)
}
