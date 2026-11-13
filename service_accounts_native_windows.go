//go:build windows && (amd64 || arm64)

package activedirectory

import "github.com/deploymenttheory/go-sdk-activedirectory/conditions"

func (*ldapSession) newDirectoryDescriptor(sddl string) ([]byte, error) {
	return conditions.DescriptorBytes(sddl)
}
