//go:build !windows || (!amd64 && !arm64)

package conditions

func Compile(ace ACE) (string, error)              { return "", ErrUnsupported }
func NormalizeSDDL(input string) (string, error)   { return "", ErrUnsupported }
func DescriptorBytes(input string) ([]byte, error) { return nil, ErrUnsupported }
