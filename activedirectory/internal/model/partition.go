package model

import (
	"errors"
)

var (
	ErrNoDefaultPartition = errors.New(
		"directory has no usable default naming context; set Config.Partition explicitly",
	)
	ErrNotNamingContext = errors.New("selected object is not a naming-context root")
)

// Partition is the naming-context root returned by the configured server.
// Attributes owns copied raw values. On error the result may be partial.
type Partition struct {
	DistinguishedName string
	InstanceType      uint32
	Attributes        map[string][][]byte
}
