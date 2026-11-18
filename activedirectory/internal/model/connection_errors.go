package model

import "errors"

// ErrConnection identifies an interrupted or failed transport without inventing
// an LDAP server status. A possibly submitted write must also retain its existing
// uncertainty marker; ClassUncertain then dominates ClassTransport.
var ErrConnection = errors.New("directory connection failed or was interrupted")
