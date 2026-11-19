package model

import "errors"

// ErrReplicationPermission identifies an actual authenticated replication RPC
// access refusal. An unprotected bind rejection does not establish this fact.
var ErrReplicationPermission = errors.New("replication diagnostics access was refused")
