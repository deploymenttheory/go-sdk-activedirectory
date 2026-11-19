package rpcdce

import (
	"fmt"
	"io"
	"log/slog"
)

const redactedContext = "RPC Kerberos context [REDACTED]"

func (*Client) String() string                       { return redactedContext }
func (*Client) GoString() string                     { return redactedContext }
func (*Client) Format(state fmt.State, _ rune)       { _, _ = io.WriteString(state, redactedContext) }
func (*Client) MarshalJSON() ([]byte, error)         { return []byte(`{"redacted":true}`), nil }
func (*Client) LogValue() slog.Value                 { return slog.StringValue(redactedContext) }
func (RecordContext) String() string                 { return redactedContext }
func (RecordContext) GoString() string               { return redactedContext }
func (RecordContext) Format(state fmt.State, _ rune) { _, _ = io.WriteString(state, redactedContext) }
func (RecordContext) MarshalJSON() ([]byte, error)   { return []byte(`{"redacted":true}`), nil }
func (RecordContext) LogValue() slog.Value           { return slog.StringValue(redactedContext) }
