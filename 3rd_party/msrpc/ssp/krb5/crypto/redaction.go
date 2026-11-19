package crypto

import (
	"fmt"
	"io"
	"log/slog"
)

const redactedRecord = "RPC Kerberos record key [REDACTED]"

func (CipherSetting) String() string                   { return redactedRecord }
func (CipherSetting) GoString() string                 { return redactedRecord }
func (CipherSetting) Format(state fmt.State, _ rune)   { _, _ = io.WriteString(state, redactedRecord) }
func (CipherSetting) MarshalJSON() ([]byte, error)     { return []byte(`{"redacted":true}`), nil }
func (CipherSetting) LogValue() slog.Value             { return slog.StringValue(redactedRecord) }
func (*AESCTSHMACSHA1) String() string                 { return redactedRecord }
func (*AESCTSHMACSHA1) GoString() string               { return redactedRecord }
func (*AESCTSHMACSHA1) Format(state fmt.State, _ rune) { _, _ = io.WriteString(state, redactedRecord) }
func (*AESCTSHMACSHA1) MarshalJSON() ([]byte, error)   { return []byte(`{"redacted":true}`), nil }
func (*AESCTSHMACSHA1) LogValue() slog.Value           { return slog.StringValue(redactedRecord) }
