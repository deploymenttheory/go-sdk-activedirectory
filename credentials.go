package activedirectory

import (
	"bytes"
	"fmt"
	"math"
	"unicode/utf8"
)

// Credentials supplies an explicit identity for Negotiate. A nil Config.Credentials
// uses the current Windows identity. A nonnil value always attempts the supplied
// identity, including when Password is empty; it never falls back to the caller.
//
// Password is UTF-8 owned by the caller. Do not mutate any fields during Dial.
// The SDK creates temporary Unicode buffers, erases those buffers after bind,
// and does not retain Credentials in the returned Client. The caller remains
// responsible for clearing its own password bytes. No erasure guarantee applies
// to caller copies or storage maintained internally by Windows.
type Credentials struct {
	Username string
	Domain   string
	Password []byte `json:"-"`
}

// String and GoString redact the entire identity in ordinary Go formatting.
func (Credentials) String() string   { return "Credentials{redacted}" }
func (Credentials) GoString() string { return "Credentials{redacted}" }

// MarshalJSON excludes credential material from structured logging.
func (Credentials) MarshalJSON() ([]byte, error) { return []byte(`{"redacted":true}`), nil }

// MarshalText excludes credential material from text serialization.
func (Credentials) MarshalText() ([]byte, error) { return []byte("Credentials{redacted}"), nil }

func (c *Credentials) validate() error {
	if c == nil {
		return nil
	}
	for _, field := range []struct {
		name  string
		value []byte
	}{
		{"username", []byte(c.Username)}, {"domain", []byte(c.Domain)}, {"password", c.Password},
	} {
		if !utf8.Valid(field.value) || bytes.IndexByte(field.value, 0) >= 0 || utf16Units(field.value) > math.MaxUint32 {
			return fmt.Errorf("%w: credential %s must be valid UTF-8 without NUL and fit the native character count", ErrInvalidConfig, field.name)
		}
	}
	if c.Username == "" {
		return fmt.Errorf("%w: explicit credentials require a username", ErrInvalidConfig)
	}
	return nil
}

func utf16Units(value []byte) uint64 {
	var units uint64
	for len(value) != 0 {
		r, size := utf8.DecodeRune(value)
		units++
		if r > 0xffff {
			units++
		}
		value = value[size:]
	}
	return units
}
