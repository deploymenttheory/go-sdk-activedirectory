package messages

import "fmt"

// Formatting and JSON hooks protect these credential containers, including
// nested/numeric fmt verbs. Direct field/reflection access is not a secure
// serialization boundary; callers must still own and retire decrypted keys.
func (KRBCred) String() string                      { return "KRBCred{redacted}" }
func (KRBCred) GoString() string                    { return "KRBCred{redacted}" }
func (KRBCred) MarshalJSON() ([]byte, error)        { return []byte(`{"redacted":true}`), nil }
func (EncKrbCredPart) String() string               { return "EncKrbCredPart{redacted}" }
func (EncKrbCredPart) GoString() string             { return "EncKrbCredPart{redacted}" }
func (EncKrbCredPart) MarshalJSON() ([]byte, error) { return []byte(`{"redacted":true}`), nil }
func (KrbCredInfo) String() string                  { return "KrbCredInfo{redacted}" }
func (KrbCredInfo) GoString() string                { return "KrbCredInfo{redacted}" }
func (KrbCredInfo) MarshalJSON() ([]byte, error)    { return []byte(`{"redacted":true}`), nil }

func (KRBCred) Format(state fmt.State, _ rune) {
	_, _ = state.Write([]byte("KRBCred{redacted}"))
}

func (EncKrbCredPart) Format(state fmt.State, _ rune) {
	_, _ = state.Write([]byte("EncKrbCredPart{redacted}"))
}

func (KrbCredInfo) Format(state fmt.State, _ rune) {
	_, _ = state.Write([]byte("KrbCredInfo{redacted}"))
}
