package model

// InternalIdentityFields supports internal workflows and deliberately malformed test fixtures.
type InternalIdentityFields struct {
	Form   IdentityForm
	Value  string
	Binary []byte
}

func InternalIdentityFromFields(fields InternalIdentityFields) Identity {
	return Identity{form: fields.Form, value: fields.Value, binary: fields.Binary}
}

func InternalIdentityPointerFromFields(fields InternalIdentityFields) *Identity {
	return &Identity{form: fields.Form, value: fields.Value, binary: fields.Binary}
}
func InternalIdentityForm(value Identity) IdentityForm          { return value.form }
func InternalIdentityFormPointer(value *Identity) *IdentityForm { return &value.form }
func InternalIdentityValue(value Identity) string               { return value.value }
func InternalIdentityValuePointer(value *Identity) *string      { return &value.value }
func InternalIdentityBinary(value Identity) []byte              { return value.binary }
func InternalIdentityBinaryPointer(value *Identity) *[]byte     { return &value.binary }

// InternalRawValueFields supports internal workflows and deliberately malformed test fixtures.
type InternalRawValueFields struct {
	Data []byte
}

func InternalRawValueFromFields(fields InternalRawValueFields) RawValue {
	return RawValue{data: fields.Data}
}

func InternalRawValuePointerFromFields(fields InternalRawValueFields) *RawValue {
	return &RawValue{data: fields.Data}
}
func InternalRawValueData(value RawValue) []byte          { return value.data }
func InternalRawValueDataPointer(value *RawValue) *[]byte { return &value.data }

// InternalSIDFields supports internal workflows and deliberately malformed test fixtures.
type InternalSIDFields struct {
	Encoded string
}

func InternalSIDFromFields(fields InternalSIDFields) SID { return SID{encoded: fields.Encoded} }
func InternalSIDPointerFromFields(fields InternalSIDFields) *SID {
	return &SID{encoded: fields.Encoded}
}
func InternalSIDEncoded(value SID) string          { return value.encoded }
func InternalSIDEncodedPointer(value *SID) *string { return &value.encoded }

// InternalGeneralizedTimeFields supports internal workflows and deliberately malformed test fixtures.
type InternalGeneralizedTimeFields struct {
	Text string
}

func InternalGeneralizedTimeFromFields(fields InternalGeneralizedTimeFields) GeneralizedTime {
	return GeneralizedTime{text: fields.Text}
}

func InternalGeneralizedTimePointerFromFields(
	fields InternalGeneralizedTimeFields,
) *GeneralizedTime {
	return &GeneralizedTime{text: fields.Text}
}
func InternalGeneralizedTimeText(value GeneralizedTime) string          { return value.text }
func InternalGeneralizedTimeTextPointer(value *GeneralizedTime) *string { return &value.text }

// InternalFilterFields supports internal workflows and deliberately malformed test fixtures.
type InternalFilterFields struct {
	Encoded   string
	Depth     int
	Err       error
	Native    string
	NativeErr error
}

func InternalFilterFromFields(fields InternalFilterFields) Filter {
	return Filter{
		encoded:   fields.Encoded,
		depth:     fields.Depth,
		err:       fields.Err,
		native:    fields.Native,
		nativeErr: fields.NativeErr,
	}
}

func InternalFilterPointerFromFields(fields InternalFilterFields) *Filter {
	return &Filter{
		encoded:   fields.Encoded,
		depth:     fields.Depth,
		err:       fields.Err,
		native:    fields.Native,
		nativeErr: fields.NativeErr,
	}
}
func InternalFilterEncoded(value Filter) string           { return value.encoded }
func InternalFilterEncodedPointer(value *Filter) *string  { return &value.encoded }
func InternalFilterDepth(value Filter) int                { return value.depth }
func InternalFilterDepthPointer(value *Filter) *int       { return &value.depth }
func InternalFilterErr(value Filter) error                { return value.err }
func InternalFilterErrPointer(value *Filter) *error       { return &value.err }
func InternalFilterNative(value Filter) string            { return value.native }
func InternalFilterNativePointer(value *Filter) *string   { return &value.native }
func InternalFilterNativeErr(value Filter) error          { return value.nativeErr }
func InternalFilterNativeErrPointer(value *Filter) *error { return &value.nativeErr }

// InternalFilterValueFields supports internal workflows and deliberately malformed test fixtures.
type InternalFilterValueFields struct {
	Value  string
	Binary bool
	Set    bool
}

func InternalFilterValueFromFields(fields InternalFilterValueFields) FilterValue {
	return FilterValue{value: fields.Value, binary: fields.Binary, set: fields.Set}
}

func InternalFilterValuePointerFromFields(fields InternalFilterValueFields) *FilterValue {
	return &FilterValue{value: fields.Value, binary: fields.Binary, set: fields.Set}
}
func InternalFilterValueValue(value FilterValue) string          { return value.value }
func InternalFilterValueValuePointer(value *FilterValue) *string { return &value.value }
func InternalFilterValueBinary(value FilterValue) bool           { return value.binary }
func InternalFilterValueBinaryPointer(value *FilterValue) *bool  { return &value.binary }
func InternalFilterValueSet(value FilterValue) bool              { return value.set }
func InternalFilterValueSetPointer(value *FilterValue) *bool     { return &value.set }
