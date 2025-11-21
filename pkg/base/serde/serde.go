package serde

import (
	"reflect"

	"github.com/bronlabs/bron-crypto/pkg/base/errs2"
	"github.com/fxamacker/cbor/v2"
)

const (
	DefaultMaxArrayElements = 131072
	DefaultMaxMapPairs      = 131072
	DefaultMaxNestedLevels  = 32
)

var (
	enc cbor.EncMode
	dec cbor.DecMode

	// Global TagSet for type registration.
	tags = cbor.NewTagSet()

	ErrSerialisation   = errs2.New("serialisation error")
	ErrDeserialisation = errs2.New("deserialisation error")
)

// Register registers the concrete type parameter T with a fixed CBOR tag.
func Register[T any](tag uint64) {
	var zero T
	typ := reflect.TypeOf(zero)
	if typ == nil {
		panic("serde.RegisterWithTag: nil type for generic parameter T")
	}
	if err := tags.Add(
		cbor.TagOptions{DecTag: cbor.DecTagOptional, EncTag: cbor.EncTagRequired},
		typ,
		tag,
	); err != nil {
		panic(err)
	}
	// ensure enc/dec modes see the new tag
	updateModes()
}

func init() {
	updateModes()
}

func updateModes() {
	var err error
	enc, err = cbor.CoreDetEncOptions().EncModeWithTags(tags)
	if err != nil {
		panic(err)
	}
	decOptions := cbor.DecOptions{
		DupMapKey:                cbor.DupMapKeyEnforcedAPF,
		TimeTag:                  cbor.DecTagRequired,
		MaxNestedLevels:          DefaultMaxNestedLevels,
		MaxArrayElements:         DefaultMaxArrayElements,
		MaxMapPairs:              DefaultMaxMapPairs,
		IndefLength:              cbor.IndefLengthForbidden,
		TagsMd:                   cbor.TagsAllowed,       // default
		IntDec:                   cbor.IntDecConvertNone, // default
		MapKeyByteString:         cbor.MapKeyByteStringForbidden,
		ExtraReturnErrors:        cbor.ExtraDecErrorUnknownField,
		UTF8:                     cbor.UTF8RejectInvalid, // default
		FieldNameMatching:        cbor.FieldNameMatchingCaseSensitive,
		BigIntDec:                cbor.BigIntDecodePointer,
		ByteStringToString:       cbor.ByteStringToStringForbidden,  // default
		FieldNameByteString:      cbor.FieldNameByteStringForbidden, // default
		UnrecognizedTagToAny:     cbor.UnrecognizedTagContentToAny,
		TimeTagToAny:             cbor.TimeTagToRFC3339,
		NaN:                      cbor.NaNDecodeForbidden,
		Inf:                      cbor.InfDecodeForbidden,
		ByteStringToTime:         cbor.ByteStringToTimeForbidden,
		ByteStringExpectedFormat: cbor.ByteStringExpectedFormatNone, // default
		BignumTag:                cbor.BignumTagForbidden,
		BinaryUnmarshaler:        cbor.BinaryUnmarshalerByteString,
		TextUnmarshaler:          cbor.TextUnmarshalerNone,
	}
	dec, err = decOptions.DecModeWithTags(tags)
	if err != nil {
		panic(err)
	}
}

// MarshalCBOR serialises the given value to CBOR format.
func MarshalCBOR[T any](t T) ([]byte, error) {
	data, err := enc.Marshal(t)
	if err != nil {
		return nil, ErrSerialisation
	}
	return data, nil
}

// MarshalCBORTagged serialises the given value to CBOR format with the specified tag.
func MarshalCBORTagged[T any](t T, tag uint64) ([]byte, error) {
	wrapped := cbor.Tag{
		Number:  tag,
		Content: t,
	}
	data, err := enc.Marshal(wrapped)
	if err != nil {
		return nil, ErrSerialisation
	}
	return data, nil
}

// UnmarshalCBOR deserialises the given CBOR data into the specified type.
func UnmarshalCBOR[T any](data []byte) (T, error) {
	var t T
	err := dec.Unmarshal(data, &t)
	if err != nil {
		return t, ErrDeserialisation
	}
	return t, nil
}
