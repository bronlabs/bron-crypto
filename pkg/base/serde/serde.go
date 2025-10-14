package serde

import (
	"github.com/fxamacker/cbor/v2"
)

const (
	DefaultMaxArrayElements = 131072
	DefaultMaxMapPairs      = 131072
	DefaultMaxNestedLevels  = 32
)

var (
	encMode cbor.EncMode
	decMode cbor.DecMode
)

func init() {
	enc, err := cbor.CoreDetEncOptions().EncMode()
	if err != nil {
		panic(err)
	}
	encMode = enc

	decOptions := cbor.DecOptions{
		DupMapKey:                cbor.DupMapKeyEnforcedAPF,
		TimeTag:                  cbor.DecTagRequired,
		MaxNestedLevels:          DefaultMaxNestedLevels,
		MaxArrayElements:         DefaultMaxArrayElements,
		MaxMapPairs:              DefaultMaxMapPairs,
		IndefLength:              cbor.IndefLengthForbidden,
		TagsMd:                   cbor.TagsAllowed,       //default
		IntDec:                   cbor.IntDecConvertNone, //default
		MapKeyByteString:         cbor.MapKeyByteStringForbidden,
		ExtraReturnErrors:        cbor.ExtraDecErrorUnknownField,
		UTF8:                     cbor.UTF8RejectInvalid, //default
		FieldNameMatching:        cbor.FieldNameMatchingCaseSensitive,
		BigIntDec:                cbor.BigIntDecodePointer,
		ByteStringToString:       cbor.ByteStringToStringForbidden,  //default
		FieldNameByteString:      cbor.FieldNameByteStringForbidden, //default
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
	dec, err := decOptions.DecMode()
	if err != nil {
		panic(err)
	}
	decMode = dec
}

func MarshalCBOR[T any](t T) ([]byte, error) {
	return encMode.Marshal(t)
}

func UnmarshalCBOR[T any](data []byte) (T, error) {
	var t T
	err := decMode.Unmarshal(data, &t)
	return t, err
}
