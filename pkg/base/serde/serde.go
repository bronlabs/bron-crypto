package serde

import (
	"github.com/bronlabs/bron-crypto/pkg/base/errs"
	"github.com/fxamacker/cbor/v2"
)

const (
	DefaultMaxArrayElements = 131072
	MinMaxArrayElements     = 16
	MaxMaxArrayElements     = 2147483647

	DefaultMaxMapPairs = 131072
	MinMaxMapPairs     = 16
	MaxMaxMapPairs     = 2147483647

	DefaultMaxNestedLevels = 32
	MinMaxNestedLevels     = 4
	MaxMaxNestedLevels     = 65535
)

// TODO: add the init

func MarshalCBOR[T any](t T) ([]byte, error) {
	enc, err := cbor.CoreDetEncOptions().EncMode()
	if err != nil {
		return nil, errs.WrapSerialisation(err, "cannot marshal to CBOR")
	}
	return enc.Marshal(t)
}

func UnmarshalCBOR[T any](data []byte) (T, error) {
	var t T
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
		return t, errs.WrapSerialisation(err, "cannot unmarshal from CBOR")
	}
	err = dec.Unmarshal(data, &t)
	return t, err
}
