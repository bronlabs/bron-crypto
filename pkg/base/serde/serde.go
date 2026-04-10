package serde

import (
	"reflect"
	"sync"

	"github.com/fxamacker/cbor/v2"

	"github.com/bronlabs/errs-go/errs"
)

const (
	DefaultMaxArrayElements = 131072
	DefaultMaxMapPairs      = 131072
	DefaultMaxNestedLevels  = 32
)

var (
	mu sync.RWMutex

	enc cbor.EncMode
	dec cbor.DecMode

	// Global TagSet for type registration.
	tags = cbor.NewTagSet()
)

// Register registers the concrete type parameter T with a fixed CBOR tag.
func Register[T any](tag uint64) {
	var zero T
	typ := reflect.TypeOf(zero)
	if typ == nil {
		panic("serde.RegisterWithTag: nil type for generic parameter T")
	}
	mu.Lock()
	defer mu.Unlock()
	if err := tags.Add(
		cbor.TagOptions{DecTag: cbor.DecTagRequired, EncTag: cbor.EncTagRequired},
		typ,
		tag,
	); err != nil {
		panic(err)
	}
	// ensure enc/dec modes see the new tag
	updateModes()
}

func init() { //nolint:gochecknoinits // necessary for setup
	updateModes()
}

func updateModes() {
	var err error
	enc, err = cbor.CoreDetEncOptions().EncModeWithTags(tags)
	if err != nil {
		panic(err)
	}
	decOptions := cbor.DecOptions{ //nolint:exhaustruct // readability
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
	mu.RLock()
	mode := enc
	mu.RUnlock()
	data, err := mode.Marshal(t)
	if err != nil {
		return nil, errs.Wrap(err).WithMessage("serialisation error")
	}
	return data, nil
}

// MarshalCBORTagged serialises the given value to CBOR format wrapped in an
// explicit outer tag.
//
// This helper is intended for custom MarshalCBOR implementations that encode a
// DTO payload instead of the registered concrete Go type itself. In that case
// Register alone is not enough to emit the desired outer type tag, because the
// encoder only sees the DTO value. MarshalCBORTagged should therefore be used
// by such custom marshalers to wrap the DTO in the concrete type's registered
// tag.
//
// For ordinary values of registered types, prefer MarshalCBOR directly and do
// not wrap them again with MarshalCBORTagged.
func MarshalCBORTagged[T any](t T, tag uint64) ([]byte, error) {
	return MarshalCBOR(cbor.Tag{
		Number:  tag,
		Content: t,
	})
}

// UnmarshalCBOR deserialises the given CBOR data into the specified type.
func UnmarshalCBOR[T any](data []byte) (T, error) {
	var t T
	mu.RLock()
	mode := dec
	mu.RUnlock()
	err := mode.Unmarshal(data, &t)
	if err != nil {
		return t, errs.Wrap(err).WithMessage("deserialisation error")
	}
	return t, nil
}
