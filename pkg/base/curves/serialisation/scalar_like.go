package serialisation

import (
	"encoding/hex"
	"encoding/json"

	"github.com/copperexchange/krypton-primitives/pkg/base/errs"
)

type setBytesFuncType[E any] func(input []byte) (E, error)

type ScalarLike[E any] interface {
	Bytes() []byte
}

func UnmarshalScalarLike(input []byte) []byte {
	sep := byte(':')
	i := 0
	for ; i < len(input); i++ {
		if input[i] == sep {
			break
		}
	}
	return input[i+1:]
}

func ScalarLikeMarshalBinary[E any](name string, fieldBytes int, x ScalarLike[E]) ([]byte, error) {
	output := make([]byte, len(name)+1+fieldBytes)
	copy(output[:len(name)], name)
	output[len(name)] = byte(':')
	copy(output[len(name)+1:], x.Bytes())
	return output, nil
}

func ScalarLikeUnmarshalBinary[E any](name string, f setBytesFuncType[E], fieldBytes int, input []byte) (E, error) {
	if len(input) < fieldBytes+1+len(name) {
		return *new(E), errs.NewInvalidLength("invalid byte sequence")
	}
	data := UnmarshalScalarLike(input)
	scalarLike, err := f(data)
	if err != nil {
		return *new(E), errs.WrapSerialisation(err, "set bytes failed")
	}
	return scalarLike, nil
}

func ScalarLikeMarshalText[E any](name string, fieldBytes int, x ScalarLike[E]) ([]byte, error) {
	// For text encoding we put the curve name first for readability
	// separated by a colon, then the hex encoding of the scalar
	// which avoids the base64 weakness with strict mode or not
	output := make([]byte, len(name)+1+fieldBytes*2)
	copy(output[:len(name)], name)
	output[len(name)] = byte(':')
	_ = hex.Encode(output[len(name)+1:], x.Bytes())
	return output, nil
}

func ScalarLikeUnmarshalText[E any](name string, f setBytesFuncType[E], fieldBytes int, input []byte) (E, error) {
	if len(input) < fieldBytes*2+len(name)+1 {
		return *new(E), errs.NewInvalidLength("invalid byte sequence")
	}
	data := UnmarshalScalarLike(input)
	t := make([]byte, fieldBytes)
	if _, err := hex.Decode(t[:], data); err != nil {
		return *new(E), errs.WrapSerialisation(err, "hex decoding failed")
	}
	scalarLike, err := f(t[:])
	if err != nil {
		return *new(E), errs.WrapFailed(err, "set bytes failed")
	}
	return scalarLike, nil
}

func ScalarLikeMarshalJson[E any](name string, x ScalarLike[E]) ([]byte, error) {
	m := make(map[string]string, 2)
	m["type"] = name
	m["value"] = hex.EncodeToString(x.Bytes())
	serialised, err := json.Marshal(m)
	if err != nil {
		return nil, errs.WrapFailed(err, "json marshal failed")
	}
	return serialised, nil
}

func NewScalarLikeFromJSON[E any](f setBytesFuncType[E], data []byte) (E, error) {
	var m map[string]string

	err := json.Unmarshal(data, &m)
	if err != nil {
		return *new(E), errs.WrapSerialisation(err, "json unmarshal failed")
	}
	s, err := hex.DecodeString(m["value"])
	if err != nil {
		return *new(E), errs.WrapSerialisation(err, "hex decode string failed")
	}
	S, err := f(s)
	if err != nil {
		return *new(E), errs.WrapSerialisation(err, "set bytes failed")
	}
	return S, nil
}
