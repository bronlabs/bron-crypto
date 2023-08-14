package internal

import (
	"encoding/hex"
	"encoding/json"

	"github.com/copperexchange/knox-primitives/pkg/core/curves"
	"github.com/copperexchange/knox-primitives/pkg/core/errs"
)

type setBytesFuncType func(input []byte) (curves.Scalar, error)

func UnmarshalScalar(input []byte) []byte {
	sep := byte(':')
	i := 0
	for ; i < len(input); i++ {
		if input[i] == sep {
			break
		}
	}
	return input[i+1:]
}

func ScalarMarshalBinary(scalar curves.Scalar) ([]byte, error) {
	// All scalars are 32 bytes long
	// The last 32 bytes are the actual value
	// The first remaining bytes are the curve name
	// separated by a colon
	curve, err := scalar.Curve()
	if err != nil {
		return nil, errs.WrapInvalidCurve(err, "could not extract curve")
	}
	name := []byte(curve.Name())
	output := make([]byte, len(name)+1+scalarBytes)
	copy(output[:len(name)], name)
	output[len(name)] = byte(':')
	copy(output[len(name)+1:], scalar.Bytes())
	return output, nil
}

func ScalarUnmarshalBinary(name string, f setBytesFuncType, input []byte) (curves.Scalar, error) {
	// All scalars are 32 bytes long
	// The first 32 bytes are the actual value
	// The remaining bytes are the curve name
	if len(input) < scalarBytes+1+len(name) {
		return nil, errs.NewInvalidLength("invalid byte sequence")
	}
	data := UnmarshalScalar(input)
	scalar, err := f(data)
	if err != nil {
		return nil, errs.WrapDeserializationFailed(err, "set bytes failed")
	}
	return scalar, nil
}

func ScalarMarshalText(scalar curves.Scalar) ([]byte, error) {
	// All scalars are 32 bytes long
	// For text encoding we put the curve name first for readability
	// separated by a colon, then the hex encoding of the scalar
	// which avoids the base64 weakness with strict mode or not
	curve, err := scalar.Curve()
	if err != nil {
		return nil, errs.WrapInvalidCurve(err, "could not extract curve")
	}
	name := []byte(curve.Name())
	output := make([]byte, len(name)+1+scalarBytes*2)
	copy(output[:len(name)], name)
	output[len(name)] = byte(':')
	_ = hex.Encode(output[len(name)+1:], scalar.Bytes())
	return output, nil
}

func ScalarUnmarshalText(name string, f setBytesFuncType, input []byte) (curves.Scalar, error) {
	if len(input) < scalarBytes*2+len(name)+1 {
		return nil, errs.NewInvalidLength("invalid byte sequence")
	}
	data := UnmarshalScalar(input)
	var t [scalarBytes]byte
	if _, err := hex.Decode(t[:], data); err != nil {
		return nil, errs.WrapDeserializationFailed(err, "hex decoding failed")
	}
	scalar, err := f(t[:])
	if err != nil {
		return nil, errs.WrapFailed(err, "set bytes failed")
	}
	return scalar, nil
}

func ScalarMarshalJson(name string, scalar curves.Scalar) ([]byte, error) {
	m := make(map[string]string, 2)
	m["type"] = name
	m["value"] = hex.EncodeToString(scalar.Bytes())
	serialised, err := json.Marshal(m)
	if err != nil {
		return nil, errs.WrapFailed(err, "json marshal failed")
	}
	return serialised, nil
}

func NewScalarFromJSON(f setBytesFuncType, data []byte) (curves.Scalar, error) {
	var m map[string]string

	err := json.Unmarshal(data, &m)
	if err != nil {
		return nil, errs.WrapDeserializationFailed(err, "json unmarshal failed")
	}
	s, err := hex.DecodeString(m["value"])
	if err != nil {
		return nil, errs.WrapDeserializationFailed(err, "hex decode string failed")
	}
	S, err := f(s)
	if err != nil {
		return nil, errs.WrapDeserializationFailed(err, "set bytes failed")
	}
	return S, nil
}
