package serialisation

import (
	"encoding/hex"
	"encoding/json"

	"github.com/copperexchange/krypton-primitives/pkg/base/curves"
	"github.com/copperexchange/krypton-primitives/pkg/base/errs"
)

type setBytesFuncType[C curves.CurveIdentifier] func(input []byte) (curves.Scalar[C], error)

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

func ScalarMarshalBinary[C curves.CurveIdentifier](scalar curves.Scalar[C]) ([]byte, error) {
	// All scalars are 32 bytes long
	// The last 32 bytes are the actual value
	// The first remaining bytes are the curve name
	// separated by a colon
	curve := scalar.Curve()
	name := []byte(curve.Name())
	output := make([]byte, len(name)+1+scalarBytes)
	copy(output[:len(name)], name)
	output[len(name)] = byte(':')
	copy(output[len(name)+1:], scalar.Bytes())
	return output, nil
}

func ScalarUnmarshalBinary[C curves.CurveIdentifier](name string, f setBytesFuncType[C], input []byte) (curves.Scalar[C], error) {
	// All scalars are 32 bytes long
	// The first 32 bytes are the actual value
	// The remaining bytes are the curve name
	if len(input) < scalarBytes+1+len(name) {
		return nil, errs.NewInvalidLength("invalid byte sequence")
	}
	data := UnmarshalScalar(input)
	scalar, err := f(data)
	if err != nil {
		return nil, errs.WrapSerializationError(err, "set bytes failed")
	}
	return scalar, nil
}

func ScalarMarshalText[C curves.CurveIdentifier](scalar curves.Scalar[C]) ([]byte, error) {
	// All scalars are 32 bytes long
	// For text encoding we put the curve name first for readability
	// separated by a colon, then the hex encoding of the scalar
	// which avoids the base64 weakness with strict mode or not
	curve := scalar.Curve()
	name := []byte(curve.Name())
	output := make([]byte, len(name)+1+scalarBytes*2)
	copy(output[:len(name)], name)
	output[len(name)] = byte(':')
	_ = hex.Encode(output[len(name)+1:], scalar.Bytes())
	return output, nil
}

func ScalarUnmarshalText[C curves.CurveIdentifier](name string, f setBytesFuncType[C], input []byte) (curves.Scalar[C], error) {
	if len(input) < scalarBytes*2+len(name)+1 {
		return nil, errs.NewInvalidLength("invalid byte sequence")
	}
	data := UnmarshalScalar(input)
	var t [scalarBytes]byte
	if _, err := hex.Decode(t[:], data); err != nil {
		return nil, errs.WrapSerializationError(err, "hex decoding failed")
	}
	scalar, err := f(t[:])
	if err != nil {
		return nil, errs.WrapFailed(err, "set bytes failed")
	}
	return scalar, nil
}

func ScalarMarshalJson[C curves.CurveIdentifier](name string, scalar curves.Scalar[C]) ([]byte, error) {
	m := make(map[string]string, 2)
	m["type"] = name
	m["value"] = hex.EncodeToString(scalar.Bytes())
	serialised, err := json.Marshal(m)
	if err != nil {
		return nil, errs.WrapFailed(err, "json marshal failed")
	}
	return serialised, nil
}

func NewScalarFromJSON[C curves.CurveIdentifier](f setBytesFuncType[C], data []byte) (curves.Scalar[C], error) {
	var m map[string]string

	err := json.Unmarshal(data, &m)
	if err != nil {
		return nil, errs.WrapSerializationError(err, "json unmarshal failed")
	}
	s, err := hex.DecodeString(m["value"])
	if err != nil {
		return nil, errs.WrapSerializationError(err, "hex decode string failed")
	}
	S, err := f(s)
	if err != nil {
		return nil, errs.WrapSerializationError(err, "set bytes failed")
	}
	return S, nil
}
