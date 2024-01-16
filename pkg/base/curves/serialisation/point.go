package serialisation

import (
	"encoding/hex"
	"encoding/json"

	"github.com/copperexchange/krypton-primitives/pkg/base"
	"github.com/copperexchange/krypton-primitives/pkg/base/curves"
	"github.com/copperexchange/krypton-primitives/pkg/base/errs"
)

func PointMarshalBinary(point curves.Point) ([]byte, error) {
	// Always stores points in compressed form
	// The first bytes are the curve name
	// separated by a colon followed by the compressed point
	// bytes
	t := point.ToAffineCompressed()
	curve := point.Curve()
	name := []byte(curve.Name())
	output := make([]byte, len(name)+1+len(t))
	copy(output[:len(name)], name)
	output[len(name)] = byte(':')
	copy(output[len(output)-len(t):], t)
	return output, nil
}

func PointUnmarshalBinary(curve curves.Curve, input []byte) (curves.Point, error) {
	if len(input) < base.FieldBytes+1+len(curve.Name()) {
		return nil, errs.NewInvalidLength("invalid byte sequence")
	}
	sep := byte(':')
	i := 0
	for ; i < len(input); i++ {
		if input[i] == sep {
			break
		}
	}
	point, err := curve.Point().FromAffineCompressed(input[i+1:])
	if err != nil {
		return nil, errs.WrapSerialisation(err, "from affine compressed")
	}
	return point, nil
}

func PointMarshalText(point curves.Point) ([]byte, error) {
	// Always stores points in compressed form
	// The first bytes are the curve name
	// separated by a colon followed by the compressed point
	// bytes
	t := point.ToAffineCompressed()
	curve := point.Curve()
	name := []byte(curve.Name())
	output := make([]byte, len(name)+1+len(t)*2)
	copy(output[:len(name)], name)
	output[len(name)] = byte(':')
	hex.Encode(output[len(output)-len(t)*2:], t)
	return output, nil
}

func PointUnmarshalText(curve curves.Curve, input []byte) (curves.Point, error) {
	if len(input) < base.FieldBytes*2+1+len(curve.Name()) {
		return nil, errs.NewInvalidLength("invalid byte sequence")
	}
	sep := byte(':')
	i := 0
	for ; i < len(input); i++ {
		if input[i] == sep {
			break
		}
	}
	buffer := make([]byte, (len(input)-i)/2)
	_, err := hex.Decode(buffer, input[i+1:])
	if err != nil {
		return nil, errs.WrapSerialisation(err, "hex decoding failed")
	}
	point, err := curve.Point().FromAffineCompressed(buffer)
	if err != nil {
		return nil, errs.WrapSerialisation(err, "from affine compressed")
	}
	return point, nil
}

func PointMarshalJson(point curves.Point) ([]byte, error) {
	m := make(map[string]string, 2)
	curve := point.Curve()
	m["type"] = curve.Name()
	m["value"] = hex.EncodeToString(point.ToAffineCompressed())
	marshalled, err := json.Marshal(m)
	if err != nil {
		return nil, errs.WrapFailed(err, "json marshal failed")
	}
	return marshalled, nil
}

func NewPointFromJSON(curve curves.Curve, data []byte) (curves.Point, error) {
	var m map[string]string

	if err := json.Unmarshal(data, &m); err != nil {
		return nil, errs.WrapSerialisation(err, "json unmarshal failed")
	}
	p, err := hex.DecodeString(m["value"])
	if err != nil {
		return nil, errs.WrapSerialisation(err, "hex decode string failed")
	}
	P, err := curve.Point().FromAffineCompressed(p)
	if err != nil {
		return nil, errs.WrapSerialisation(err, "from affine compressed")
	}
	return P, nil
}
