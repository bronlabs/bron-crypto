package bls12381

import (
	"bytes"
	"io"

	"github.com/cronokirby/saferith"
	"golang.org/x/crypto/sha3"

	"github.com/copperexchange/knox-primitives/pkg/core/curves"
	bls12381impl "github.com/copperexchange/knox-primitives/pkg/core/curves/bls12381/impl"
	"github.com/copperexchange/knox-primitives/pkg/core/curves/internal"
	"github.com/copperexchange/knox-primitives/pkg/core/errs"
	"github.com/copperexchange/knox-primitives/pkg/core/integration/helper_types"
)

var _ (curves.Scalar) = (*ScalarGt)(nil)

type ScalarGt struct {
	Value *bls12381impl.Gt

	_ helper_types.Incomparable
}

func (*ScalarGt) Curve() curves.Curve {
	return nil
}

func (*ScalarGt) CurveName() string {
	return Name
}

func (*ScalarGt) PairingCurve() curves.PairingCurve {
	return New()
}

func (*ScalarGt) PairingCurveName() string {
	return Name
}

func (*ScalarGt) Random(reader io.Reader) curves.Scalar {
	value, err := new(bls12381impl.Gt).Random(reader)
	if err != nil {
		return nil
	}
	return &ScalarGt{Value: value}
}

func (s *ScalarGt) Hash(inputs ...[]byte) curves.Scalar {
	reader := sha3.NewShake256()
	n, err := reader.Write(bytes.Join(inputs, nil))
	if err != nil {
		return nil
	}
	if n != len(inputs) {
		return nil
	}
	return s.Random(reader)
}

func (*ScalarGt) Zero() curves.Scalar {
	return &ScalarGt{Value: new(bls12381impl.Gt)}
}

func (*ScalarGt) One() curves.Scalar {
	return &ScalarGt{Value: new(bls12381impl.Gt).SetOne()}
}

func (s *ScalarGt) IsZero() bool {
	return s.Value.IsZero() == 1
}

func (s *ScalarGt) IsOne() bool {
	return s.Value.IsOne() == 1
}

func (s *ScalarGt) MarshalBinary() ([]byte, error) {
	return internal.ScalarMarshalBinary(s)
}

func (s *ScalarGt) UnmarshalBinary(input []byte) error {
	sc, err := internal.ScalarUnmarshalBinary(GtName, s.SetBytes, input)
	if err != nil {
		return errs.WrapSerializationError(err, "could not unmarshal")
	}
	ss, ok := sc.(*ScalarGt)
	if !ok {
		return errs.NewInvalidType("invalid scalar")
	}
	s.Value = ss.Value
	return nil
}

func (s *ScalarGt) MarshalText() ([]byte, error) {
	return internal.ScalarMarshalText(s)
}

func (s *ScalarGt) UnmarshalText(input []byte) error {
	sc, err := internal.ScalarUnmarshalText(Name, s.SetBytes, input)
	if err != nil {
		return errs.WrapSerializationError(err, "could not unmarshal")
	}
	ss, ok := sc.(*ScalarGt)
	if !ok {
		return errs.NewInvalidType("invalid scalar")
	}
	s.Value = ss.Value
	return nil
}

func (s *ScalarGt) MarshalJSON() ([]byte, error) {
	return internal.ScalarMarshalJson(GtName, s)
}

func (s *ScalarGt) UnmarshalJSON(input []byte) error {
	sc, err := internal.NewScalarFromJSON(s.SetBytes, input)
	if err != nil {
		return errs.WrapSerializationError(err, "could not extract a scalar from json")
	}
	S, ok := sc.(*ScalarGt)
	if !ok {
		return errs.NewFailed("invalid type")
	}
	s.Value = S.Value
	return nil
}

func (s *ScalarGt) IsOdd() bool {
	data := s.Value.Bytes()
	return data[0]&1 == 1
}

func (s *ScalarGt) IsEven() bool {
	data := s.Value.Bytes()
	return data[0]&1 == 0
}

func (*ScalarGt) New(input uint64) curves.Scalar {
	var data [bls12381impl.GtFieldBytes]byte
	data[7] = byte(input >> 56 & 0xFF)
	data[6] = byte(input >> 48 & 0xFF)
	data[5] = byte(input >> 40 & 0xFF)
	data[4] = byte(input >> 32 & 0xFF)
	data[3] = byte(input >> 24 & 0xFF)
	data[2] = byte(input >> 16 & 0xFF)
	data[1] = byte(input >> 8 & 0xFF)
	data[0] = byte(input & 0xFF)

	value, isCanonical := new(bls12381impl.Gt).SetBytes(&data)
	if isCanonical != 1 {
		return nil
	}
	return &ScalarGt{Value: value}
}

func (s *ScalarGt) Cmp(rhs curves.Scalar) int {
	r, ok := rhs.(*ScalarGt)
	if ok && s.Value.Equal(r.Value) == 1 {
		return 0
	} else {
		return -2
	}
}

func (s *ScalarGt) Square() curves.Scalar {
	return &ScalarGt{
		Value: new(bls12381impl.Gt).Square(s.Value),
	}
}

func (s *ScalarGt) Double() curves.Scalar {
	return &ScalarGt{
		Value: new(bls12381impl.Gt).Double(s.Value),
	}
}

func (s *ScalarGt) Invert() (curves.Scalar, error) {
	value, wasInverted := new(bls12381impl.Gt).Invert(s.Value)
	if wasInverted != 1 {
		return nil, errs.NewFailed("not invertible")
	}
	return &ScalarGt{
		Value: value,
	}, nil
}

func (*ScalarGt) Sqrt() (curves.Scalar, error) {
	// Not implemented
	return nil, errs.NewFailed("not implemented")
}

func (s *ScalarGt) Cube() curves.Scalar {
	value := new(bls12381impl.Gt).Square(s.Value)
	value.Add(value, s.Value)
	return &ScalarGt{
		Value: value,
	}
}

func (s *ScalarGt) Add(rhs curves.Scalar) curves.Scalar {
	r, ok := rhs.(*ScalarGt)
	if ok {
		return &ScalarGt{
			Value: new(bls12381impl.Gt).Add(s.Value, r.Value),
		}
	} else {
		return nil
	}
}

func (s *ScalarGt) Sub(rhs curves.Scalar) curves.Scalar {
	r, ok := rhs.(*ScalarGt)
	if ok {
		return &ScalarGt{
			Value: new(bls12381impl.Gt).Sub(s.Value, r.Value),
		}
	} else {
		return nil
	}
}

func (s *ScalarGt) Mul(rhs curves.Scalar) curves.Scalar {
	r, ok := rhs.(*ScalarGt)
	if ok {
		return &ScalarGt{
			Value: new(bls12381impl.Gt).Add(s.Value, r.Value),
		}
	} else {
		return nil
	}
}

func (s *ScalarGt) MulAdd(y, z curves.Scalar) curves.Scalar {
	return s.Mul(y).Add(z)
}

func (s *ScalarGt) Div(rhs curves.Scalar) curves.Scalar {
	r, ok := rhs.(*ScalarGt)
	if ok {
		return &ScalarGt{
			Value: new(bls12381impl.Gt).Sub(s.Value, r.Value),
		}
	} else {
		return nil
	}
}

func (s *ScalarGt) Exp(k curves.Scalar) curves.Scalar {
	exp, ok := k.(*ScalarGt)
	if !ok {
		return nil
	}

	res := s.One()
	for i := s.Zero(); i.Cmp(exp) < 0; i = i.Add(s.One()) {
		res = res.Mul(s)
	}

	return res
}

func (s *ScalarGt) Neg() curves.Scalar {
	return &ScalarGt{
		Value: new(bls12381impl.Gt).Neg(s.Value),
	}
}

func (s *ScalarGt) SetNat(v *saferith.Nat) (curves.Scalar, error) {
	var bytes_ [bls12381impl.GtFieldBytes]byte
	v.FillBytes(bytes_[:])
	return s.SetBytes(bytes_[:])
}

func (s *ScalarGt) Nat() *saferith.Nat {
	bytes_ := s.Value.Bytes()
	return new(saferith.Nat).SetBytes(bytes_[:])
}

func (s *ScalarGt) Bytes() []byte {
	bytes_ := s.Value.Bytes()
	return bytes_[:]
}

func (*ScalarGt) SetBytes(input []byte) (curves.Scalar, error) {
	var b [bls12381impl.GtFieldBytes]byte
	copy(b[:], input)
	ss, isCanonical := new(bls12381impl.Gt).SetBytes(&b)
	if isCanonical == 0 {
		return nil, errs.NewSerializationError("invalid bytes")
	}
	return &ScalarGt{Value: ss}, nil
}

func (*ScalarGt) SetBytesWide(input []byte) (curves.Scalar, error) {
	if l := len(input); l != bls12381impl.GtFieldBytes*2 {
		return nil, errs.NewInvalidLength("invalid byte sequence")
	}
	var b [bls12381impl.GtFieldBytes]byte
	copy(b[:], input[:bls12381impl.GtFieldBytes])

	value, isCanonical := new(bls12381impl.Gt).SetBytes(&b)
	if isCanonical == 0 {
		return nil, errs.NewSerializationError("invalid bytes")
	}
	copy(b[:], input[bls12381impl.GtFieldBytes:])
	value2, isCanonical := new(bls12381impl.Gt).SetBytes(&b)
	if isCanonical == 0 {
		return nil, errs.NewSerializationError("invalid bytes")
	}
	value.Add(value, value2)
	return &ScalarGt{Value: value}, nil
}

func (s *ScalarGt) Clone() curves.Scalar {
	return &ScalarGt{
		Value: new(bls12381impl.Gt).Set(s.Value),
	}
}
