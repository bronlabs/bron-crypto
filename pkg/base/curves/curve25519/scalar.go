package curve25519

import (
	"encoding/binary"
	"io"

	"github.com/cronokirby/saferith"

	"github.com/copperexchange/krypton-primitives/pkg/base/constants"
	"github.com/copperexchange/krypton-primitives/pkg/base/curves"
	"github.com/copperexchange/krypton-primitives/pkg/base/curves/serialisation"
	"github.com/copperexchange/krypton-primitives/pkg/base/errs"
	"github.com/copperexchange/krypton-primitives/pkg/base/types"
)

var _ curves.Scalar = (*Scalar)(nil)

type Scalar struct {
	Value [32]byte

	_ types.Incomparable
}

func (*Scalar) Random(prng io.Reader) (curves.Scalar, error) {
	if prng == nil {
		panic("prng in nil")
	}
	var seed [32]byte
	if _, err := prng.Read(seed[:]); err != nil {
		return nil, errs.WrapRandomSampleFailed(err, "could not read from prng")
	}
	return &Scalar{Value: seed}, nil
}

func (*Scalar) Hash(bytes ...[]byte) (curves.Scalar, error) {
	// TODO implement me
	panic("implement me")
}

func (*Scalar) Zero() curves.Scalar {
	return &Scalar{
		Value: [32]byte{
			0x00, 0x00, 0x00, 0x00,
			0x00, 0x00, 0x00, 0x00,
			0x00, 0x00, 0x00, 0x00,
			0x00, 0x00, 0x00, 0x00,
			0x00, 0x00, 0x00, 0x00,
			0x00, 0x00, 0x00, 0x00,
			0x00, 0x00, 0x00, 0x00,
			0x00, 0x00, 0x00, 0x00,
		},
	}
}

func (*Scalar) One() curves.Scalar {
	// TODO implement me
	panic("implement me")
}

func (*Scalar) IsZero() bool {
	// TODO implement me
	panic("implement me")
}

func (*Scalar) IsOne() bool {
	// TODO implement me
	panic("implement me")
}

func (*Scalar) IsOdd() bool {
	// TODO implement me
	panic("implement me")
}

func (*Scalar) IsEven() bool {
	// TODO implement me
	panic("implement me")
}

func (*Scalar) New(value uint64) curves.Scalar {
	s := make([]byte, 32)
	binary.LittleEndian.PutUint64(s, value)
	var scalar [32]byte
	copy(scalar[:], s)
	return &Scalar{Value: scalar}
}

func (*Scalar) Cmp(rhs curves.Scalar) int {
	// TODO implement me
	panic("implement me")
}

func (*Scalar) Square() curves.Scalar {
	// TODO implement me
	panic("implement me")
}

func (*Scalar) Double() curves.Scalar {
	// TODO implement me
	panic("implement me")
}

func (*Scalar) Invert() (curves.Scalar, error) {
	// TODO implement me
	panic("implement me")
}

func (*Scalar) Sqrt() (curves.Scalar, error) {
	// TODO implement me
	panic("implement me")
}

func (*Scalar) Cube() curves.Scalar {
	// TODO implement me
	panic("implement me")
}

func (*Scalar) Add(rhs curves.Scalar) curves.Scalar {
	// TODO implement me
	panic("implement me")
}

func (*Scalar) Sub(rhs curves.Scalar) curves.Scalar {
	// TODO implement me
	panic("implement me")
}

func (*Scalar) Mul(rhs curves.Scalar) curves.Scalar {
	// TODO implement me
	panic("implement me")
}

func (*Scalar) MulAdd(y, z curves.Scalar) curves.Scalar {
	// TODO implement me
	panic("implement me")
}

func (*Scalar) Div(rhs curves.Scalar) curves.Scalar {
	// TODO implement me
	panic("implement me")
}

func (*Scalar) Exp(k curves.Scalar) curves.Scalar {
	// TODO implement me
	panic("implement me")
}

func (*Scalar) Neg() curves.Scalar {
	// TODO implement me
	panic("implement me")
}

func (*Scalar) SetNat(v *saferith.Nat) (curves.Scalar, error) {
	// TODO implement me
	panic("implement me")
}

func (*Scalar) Nat() *saferith.Nat {
	// TODO implement me
	panic("implement me")
}

func (*Scalar) Uint64() uint64 {
	// TODO implement me
	panic("implement me")
}

func (s *Scalar) Bytes() []byte {
	return s.Value[:]
}

func (*Scalar) SetBytes(bytes []byte) (curves.Scalar, error) {
	var ss [constants.FieldBytes]byte
	copy(ss[:], bytes)
	return &Scalar{Value: ss}, nil
}

func (*Scalar) SetBytesWide(bytes []byte) (curves.Scalar, error) {
	// TODO implement me
	panic("implement me")
}

func (*Scalar) Clone() curves.Scalar {
	// TODO implement me
	panic("implement me")
}

func (*Scalar) Curve() curves.Curve {
	return &curve25519Instance
}

func (*Scalar) CurveName() string {
	return Name
}

func (s *Scalar) MarshalBinary() ([]byte, error) {
	buffer, err := serialisation.ScalarMarshalBinary(s)
	if err != nil {
		return nil, errs.WrapSerializationError(err, "could not marshal")
	}
	return buffer, nil
}

func (s *Scalar) UnmarshalBinary(input []byte) error {
	sc, err := serialisation.ScalarUnmarshalBinary(Name, s.SetBytes, input)
	if err != nil {
		return errs.WrapSerializationError(err, "could not unmarshal")
	}
	ss, ok := sc.(*Scalar)
	if !ok {
		return errs.NewInvalidType("invalid scalar")
	}
	s.Value = ss.Value
	return nil
}

func (s *Scalar) MarshalText() ([]byte, error) {
	buffer, err := serialisation.ScalarMarshalText(s)
	if err != nil {
		return nil, errs.WrapSerializationError(err, "could not marshal")
	}
	return buffer, nil
}

func (s *Scalar) UnmarshalText(input []byte) error {
	sc, err := serialisation.ScalarUnmarshalText(Name, s.SetBytes, input)
	if err != nil {
		return errs.WrapSerializationError(err, "could not unmarshal")
	}
	ss, ok := sc.(*Scalar)
	if !ok {
		return errs.NewInvalidType("invalid scalar")
	}
	s.Value = ss.Value
	return nil
}

func (s *Scalar) MarshalJSON() ([]byte, error) {
	buffer, err := serialisation.ScalarMarshalJson(Name, s)
	if err != nil {
		return nil, errs.WrapSerializationError(err, "could not marshal")
	}
	return buffer, nil
}

func (s *Scalar) UnmarshalJSON(input []byte) error {
	sc, err := serialisation.NewScalarFromJSON(s.SetBytes, input)
	if err != nil {
		return errs.WrapSerializationError(err, "could not extract a scalar from json")
	}
	S, ok := sc.(*Scalar)
	if !ok {
		return errs.NewFailed("invalid type")
	}
	s.Value = S.Value
	return nil
}
