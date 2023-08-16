package k256

import (
	"bytes"
	"io"
	"math/big"

	"github.com/copperexchange/knox-primitives/pkg/core/bitstring"
	"github.com/copperexchange/knox-primitives/pkg/core/curves"
	"github.com/copperexchange/knox-primitives/pkg/core/curves/impl"
	"github.com/copperexchange/knox-primitives/pkg/core/curves/internal"
	"github.com/copperexchange/knox-primitives/pkg/core/curves/k256/impl/fq"
	"github.com/copperexchange/knox-primitives/pkg/core/errs"
	"github.com/copperexchange/knox-primitives/pkg/core/integration/helper_types"
)

var _ (curves.Scalar) = (*Scalar)(nil)

type Scalar struct {
	Value *impl.Field

	_ helper_types.Incomparable
}

func (Scalar) Curve() (curves.Curve, error) {
	return k256Instance, nil
}

func (s *Scalar) Random(prng io.Reader) curves.Scalar {
	if prng == nil {
		panic("prng is nil")
	}
	var seed [64]byte
	_, _ = prng.Read(seed[:])
	return s.Hash(seed[:])
}

func (*Scalar) Hash(inputs ...[]byte) curves.Scalar {
	dst := []byte("secp256k1_XMD:SHA-256_SSWU_RO_")
	xmd := impl.ExpandMsgXmd(impl.EllipticPointHasherSha256(), bytes.Join(inputs, nil), dst, 48)
	var t [64]byte
	copy(t[:48], bitstring.ReverseBytes(xmd))

	return &Scalar{
		Value: fq.K256FqNew().SetBytesWide(&t),
	}
}

func (*Scalar) Zero() curves.Scalar {
	return &Scalar{
		Value: fq.K256FqNew().SetZero(),
	}
}

func (*Scalar) One() curves.Scalar {
	return &Scalar{
		Value: fq.K256FqNew().SetOne(),
	}
}

func (s *Scalar) IsZero() bool {
	return s.Value.IsZero() == 1
}

func (s *Scalar) IsOne() bool {
	return s.Value.IsOne() == 1
}

func (s *Scalar) IsOdd() bool {
	return s.Value.Bytes()[0]&1 == 1
}

func (s *Scalar) IsEven() bool {
	return s.Value.Bytes()[0]&1 == 0
}

func (*Scalar) New(value int) curves.Scalar {
	t := fq.K256FqNew()
	v := big.NewInt(int64(value))
	if value < 0 {
		v.Mod(v, t.Params.BiModulus)
	}
	return &Scalar{
		Value: t.SetBigInt(v),
	}
}

func (s *Scalar) Cmp(rhs curves.Scalar) int {
	if rhs == nil {
		panic("rhs is nil")
	}
	r, ok := rhs.(*Scalar)
	if ok {
		return s.Value.Cmp(r.Value)
	} else {
		panic("rhs is not ScalarK256")
	}
}

func (s *Scalar) Square() curves.Scalar {
	return &Scalar{
		Value: fq.K256FqNew().Square(s.Value),
	}
}

func (s *Scalar) Double() curves.Scalar {
	return &Scalar{
		Value: fq.K256FqNew().Double(s.Value),
	}
}

func (s *Scalar) Invert() (curves.Scalar, error) {
	value, wasInverted := fq.K256FqNew().Invert(s.Value)
	if !wasInverted {
		return nil, errs.NewFailed("inverse doesn't exist")
	}
	return &Scalar{
		Value: value,
	}, nil
}

func (s *Scalar) Sqrt() (curves.Scalar, error) {
	value, wasSquare := fq.K256FqNew().Sqrt(s.Value)
	if !wasSquare {
		return nil, errs.NewFailed("not a square")
	}
	return &Scalar{
		Value: value,
	}, nil
}

func (s *Scalar) Cube() curves.Scalar {
	value := fq.K256FqNew().Mul(s.Value, s.Value)
	value.Mul(value, s.Value)
	return &Scalar{
		Value: value,
	}
}

func (s *Scalar) Add(rhs curves.Scalar) curves.Scalar {
	r, ok := rhs.(*Scalar)
	if ok {
		return &Scalar{
			Value: fq.K256FqNew().Add(s.Value, r.Value),
		}
	} else {
		panic("rhs is not ScalarK256")
	}
}

func (s *Scalar) Sub(rhs curves.Scalar) curves.Scalar {
	r, ok := rhs.(*Scalar)
	if ok {
		return &Scalar{
			Value: fq.K256FqNew().Sub(s.Value, r.Value),
		}
	} else {
		panic("rhs is not ScalarK256")
	}
}

func (s *Scalar) Mul(rhs curves.Scalar) curves.Scalar {
	r, ok := rhs.(*Scalar)
	if ok {
		return &Scalar{
			Value: fq.K256FqNew().Mul(s.Value, r.Value),
		}
	} else {
		panic("rhs is not ScalarK256")
	}
}

func (s *Scalar) MulAdd(y, z curves.Scalar) curves.Scalar {
	return s.Mul(y).Add(z)
}

func (s *Scalar) Div(rhs curves.Scalar) curves.Scalar {
	r, ok := rhs.(*Scalar)
	if ok {
		v, wasInverted := fq.K256FqNew().Invert(r.Value)
		if !wasInverted {
			panic("cannot invert rhs")
		}
		v.Mul(v, s.Value)
		return &Scalar{Value: v}
	} else {
		panic("rhs is not ScalarK256")
	}
}

func (s *Scalar) Exp(k curves.Scalar) curves.Scalar {
	exponent, ok := k.(*Scalar)
	if !ok {
		panic("rhs is not ScalarK256")
	}

	value := fq.K256FqNew().Exp(s.Value, exponent.Value)
	return &Scalar{Value: value}
}

func (s *Scalar) Neg() curves.Scalar {
	return &Scalar{
		Value: fq.K256FqNew().Neg(s.Value),
	}
}

func (*Scalar) SetBigInt(v *big.Int) (curves.Scalar, error) {
	if v == nil {
		return nil, errs.NewFailed("'v' cannot be nil")
	}
	value := fq.K256FqNew().SetBigInt(v)
	return &Scalar{
		Value: value,
	}, nil
}

func (s *Scalar) BigInt() *big.Int {
	return s.Value.BigInt()
}

func (s *Scalar) Bytes() []byte {
	t := s.Value.Bytes()
	return bitstring.ReverseBytes(t[:])
}

func (*Scalar) SetBytes(input []byte) (curves.Scalar, error) {
	if len(input) != 32 {
		return nil, errs.NewInvalidLength("invalid length")
	}
	var seq [32]byte
	copy(seq[:], bitstring.ReverseBytes(input))
	value, err := fq.K256FqNew().SetBytes(&seq)
	if err != nil {
		return nil, errs.WrapFailed(err, "could not set bytes")
	}
	return &Scalar{
		Value: value,
	}, nil
}

func (*Scalar) SetBytesWide(input []byte) (curves.Scalar, error) {
	if len(input) != 64 {
		return nil, errs.NewInvalidLength("invalid length")
	}
	var seq [64]byte
	copy(seq[:], input)
	return &Scalar{
		Value: fq.K256FqNew().SetBytesWide(&seq),
	}, nil
}

func (*Scalar) CurveName() string {
	return Name
}

func (s *Scalar) Clone() curves.Scalar {
	return &Scalar{
		Value: fq.K256FqNew().Set(s.Value),
	}
}

func (s *Scalar) MarshalBinary() ([]byte, error) {
	return internal.ScalarMarshalBinary(s)
}

func (s *Scalar) UnmarshalBinary(input []byte) error {
	sc, err := internal.ScalarUnmarshalBinary(Name, s.SetBytes, input)
	if err != nil {
		return err
	}
	ss, ok := sc.(*Scalar)
	if !ok {
		return errs.NewInvalidType("invalid scalar")
	}
	s.Value = ss.Value
	return nil
}

func (s *Scalar) MarshalText() ([]byte, error) {
	return internal.ScalarMarshalText(s)
}

func (s *Scalar) UnmarshalText(input []byte) error {
	sc, err := internal.ScalarUnmarshalText(Name, s.SetBytes, input)
	if err != nil {
		return err
	}
	ss, ok := sc.(*Scalar)
	if !ok {
		return errs.NewInvalidType("invalid scalar")
	}
	s.Value = ss.Value
	return nil
}

func (s *Scalar) MarshalJSON() ([]byte, error) {
	return internal.ScalarMarshalJson(Name, s)
}

func (s *Scalar) UnmarshalJSON(input []byte) error {
	sc, err := internal.NewScalarFromJSON(s.SetBytes, input)
	if err != nil {
		return errs.WrapFailed(err, "could not extract a scalar from json")
	}
	S, ok := sc.(*Scalar)
	if !ok {
		return errs.NewFailed("invalid type")
	}
	s.Value = S.Value
	return nil
}
