package examplecurve

import (
	algebra "github.com/bronlabs/krypton-primitives/pkg/base/algebra2"
	"github.com/bronlabs/krypton-primitives/pkg/base/algebra2/fields"
	"github.com/bronlabs/krypton-primitives/pkg/base/errs"
	"github.com/cronokirby/saferith"
	"io"
)

var (
	Z13Instance = &Z13{}

	_ fields.PrimeField[*Z13Element]        = Z13Instance
	_ fields.PrimeFieldElement[*Z13Element] = (*Z13Element)(nil)
)

type Z13 struct{}

func (f *Z13) Name() string {
	return "Z13"
}

func (f *Z13) Zero() *Z13Element {
	return &Z13Element{V: 0}
}

func (f *Z13) One() *Z13Element {
	return &Z13Element{V: 1}
}

func (f *Z13) Random(prng io.Reader) (*Z13Element, error) {
	var b [1]byte
	_, err := io.ReadFull(prng, b[:])
	if err != nil {
		return nil, err
	}

	return &Z13Element{V: uint64(b[0] % 13)}, nil
}

func (f *Z13) Hash(bytes []byte) (*Z13Element, error) {
	panic("implement me")
}

func (f *Z13) Order() algebra.Cardinal {
	panic("implement me")
}

func (f *Z13) Characteristic() algebra.Cardinal {
	panic("implement me")
}

func (f *Z13) ExtensionDegree() uint {
	panic("implement me")
}

func (f *Z13) SubFieldIdentity(i uint) (any, error) {
	panic("implement me")
}

func (f *Z13) ElementSize() int {
	panic("implement me")
}

func (f *Z13) WideElementSize() int {
	panic("implement me")
}

func (f *Z13) FromNat(nat *saferith.Nat) *Z13Element {
	panic("implement me")
}

func (f *Z13) OpIdentity() *Z13Element {
	return f.Zero()
}

type Z13Element struct {
	V uint64
}

func (fe *Z13Element) MarshalBinary() (data []byte, err error) {
	panic("implement me")
}

func (fe *Z13Element) UnmarshalBinary(data []byte) error {
	panic("implement me")
}

func (fe *Z13Element) Clone() *Z13Element {
	return &Z13Element{V: fe.V}
}

func (fe *Z13Element) Equal(rhs *Z13Element) bool {
	return fe.V == rhs.V
}

func (fe *Z13Element) HashCode() uint64 {
	panic("implement me")
}

func (fe *Z13Element) Structure() algebra.Structure[*Z13Element] {
	return Z13Instance
}

func (fe *Z13Element) Op(rhs *Z13Element) *Z13Element {
	return fe.Add(rhs)
}

func (fe *Z13Element) Order() algebra.Cardinal {
	panic("implement me")
}

func (fe *Z13Element) Add(rhs *Z13Element) *Z13Element {
	return &Z13Element{V: (fe.V + rhs.V) % 13}
}

func (fe *Z13Element) Double() *Z13Element {
	return fe.Add(fe)
}

func (fe *Z13Element) Mul(rhs *Z13Element) *Z13Element {
	return &Z13Element{V: (fe.V * rhs.V) % 13}
}

func (fe *Z13Element) Square() *Z13Element {
	return fe.Mul(fe)
}

func (fe *Z13Element) IsOpIdentity() bool {
	return fe.IsZero()
}

func (fe *Z13Element) IsOne() bool {
	return fe.V == 1
}

func (fe *Z13Element) OtherOp(rhs *Z13Element) *Z13Element {
	return fe.Mul(fe)
}

func (fe *Z13Element) IsZero() bool {
	return fe.V == 0
}

func (fe *Z13Element) OpInv() *Z13Element {
	return fe.Neg()
}

func (fe *Z13Element) Neg() *Z13Element {
	return &Z13Element{V: 13 - fe.V}
}

func (fe *Z13Element) Sub(e *Z13Element) *Z13Element {
	return &Z13Element{V: (13 + fe.V - e.V) % 13}
}

func (fe *Z13Element) IsProbablyPrime() bool {
	panic("implement me")
}

func (fe *Z13Element) EuclideanDiv(rhs *Z13Element) (quot, rem *Z13Element) {
	panic("implement me")
}

func (fe *Z13Element) TryInv() (*Z13Element, error) {
	if fe.IsZero() {
		return nil, errs.NewFailed("division by zero")
	}

	return fe.Mul(fe).Mul(fe).Mul(fe).Mul(fe).Mul(fe).Mul(fe).Mul(fe).Mul(fe).Mul(fe).Mul(fe), nil
}

func (fe *Z13Element) TryDiv(e *Z13Element) (*Z13Element, error) {
	eInv, err := e.TryInv()
	if err != nil {
		return nil, err
	}

	return fe.Mul(eInv), nil
}

func (fe *Z13Element) IsEven() bool {
	panic("implement me")
}

func (fe *Z13Element) IsOdd() bool {
	panic("implement me")
}

func (fe *Z13Element) Nat() *saferith.Nat {
	panic("implement me")
}
