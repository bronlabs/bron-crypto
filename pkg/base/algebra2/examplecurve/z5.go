package examplecurve

import (
	algebra "github.com/bronlabs/krypton-primitives/pkg/base/algebra2"
	"github.com/bronlabs/krypton-primitives/pkg/base/algebra2/fields"
	"github.com/bronlabs/krypton-primitives/pkg/base/errs"
	"github.com/cronokirby/saferith"
	"io"
)

var (
	Z5Instance = &Z5{}

	_ fields.PrimeField[*Z5Element]        = Z5Instance
	_ fields.PrimeFieldElement[*Z5Element] = (*Z5Element)(nil)
)

type Z5 struct{}

func (f *Z5) Name() string {
	return "Z5"
}

func (f *Z5) Zero() *Z5Element {
	return &Z5Element{V: 0}
}

func (f *Z5) One() *Z5Element {
	return &Z5Element{V: 1}
}

func (f *Z5) Random(prng io.Reader) (*Z5Element, error) {
	var b [1]byte
	_, err := io.ReadFull(prng, b[:])
	if err != nil {
		return nil, err
	}

	return &Z5Element{V: uint64(b[0] % 5)}, nil
}

func (f *Z5) Hash(bytes []byte) (*Z5Element, error) {
	panic("implement me")
}

func (f *Z5) Order() algebra.Cardinal {
	panic("implement me")
}

func (f *Z5) Characteristic() algebra.Cardinal {
	panic("implement me")
}

func (f *Z5) ExtensionDegree() uint {
	panic("implement me")
}

func (f *Z5) SubFieldIdentity(i uint) (any, error) {
	panic("implement me")
}

func (f *Z5) ElementSize() int {
	panic("implement me")
}

func (f *Z5) WideElementSize() int {
	panic("implement me")
}

func (f *Z5) FromNat(nat *saferith.Nat) *Z5Element {
	panic("implement me")
}

func (f *Z5) OpIdentity() *Z5Element {
	return f.Zero()
}

type Z5Element struct {
	V uint64
}

func (fe *Z5Element) MarshalBinary() (data []byte, err error) {
	panic("implement me")
}

func (fe *Z5Element) UnmarshalBinary(data []byte) error {
	panic("implement me")
}

func (fe *Z5Element) Clone() *Z5Element {
	return &Z5Element{V: fe.V}
}

func (fe *Z5Element) Equal(rhs *Z5Element) bool {
	return fe.V == rhs.V
}

func (fe *Z5Element) HashCode() uint64 {
	panic("implement me")
}

func (fe *Z5Element) Structure() algebra.Structure[*Z5Element] {
	return Z5Instance
}

func (fe *Z5Element) Op(rhs *Z5Element) *Z5Element {
	return fe.Add(rhs)
}

func (fe *Z5Element) Order() algebra.Cardinal {
	panic("implement me")
}

func (fe *Z5Element) Add(rhs *Z5Element) *Z5Element {
	return &Z5Element{V: (fe.V + rhs.V) % 5}
}

func (fe *Z5Element) Double() *Z5Element {
	return fe.Add(fe)
}

func (fe *Z5Element) Mul(rhs *Z5Element) *Z5Element {
	return &Z5Element{V: (fe.V * rhs.V) % 5}
}

func (fe *Z5Element) Square() *Z5Element {
	return fe.Mul(fe)
}

func (fe *Z5Element) IsOpIdentity() bool {
	return fe.IsZero()
}

func (fe *Z5Element) IsOne() bool {
	return fe.V == 1
}

func (fe *Z5Element) OtherOp(rhs *Z5Element) *Z5Element {
	return fe.Mul(fe)
}

func (fe *Z5Element) IsZero() bool {
	return fe.V == 0
}

func (fe *Z5Element) OpInv() *Z5Element {
	return fe.Neg()
}

func (fe *Z5Element) Neg() *Z5Element {
	return &Z5Element{V: 5 - fe.V}
}

func (fe *Z5Element) Sub(e *Z5Element) *Z5Element {
	return &Z5Element{V: (5 + fe.V - e.V) % 5}
}

func (fe *Z5Element) IsProbablyPrime() bool {
	panic("implement me")
}

func (fe *Z5Element) EuclideanDiv(rhs *Z5Element) (quot, rem *Z5Element) {
	panic("implement me")
}

func (fe *Z5Element) TryInv() (*Z5Element, error) {
	if fe.IsZero() {
		return nil, errs.NewFailed("division by zero")
	}

	return fe.Mul(fe).Mul(fe), nil
}

func (fe *Z5Element) TryDiv(e *Z5Element) (*Z5Element, error) {
	eInv, err := e.TryInv()
	if err != nil {
		return nil, err
	}

	return fe.Mul(eInv), nil
}

func (fe *Z5Element) IsEven() bool {
	panic("implement me")
}

func (fe *Z5Element) IsOdd() bool {
	panic("implement me")
}

func (fe *Z5Element) Nat() *saferith.Nat {
	panic("implement me")
}
