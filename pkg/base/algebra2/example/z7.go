package example

import (
	"crypto/sha256"
	algebra "github.com/bronlabs/krypton-primitives/pkg/base/algebra2"
	"github.com/bronlabs/krypton-primitives/pkg/base/algebra2/fields"
	//"github.com/bronlabs/krypton-primitives/pkg/base/errs"
	"github.com/cronokirby/saferith"
	"io"
)

var (
	_ fields.PrimeField[*Z7Element]        = Z7Instance
	_ fields.PrimeFieldElement[*Z7Element] = (*Z7Element)(nil)

	Z7Instance = &Z7{}
)

type Z7 struct{}

func (f *Z7) Name() string {
	return "Z7"
}

func (f *Z7) Order() algebra.Cardinal {
	return new(saferith.Nat).SetUint64(7).Resize(3)
}

func (f *Z7) OpIdentity() *Z7Element {
	return f.Zero()
}

func (f *Z7) One() *Z7Element {
	return &Z7Element{V: 1}
}

func (f *Z7) Characteristic() algebra.Cardinal {
	return new(saferith.Nat).SetUint64(1).Resize(1)
}

func (f *Z7) Zero() *Z7Element {
	return &Z7Element{V: 0}
}

func (f *Z7) ExtensionDegree() uint {
	return 1
}

func (f *Z7) SubFieldIdentity(i uint) (any, error) {
	panic("implement me")
}

func (f *Z7) Random(prng io.Reader) (*Z7Element, error) {
	var b [1]byte
	_, err := prng.Read(b[:])
	if err != nil {
		return nil, err
	}

	return &Z7Element{V: uint64(b[0] % 7)}, nil
}

func (f *Z7) Hash(bytes []byte) (*Z7Element, error) {
	digest := sha256.Sum256(bytes)
	return &Z7Element{V: uint64(digest[0] % 7)}, nil
}

func (f *Z7) ElementSize() int {
	return 1
}

func (f *Z7) WideElementSize() int {
	return 8
}

func (f *Z7) FromNat(nat *saferith.Nat) *Z7Element {
	panic("implement me")
}

type Z7Element struct {
	V uint64
}

func (fe *Z7Element) MarshalBinary() (data []byte, err error) {
	panic("implement me")
}

func (fe *Z7Element) UnmarshalBinary(data []byte) error {
	panic("implement me")
}

func (fe *Z7Element) Clone() *Z7Element {
	return &Z7Element{V: fe.V}
}

func (fe *Z7Element) Equal(rhs *Z7Element) bool {
	return fe.V == rhs.V
}

func (fe *Z7Element) HashCode() uint64 {
	return fe.V
}

func (fe *Z7Element) Structure() algebra.Structure[*Z7Element] {
	return Z7Instance
}

func (fe *Z7Element) Op(rhs *Z7Element) *Z7Element {
	return fe.Add(rhs)
}

func (fe *Z7Element) Order() algebra.Cardinal {
	panic("implement me")
}

func (fe *Z7Element) Add(rhs *Z7Element) *Z7Element {
	return &Z7Element{V: (fe.V + rhs.V) % 7}
}

func (fe *Z7Element) Double() *Z7Element {
	return fe.Add(fe)
}

func (fe *Z7Element) Mul(rhs *Z7Element) *Z7Element {
	return &Z7Element{V: (fe.V * rhs.V) % 7}
}

func (fe *Z7Element) Square() *Z7Element {
	return fe.Mul(fe)
}

func (fe *Z7Element) IsOpIdentity() bool {
	return fe.IsZero()
}

func (fe *Z7Element) IsOne() bool {
	return fe.V == 1
}

func (fe *Z7Element) OtherOp(rhs *Z7Element) *Z7Element {
	return fe.Mul(rhs)
}

func (fe *Z7Element) IsZero() bool {
	return fe.V == 0
}

func (fe *Z7Element) OpInv() *Z7Element {
	return fe.Neg()
}

func (fe *Z7Element) Neg() *Z7Element {
	return &Z7Element{V: 7 - fe.V}
}

func (fe *Z7Element) Sub(e *Z7Element) *Z7Element {
	return &Z7Element{V: (7 + fe.V - e.V) % 7}
}

func (fe *Z7Element) IsProbablyPrime() bool {
	panic("wtf?")
}

func (fe *Z7Element) EuclideanDiv(rhs *Z7Element) (quot, rem *Z7Element) {
	// TODO(aalireza): how to handle errors?
	q, _ := fe.TryDiv(rhs)
	return q, Z7Instance.Zero()
}

func (fe *Z7Element) TryInv() (*Z7Element, error) {
	return fe.Mul(fe).Mul(fe).Mul(fe).Mul(fe), nil
}

func (fe *Z7Element) TryDiv(e *Z7Element) (*Z7Element, error) {
	//if e.IsZero() {
	//	return nil, errs.NewFailed("division by zero")
	//}
	//
	//eInv := fe.Inv()
	//return fe.Mul(eInv), nil
	return nil, nil
}

func (fe *Z7Element) IsEven() bool {
	// TODO(aalireza): remove it?
	panic("implement me")
}

func (fe *Z7Element) IsOdd() bool {
	// TODO(aalireza): remove it?
	//TODO implement me
	panic("implement me")
}

func (fe *Z7Element) Nat() *saferith.Nat {
	return new(saferith.Nat).SetUint64(fe.V).Resize(3)
}
