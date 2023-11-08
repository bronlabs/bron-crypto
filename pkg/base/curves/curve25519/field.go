package curve25519

import (
	"io"

	"github.com/cronokirby/saferith"

	"github.com/copperexchange/krypton-primitives/pkg/base/constants"
	"github.com/copperexchange/krypton-primitives/pkg/base/curves"
	"github.com/copperexchange/krypton-primitives/pkg/base/types"
)

type FieldProfile struct{}

func (*FieldProfile) Curve() curves.Curve {
	return &curve25519Instance
}

func (*FieldProfile) Order() *saferith.Modulus {
	return baseFieldOrder
}

func (*FieldProfile) Characteristic() *saferith.Nat {
	return baseFieldOrder.Nat()
}

func (*FieldProfile) ExtensionDegree() *saferith.Nat {
	return new(saferith.Nat).SetUint64(1)
}

func (*FieldProfile) FieldBytes() int {
	return constants.FieldBytes
}

func (*FieldProfile) WideFieldBytes() int {
	return constants.WideFieldBytes
}

var _ curves.FieldElement = (*FieldElement)(nil)

type FieldElement struct {
	v [constants.FieldBytes]byte

	_ types.Incomparable
}

func (*FieldElement) Profile() curves.FieldProfile {
	return &FieldProfile{}
}

func (*FieldElement) Hash(x []byte) (curves.FieldElement, error) {
	// TODO implement me
	panic("implement me")
}

func (*FieldElement) Value() curves.FieldValue {
	// TODO implement me
	panic("implement me")
}

func (*FieldElement) Modulus() *saferith.Modulus {
	// TODO implement me
	panic("implement me")
}

func (e *FieldElement) Clone() curves.FieldElement {
	return &FieldElement{
		v: e.v,
	}
}

func (*FieldElement) SubfieldElement(index uint64) curves.FieldElement {
	// TODO implement me
	panic("implement me")
}

func (*FieldElement) Cmp(rhs curves.FieldElement) int {
	// TODO implement me
	panic("implement me")
}

func (*FieldElement) New(value uint64) curves.FieldElement {
	// TODO implement me
	panic("implement me")
}

func (*FieldElement) Random(prng io.Reader) (curves.FieldElement, error) {
	// TODO implement me
	panic("implement me")
}

func (*FieldElement) Zero() curves.FieldElement {
	// TODO implement me
	panic("implement me")
}

func (*FieldElement) One() curves.FieldElement {
	// TODO implement me
	panic("implement me")
}

func (*FieldElement) IsZero() bool {
	// TODO implement me
	panic("implement me")
}

func (*FieldElement) IsOne() bool {
	// TODO implement me
	panic("implement me")
}

func (*FieldElement) IsOdd() bool {
	return false
}

func (*FieldElement) IsEven() bool {
	// TODO implement me
	panic("implement me")
}

func (*FieldElement) Square() curves.FieldElement {
	// TODO implement me
	panic("implement me")
}

func (*FieldElement) Double() curves.FieldElement {
	// TODO implement me
	panic("implement me")
}

func (*FieldElement) Sqrt() (curves.FieldElement, bool) {
	// TODO implement me
	panic("implement me")
}

func (*FieldElement) Cube() curves.FieldElement {
	// TODO implement me
	panic("implement me")
}

func (*FieldElement) Add(rhs curves.FieldElement) curves.FieldElement {
	// TODO implement me
	panic("implement me")
}

func (*FieldElement) Sub(rhs curves.FieldElement) curves.FieldElement {
	// TODO implement me
	panic("implement me")
}

func (*FieldElement) Mul(rhs curves.FieldElement) curves.FieldElement {
	// TODO implement me
	panic("implement me")
}

func (*FieldElement) MulAdd(y, z curves.FieldElement) curves.FieldElement {
	// TODO implement me
	panic("implement me")
}

func (*FieldElement) Div(rhs curves.FieldElement) curves.FieldElement {
	// TODO implement me
	panic("implement me")
}

func (*FieldElement) Exp(rhs curves.FieldElement) curves.FieldElement {
	// TODO implement me
	panic("implement me")
}

func (*FieldElement) Neg() curves.FieldElement {
	// TODO implement me
	panic("implement me")
}

func (*FieldElement) SetNat(value *saferith.Nat) (curves.FieldElement, error) {
	// TODO implement me
	panic("implement me")
}

func (*FieldElement) Nat() *saferith.Nat {
	// TODO implement me
	panic("implement me")
}

func (*FieldElement) SetBytes(input []byte) (curves.FieldElement, error) {
	// TODO implement me
	panic("implement me")
}

func (*FieldElement) SetBytesWide(input []byte) (curves.FieldElement, error) {
	// TODO implement me
	panic("implement me")
}

func (e *FieldElement) Bytes() []byte {
	return e.v[:]
}

func (*FieldElement) FromScalar(sc curves.Scalar) (curves.FieldElement, error) {
	// TODO implement me
	panic("implement me")
}

func (*FieldElement) Scalar(curve curves.Curve) (curves.Scalar, error) {
	return nil, nil
}
