package edwards25519

import (
	"io"

	"filippo.io/edwards25519/field"
	"github.com/cronokirby/saferith"

	"github.com/copperexchange/knox-primitives/pkg/core/curves"
	"github.com/copperexchange/knox-primitives/pkg/core/errs"
	"github.com/copperexchange/knox-primitives/pkg/core/integration/helper_types"
)

type FieldProfileEd25519 struct{}

func (*FieldProfileEd25519) Curve() curves.Curve {
	return &edwards25519Instance
}

func (*FieldProfileEd25519) Order() *saferith.Modulus {
	return baseFieldOrder
}

func (*FieldProfileEd25519) Characteristic() *saferith.Nat {
	return baseFieldOrder.Nat()
}

func (*FieldProfileEd25519) ExtensionDegree() *saferith.Nat {
	return new(saferith.Nat).SetUint64(1)
}

var _ curves.FieldElement = (*FieldElementEd25519)(nil)

type FieldElementEd25519 struct {
	v *field.Element

	_ helper_types.Incomparable
}

func (*FieldElementEd25519) Profile() curves.FieldProfile {
	return &FieldProfileEd25519{}
}

// Hash TODO: implement
func (*FieldElementEd25519) Hash(x []byte) curves.FieldElement {
	return nil
}

func (*FieldElementEd25519) Value() curves.FieldValue {
	return nil
}

func (*FieldElementEd25519) Modulus() *saferith.Modulus {
	return baseFieldOrder
}

func (e *FieldElementEd25519) Clone() curves.FieldElement {
	return &FieldElementEd25519{
		v: e.v,
	}
}

func (e *FieldElementEd25519) Cmp(rhs curves.FieldElement) int {
	n, ok := rhs.(*FieldElementEd25519)
	if !ok {
		return -2
	}
	if e.v.Equal(n.v) == 1 {
		return 0
	}
	v := e.v.Subtract(e.v, n.v)
	if v.IsNegative() == 1 {
		return -1
	}
	return 1
}

func (*FieldElementEd25519) New(value uint64) curves.FieldElement {
	return nil
}

func (*FieldElementEd25519) Random(prng io.Reader) curves.FieldElement {
	return nil
}

func (e *FieldElementEd25519) Zero() curves.FieldElement {
	return &FieldElementEd25519{
		v: e.v.Zero(),
	}
}

func (e *FieldElementEd25519) One() curves.FieldElement {
	return &FieldElementEd25519{
		v: e.v.One(),
	}
}

func (*FieldElementEd25519) IsZero() bool {
	return false
}

func (*FieldElementEd25519) IsOne() bool {
	return false
}

func (*FieldElementEd25519) IsOdd() bool {
	return false
}

func (*FieldElementEd25519) IsEven() bool {
	return false
}

func (e *FieldElementEd25519) Square() curves.FieldElement {
	return &FieldElementEd25519{
		v: e.v.Square(e.v),
	}
}

func (e *FieldElementEd25519) Double() curves.FieldElement {
	return e.Add(e)
}

func (*FieldElementEd25519) Sqrt() (curves.FieldElement, bool) {
	return nil, false
}

func (e *FieldElementEd25519) Cube() curves.FieldElement {
	return e.Square().Mul(e)
}

func (e *FieldElementEd25519) Add(rhs curves.FieldElement) curves.FieldElement {
	n, ok := rhs.(*FieldElementEd25519)
	if !ok {
		panic("rhs is not an edwards25519 base field element")
	}
	return &FieldElementEd25519{
		v: e.v.Add(e.v, n.v),
	}
}

func (e *FieldElementEd25519) Sub(rhs curves.FieldElement) curves.FieldElement {
	n, ok := rhs.(*FieldElementEd25519)
	if !ok {
		panic("rhs is not an edwards25519 base field element")
	}
	return &FieldElementEd25519{
		v: e.v.Subtract(e.v, n.v),
	}
}

func (e *FieldElementEd25519) Mul(rhs curves.FieldElement) curves.FieldElement {
	n, ok := rhs.(*FieldElementEd25519)
	if !ok {
		panic("rhs is not an edwards25519 base field element")
	}
	return &FieldElementEd25519{
		v: e.v.Multiply(e.v, n.v),
	}
}

func (e *FieldElementEd25519) MulAdd(y, z curves.FieldElement) curves.FieldElement {
	return e.Mul(y).Add(z)
}

func (e *FieldElementEd25519) Div(rhs curves.FieldElement) curves.FieldElement {
	inverted := e.v.Invert(e.v)
	zero := new(field.Element).Zero()
	if inverted.Equal(zero) == 1 {
		panic("could not invert")
	}
	return &FieldElementEd25519{
		v: e.v.Multiply(e.v, inverted),
	}
}

func (*FieldElementEd25519) Exp(rhs curves.FieldElement) curves.FieldElement {
	return nil
}

func (e *FieldElementEd25519) Neg() curves.FieldElement {
	return &FieldElementEd25519{
		v: e.v.Negate(e.v),
	}
}

func (*FieldElementEd25519) SetNat(value *saferith.Nat) (curves.FieldElement, error) {
	return nil, nil
}

func (*FieldElementEd25519) Nat() *saferith.Nat {
	return nil
}

func (*FieldElementEd25519) SetBytes(input []byte) (curves.FieldElement, error) {
	return nil, nil
}

func (e *FieldElementEd25519) SetBytesWide(input []byte) (curves.FieldElement, error) {
	result, err := e.v.SetBytes(input)
	if err != nil {
		return nil, errs.WrapSerializationError(err, "could not set bytes")
	}
	return &FieldElementEd25519{
		v: result,
	}, nil
}

func (e *FieldElementEd25519) Bytes() []byte {
	return e.v.Bytes()
}

func (*FieldElementEd25519) FromScalar(sc curves.Scalar) (curves.FieldElement, error) {
	return nil, nil
}

func (*FieldElementEd25519) Scalar(curve curves.Curve) (curves.Scalar, error) {
	return nil, nil
}
