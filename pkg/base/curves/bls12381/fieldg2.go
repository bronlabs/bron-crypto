package bls12381

import (
	"io"

	"github.com/cronokirby/saferith"

	"github.com/copperexchange/krypton-primitives/pkg/base"
	"github.com/copperexchange/krypton-primitives/pkg/base/bitstring"
	"github.com/copperexchange/krypton-primitives/pkg/base/curves"
	bimpl "github.com/copperexchange/krypton-primitives/pkg/base/curves/bls12381/impl"
	"github.com/copperexchange/krypton-primitives/pkg/base/errs"
	"github.com/copperexchange/krypton-primitives/pkg/base/types"
)

const (
	ExtensionDegree = 2
	FieldBytes      = base.FieldBytes * ExtensionDegree
	WideFieldBytes  = base.WideFieldBytes * ExtensionDegree
)

var _ curves.FieldProfile = (*FieldProfileG2)(nil)

type FieldProfileG2 struct{}

func (*FieldProfileG2) Order() *saferith.Modulus {
	return saferith.ModulusFromNat(new(saferith.Nat).Mul(p.Nat(), p.Nat(), -1))
}

func (*FieldProfileG2) Characteristic() *saferith.Nat {
	return p.Nat()
}

func (*FieldProfileG2) ExtensionDegree() *saferith.Nat {
	return new(saferith.Nat).SetUint64(ExtensionDegree)
}

func (*FieldProfileG2) FieldBytes() int {
	return bimpl.FieldBytes
}

func (*FieldProfileG2) WideFieldBytes() int {
	return bimpl.WideFieldBytes
}

var _ curves.FieldElement = (*FieldElementG2)(nil)

type FieldElementG2 struct {
	v *bimpl.Fp2

	_ types.Incomparable
}

func (*FieldElementG2) Value() curves.FieldValue {
	return nil
}

func (e *FieldElementG2) Modulus() *saferith.Modulus {
	return e.Profile().Order()
}

func (e *FieldElementG2) Clone() curves.FieldElement {
	return &FieldElementG2{
		v: new(bimpl.Fp2).Set(e.v),
	}
}

func (*FieldElementG2) Cmp(rhs curves.FieldElement) int {
	panic("not implemented")
}

func (*FieldElementG2) Profile() curves.FieldProfile {
	return &FieldProfileG2{}
}

func (*FieldElementG2) Hash(x []byte) (curves.FieldElement, error) {
	els, err := NewG2().HashToFieldElements(1, x, nil)
	if err != nil {
		return nil, errs.WrapFailed(err, "could not hash to field element in bls12381 G1")
	}
	return els[0], nil
}

func (*FieldElementG2) New(value uint64) curves.FieldElement {
	return nil
}

func (e *FieldElementG2) Random(prng io.Reader) (curves.FieldElement, error) {
	result, err := e.v.Random(prng)
	if err != nil {
		return nil, errs.WrapRandomSampleFailed(err, "could not sample random element in bls12381 G2")
	}
	return &FieldElementG2{v: result}, nil
}

func (*FieldElementG2) Zero() curves.FieldElement {
	return &FieldElementG2{
		v: new(bimpl.Fp2).SetZero(),
	}
}

func (*FieldElementG2) One() curves.FieldElement {
	return &FieldElementG2{
		v: new(bimpl.Fp2).SetOne(),
	}
}

func (e *FieldElementG2) IsZero() bool {
	return e.v.IsZero() == 1
}

func (e *FieldElementG2) IsOne() bool {
	return e.v.IsOne() == 1
}

func (e *FieldElementG2) IsOdd() bool {
	return e.Bytes()[0]&1 == 1
}

func (e *FieldElementG2) IsEven() bool {
	return e.Bytes()[0]&1 == 0
}

func (e *FieldElementG2) Square() curves.FieldElement {
	return &FieldElementG2{
		v: new(bimpl.Fp2).Square(e.v),
	}
}

func (e *FieldElementG2) SubfieldElement(index uint64) curves.FieldElement {
	if index&0x1 == 0 {
		return &FieldElementG1{
			v: &e.v.A,
		}
	} else {
		return &FieldElementG1{
			v: &e.v.B,
		}
	}
}

func (e *FieldElementG2) Double() curves.FieldElement {
	return &FieldElementG2{
		v: new(bimpl.Fp2).Double(e.v),
	}
}

func (e *FieldElementG2) Sqrt() (curves.FieldElement, bool) {
	result, wasSquare := new(bimpl.Fp2).Sqrt(e.v)
	return &FieldElementG2{
		v: result,
	}, wasSquare == 1
}

func (e *FieldElementG2) Cube() curves.FieldElement {
	return e.Square().Mul(e)
}

func (e *FieldElementG2) Add(rhs curves.FieldElement) curves.FieldElement {
	n, ok := rhs.(*FieldElementG2)
	if !ok {
		panic("not a bls12381 G2 Fp2 element")
	}
	return &FieldElementG2{
		v: new(bimpl.Fp2).Add(e.v, n.v),
	}
}

func (e *FieldElementG2) Sub(rhs curves.FieldElement) curves.FieldElement {
	n, ok := rhs.(*FieldElementG2)
	if !ok {
		panic("not a bls12381 G2 Fp2 element")
	}
	return &FieldElementG2{
		v: new(bimpl.Fp2).Sub(e.v, n.v),
	}
}

func (e *FieldElementG2) Mul(rhs curves.FieldElement) curves.FieldElement {
	n, ok := rhs.(*FieldElementG2)
	if !ok {
		panic("not a bls12381 G2 Fp2 element")
	}
	return &FieldElementG2{
		v: new(bimpl.Fp2).Mul(e.v, n.v),
	}
}

func (e *FieldElementG2) MulAdd(y, z curves.FieldElement) curves.FieldElement {
	return e.Mul(y).Add(z)
}

func (e *FieldElementG2) Div(rhs curves.FieldElement) curves.FieldElement {
	r, ok := rhs.(*FieldElementG2)
	if ok {
		v, wasInverted := new(bimpl.Fp2).Invert(r.v)
		if wasInverted != 1 {
			panic("cannot invert rhs")
		}
		v.Mul(v, e.v)
		return &FieldElementG2{v: v}
	} else {
		panic("rhs is not bls12381 G2 Fp2 field element")
	}
}

func (*FieldElementG2) Exp(rhs curves.FieldElement) curves.FieldElement {
	return nil
}

func (e *FieldElementG2) Neg() curves.FieldElement {
	return &FieldElementG2{
		v: new(bimpl.Fp2).Neg(e.v),
	}
}

func (e *FieldElementG2) SetNat(value *saferith.Nat) (curves.FieldElement, error) {
	return e.SetBytes(value.Bytes())
}

func (e *FieldElementG2) Nat() *saferith.Nat {
	aNat := e.v.A.Nat()
	bNat := e.v.B.Nat()
	nat := bNat.Add(bNat, aNat.Mul(aNat, e.Profile().Order().Nat(), WideFieldBytes), WideFieldBytes)
	return nat
}

func (e *FieldElementG2) SetBytes(input []byte) (curves.FieldElement, error) {
	if len(input) != FieldBytes {
		return nil, errs.NewInvalidLength("input length (%d != %d bytes)", len(input), FieldBytes)
	}
	input = bitstring.ReverseBytes(input)
	a, oka := e.v.A.SetBytes((*[bimpl.FieldBytes]byte)(input[:bimpl.FieldBytes]))
	b, okb := e.v.B.SetBytes((*[bimpl.FieldBytes]byte)(input[bimpl.FieldBytes:]))
	if oka != 1 || okb != 1 {
		return nil, errs.NewFailed("could not set byte")
	}
	return &FieldElementG2{
		v: &bimpl.Fp2{
			A: *a,
			B: *b,
		},
	}, nil
}

func (*FieldElementG2) SetBytesWide(input []byte) (curves.FieldElement, error) {
	if len(input) > WideFieldBytes {
		return nil, errs.NewInvalidLength("input length > %d bytes", WideFieldBytes)
	}
	var buffer [WideFieldBytes]byte
	copy(buffer[:], input) // pad with zeroes
	a, err := NewG1().FieldElement().SetBytesWide(buffer[0:FieldBytes])
	if err != nil {
		return nil, errs.WrapHashingFailed(err, "could not set bytes of bls12381 G2 Fp2 field element A")
	}
	b, err := NewG1().FieldElement().SetBytesWide(buffer[FieldBytes:WideFieldBytes])
	if err != nil {
		return nil, errs.WrapHashingFailed(err, "could not set bytes of bls12381 G2 Fp2 field element B")
	}
	aG1, _ := a.(*FieldElementG1)
	bG1, _ := b.(*FieldElementG1)
	return &FieldElementG2{
		v: &bimpl.Fp2{
			A: *aG1.v,
			B: *bG1.v,
		},
	}, nil
}

func (*FieldElementG2) Bytes() []byte {
	// TODO: Makes some weird pieces break when implemented
	return nil
}

func (*FieldElementG2) FromScalar(sc curves.Scalar) (curves.FieldElement, error) {
	return nil, errs.NewMissing("not implemented")
}

func (*FieldElementG2) Scalar(curve curves.Curve) (curves.Scalar, error) {
	return nil, errs.NewMissing("not implemented")
}
