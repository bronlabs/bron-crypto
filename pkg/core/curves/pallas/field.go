package pallas

import (
	"io"
	"math/big"

	"github.com/copperexchange/knox-primitives/pkg/core/curves"
	"github.com/copperexchange/knox-primitives/pkg/core/curves/pallas/impl/fp"
	"github.com/copperexchange/knox-primitives/pkg/core/integration/helper_types"
)

var _ (curves.FieldProfile) = (*FieldProfile)(nil)

type FieldProfile struct{}

func (FieldProfile) Curve() curves.Curve {
	return pallasInstance
}

func (FieldProfile) Order() *big.Int {
	return fp.BiModulus
}

func (p *FieldProfile) Characteristic() *big.Int {
	return p.Order()
}

func (FieldProfile) ExtensionDegree() *big.Int {
	return big.NewInt(1)
}

var _ (curves.FieldElement) = (*FieldElement)(nil)

type FieldElement struct {
	v *fp.Fp

	_ helper_types.Incomparable
}

func (e *FieldElement) impl() *fp.Fp {
	return e.v
}

func (e FieldElement) Value() curves.FieldValue {
	return e.v.ToRaw()
}

func (FieldElement) Modulus() curves.FieldValue {
	return *fp.Modulus
}

func (e FieldElement) Clone() curves.FieldElement {
	return FieldElement{
		v: new(fp.Fp).Set(e.v),
	}
}

func (e FieldElement) Cmp(rhs curves.FieldElement) int {
	rhse, ok := rhs.(FieldElement)
	if !ok {
		return -2
	}
	return e.v.Cmp(rhse.impl())
}

func (FieldElement) Profile() curves.FieldProfile {
	return &FieldProfile{}
}

// IMPLEMENT
func (FieldElement) Hash(x []byte) curves.FieldElement {
	return nil
}

func (FieldElement) New(value int) curves.FieldElement {
	return nil
}

func (FieldElement) Random(prng io.Reader) curves.FieldElement {
	return nil
}

func (FieldElement) Zero() curves.FieldElement {
	return nil
}

func (FieldElement) One() curves.FieldElement {
	return nil
}

func (FieldElement) IsZero() bool {
	return false
}

func (FieldElement) IsOne() bool {
	return false
}

func (FieldElement) IsOdd() bool {
	return false
}

func (FieldElement) IsEven() bool {
	return false
}

func (FieldElement) Square() curves.FieldElement {
	return nil
}

func (FieldElement) Double() curves.FieldElement {
	return nil
}

func (FieldElement) Sqrt() curves.FieldElement {
	return nil
}

func (FieldElement) Cube() curves.FieldElement {
	return nil
}

func (FieldElement) Add(rhs curves.FieldElement) curves.FieldElement {
	return nil
}

func (FieldElement) Sub(rhs curves.FieldElement) curves.FieldElement {
	return nil
}

func (FieldElement) Mul(rhs curves.FieldElement) curves.FieldElement {
	return nil
}

func (FieldElement) MulAdd(y, z curves.FieldElement) curves.FieldElement {
	return nil
}

func (FieldElement) Div(rhs curves.FieldElement) curves.FieldElement {
	return nil
}

func (FieldElement) Exp(rhs curves.FieldElement) curves.FieldElement {
	return nil
}

func (FieldElement) Neg() curves.FieldElement {
	return nil
}

func (FieldElement) SetBigInt(value *big.Int) (curves.FieldElement, error) {
	return nil, nil
}

func (FieldElement) BigInt() *big.Int {
	return nil
}

func (FieldElement) SetBytes(input []byte) (curves.FieldElement, error) {
	return nil, nil
}

func (FieldElement) SetBytesWide(input []byte) (curves.FieldElement, error) {
	return nil, nil
}

func (FieldElement) Bytes() []byte {
	return nil
}

func (FieldElement) FromScalar(sc curves.Scalar) (curves.FieldElement, error) {
	return nil, nil
}

func (FieldElement) Scalar() (curves.FieldElement, error) {
	return nil, nil
}
