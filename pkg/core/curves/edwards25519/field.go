package edwards25519

import (
	"io"
	"math/big"

	"github.com/copperexchange/knox-primitives/pkg/core/curves"
	"github.com/copperexchange/knox-primitives/pkg/core/curves/impl"
)

// TODO: finish when filippo is forked
type FieldProfile struct{}

func (FieldProfile) Curve() curves.Curve {
	return edwards25519Instance
}

func (FieldProfile) Order() *big.Int {
	return nil
}

func (p *FieldProfile) Characteristic() *big.Int {
	return nil
}

func (FieldProfile) ExtensionDegree() *big.Int {
	return nil
}

var _ (curves.FieldElement) = (*FieldElement)(nil)

type FieldElement struct {
	v *impl.Field
}

//nolint:revive // we don't care if impl shadows impl
func (e *FieldElement) impl() *impl.Field {
	return e.v
}

func (FieldElement) Profile() curves.FieldProfile {
	return &FieldProfile{}
}

// IMPLEMENT
func (FieldElement) Hash(x []byte) curves.FieldElement {
	return nil
}

func (e FieldElement) Value() curves.FieldValue {
	return e.v.Value
}

func (e FieldElement) Modulus() curves.FieldValue {
	return e.v.Params.Modulus
}

func (FieldElement) Clone() curves.FieldElement {
	return nil
}

func (e FieldElement) Cmp(rhs curves.FieldElement) int {
	rhse, ok := rhs.(FieldElement)
	if !ok {
		return -2
	}
	return e.v.Cmp(rhse.impl())
}

func (e FieldElement) New(value int) curves.FieldElement {
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
