package p256

import (
	"io"
	"math/big"

	"github.com/copperexchange/knox-primitives/pkg/core/curves"
	"github.com/copperexchange/knox-primitives/pkg/core/curves/impl"
	"github.com/copperexchange/knox-primitives/pkg/core/curves/p256/impl/fq"
)

var _ (curves.Element) = (*Element)(nil)

type Element struct {
	v *impl.Field
}

//nolint:revive // we don't care if impl shadows impl
func (e *Element) impl() *impl.Field {
	return e.v
}

func (e Element) Value() curves.FieldValue {
	return e.v.Value
}

func (e Element) Modulus() curves.FieldValue {
	return e.v.Params.Modulus
}

func (e Element) Clone() curves.Element {
	return Element{
		v: fq.P256FqNew().Set(e.v),
	}
}

func (e Element) Cmp(rhs curves.Element) int {
	rhse, ok := rhs.(Element)
	if !ok {
		return -2
	}
	return e.v.Cmp(rhse.impl())
}

func (Element) Random(prng io.Reader) curves.Element {
	return nil
}

func (Element) Zero() curves.Element {
	return nil
}

func (Element) One() curves.Element {
	return nil
}

func (Element) IsZero() bool {
	return false
}

func (Element) IsOne() bool {
	return false
}

func (Element) IsOdd() bool {
	return false
}

func (Element) IsEven() bool {
	return false
}

func (Element) Square() curves.Element {
	return nil
}

func (Element) Double() curves.Element {
	return nil
}

func (Element) Sqrt() curves.Element {
	return nil
}

func (Element) Cube() curves.Element {
	return nil
}

func (Element) Add(rhs curves.Element) curves.Element {
	return nil
}

func (Element) Sub(rhs curves.Element) curves.Element {
	return nil
}

func (Element) Mul(rhs curves.Element) curves.Element {
	return nil
}

func (Element) MulAdd(y, z curves.Element) curves.Element {
	return nil
}

func (Element) Div(rhs curves.Element) curves.Element {
	return nil
}

func (Element) Exp(rhs curves.Element) curves.Element {
	return nil
}

func (Element) Neg() curves.Element {
	return nil
}

func (Element) SetBigInt(value, modulus *big.Int) {}
func (e Element) BigInt() *big.Int {
	return e.v.BigInt()
}

func (Element) SetBytes(input []byte) (curves.Element, error) {
	return nil, nil
}

func (Element) SetBytesWide(input []byte) (curves.Element, error) {
	return nil, nil
}

func (Element) Bytes() []byte {
	return nil
}

func (Element) FromScalar(sc curves.Scalar) (curves.Element, error) {
	return nil, nil
}

func (Element) Scalar(c curves.Curve) (curves.Element, error) {
	return nil, nil
}
