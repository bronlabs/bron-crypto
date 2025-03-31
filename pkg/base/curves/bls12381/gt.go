package bls12381

import (
	"github.com/bronlabs/bron-crypto/pkg/base/algebra"
	"github.com/bronlabs/bron-crypto/pkg/base/algebra/groups"
	bls12381Impl "github.com/bronlabs/bron-crypto/pkg/base/curves/bls12381/impl"
	"sync"
)

const (
	GtName = "BLS12381Fp12Mul"
)

var (
	_ groups.MultiplicativeGroup[*GtElement]        = (*Gt)(nil)
	_ groups.MultiplicativeGroupElement[*GtElement] = (*GtElement)(nil)

	gtInstance *Gt
	gtInitOnce sync.Once
)

type Gt struct{}

func NewGt() *Gt {
	gtInitOnce.Do(func() {
		gtInstance = &Gt{}
	})
	return gtInstance
}

func (g *Gt) Name() string {
	return GtName
}

func (g *Gt) Order() algebra.Cardinal {
	//TODO implement me
	panic("implement me")
}

func (g *Gt) Operator() algebra.BinaryOperator[*GtElement] {
	return algebra.Mul[*GtElement]
}

func (g *Gt) One() *GtElement {
	var one GtElement
	one.V.SetOne()
	return &one
}

func (g *Gt) OpIdentity() *GtElement {
	return g.One()
}

type GtElement struct {
	V bls12381Impl.Gt
}

func (ge *GtElement) Clone() *GtElement {
	var clone GtElement
	clone.V.Set(&ge.V.Fp12)
	return &clone
}

func (ge *GtElement) Equal(rhs *GtElement) bool {
	return ge.V.Equals(&rhs.V.Fp12) == 1
}

func (ge *GtElement) HashCode() uint64 {
	//TODO implement me
	panic("implement me")
}

func (ge *GtElement) Structure() algebra.Structure[*GtElement] {
	return NewGt()
}

func (ge *GtElement) MarshalBinary() (data []byte, err error) {
	//TODO implement me
	panic("implement me")
}

func (ge *GtElement) UnmarshalBinary(data []byte) error {
	//TODO implement me
	panic("implement me")
}

func (ge *GtElement) Mul(e *GtElement) *GtElement {
	var product GtElement
	product.V.Mul(&ge.V.Fp12, &e.V.Fp12)
	return &product
}

func (ge *GtElement) Square() *GtElement {
	var square GtElement
	square.V.Square(&ge.V.Fp12)
	return &square
}

func (ge *GtElement) IsOne() bool {
	return ge.V.IsOne() == 1
}

func (ge *GtElement) Inv() *GtElement {
	var inv GtElement
	_ = inv.V.Inv(&ge.V.Fp12)
	return &inv
}

func (ge *GtElement) Div(e *GtElement) *GtElement {
	var quotient GtElement
	_ = quotient.V.Div(&ge.V.Fp12, &e.V.Fp12)
	return &quotient
}

func (ge *GtElement) TryInv() (*GtElement, error) {
	return ge.Inv(), nil
}

func (ge *GtElement) TryDiv(e *GtElement) (*GtElement, error) {
	return ge.Div(e), nil
}

func (ge *GtElement) Op(e *GtElement) *GtElement {
	return ge.Mul(e)
}

func (ge *GtElement) IsOpIdentity() bool {
	return ge.IsOne()
}

func (ge *GtElement) TryOpInv() (*GtElement, error) {
	return ge.OpInv(), nil
}

func (ge *GtElement) OpInv() *GtElement {
	return ge.Inv()
}
