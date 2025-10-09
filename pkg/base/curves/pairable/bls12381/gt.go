package bls12381

import (
	"hash/fnv"
	"io"
	"iter"
	"sync"

	"github.com/bronlabs/bron-crypto/pkg/base"
	"github.com/bronlabs/bron-crypto/pkg/base/algebra"
	bls12381Impl "github.com/bronlabs/bron-crypto/pkg/base/curves/pairable/bls12381/impl"
	"github.com/bronlabs/bron-crypto/pkg/base/errs"
	"github.com/bronlabs/bron-crypto/pkg/base/nt/cardinal"
)

const (
	GtName = "BLS12381Fp12Mul"
)

var (
	_ algebra.MultiplicativeGroup[*GtElement]        = (*Gt)(nil)
	_ algebra.MultiplicativeGroupElement[*GtElement] = (*GtElement)(nil)

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


func (g *Gt) ElementSize() int {
	return 96
}

func (g *Gt) Order() cardinal.Cardinal {
	//TODO implement me
	panic("implement me")
}

func (g *Gt) Hash(bytes []byte) (*GtElement, error) {
	panic("Hashing not implemented for Gt")
}

func (g *Gt) Random(prng io.Reader) (*GtElement, error) {
	panic("Random sampling not implemented for Gt")
}

func (g *Gt) Iter() iter.Seq[*GtElement] {
	panic("implement me")
}

func (g *Gt) One() *GtElement {
	var one GtElement
	one.V.SetOne()
	return &one
}

func (g *Gt) OpIdentity() *GtElement {
	return g.One()
}

func (g *Gt) FromBytes(inBytes []byte) (*GtElement, error) {
	if len(inBytes) != 96 {
		return nil, errs.NewLength("input must be 96 bytes long")
	}

	var element GtElement
	if ok := element.V.Fp12.SetUniformBytes(inBytes); ok == 0 {
		return nil, errs.NewFailed("failed to set bytes")
	}

	return &element, nil
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
	return ge.V.Equal(&rhs.V.Fp12) == 1
}

func (ge *GtElement) HashCode() base.HashCode {
	h := fnv.New64a()
	_, _ = h.Write(ge.V.Bytes())
	return base.HashCode(h.Sum64())
}

func (ge *GtElement) Bytes() []byte {
	return ge.V.Bytes()
}

func (ge *GtElement) Structure() algebra.Structure[*GtElement] {
	return NewGt()
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

func (ge *GtElement) String() string {
	//TODO implement me
	panic("implement me")
}
