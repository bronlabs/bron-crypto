package bls12381

import (
	bls12381Impl "github.com/bronlabs/bron-crypto/pkg/base/curves/bls12381/impl"
	"github.com/bronlabs/bron-crypto/pkg/base/errs"
)

type Pairing struct {
	engine bls12381Impl.Engine
}

func NewPairing() *Pairing {
	p := &Pairing{}
	p.engine.Reset()
	return p
}

func (p *Pairing) Add(g1 *PointG1, g2 *PointG2) error {
	if g1 == nil || g2 == nil || g1.IsZero() || g2.IsZero() {
		return errs.NewFailed("g1 or g2 cannot be nil/identity")
	}

	p.engine.AddPair(&g1.V, &g2.V)
	return nil
}

func (p *Pairing) Result() *GtElement {
	var result GtElement
	result.V.Set(p.engine.Result())
	return &result
}
