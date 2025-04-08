package bls12381

import (
	"github.com/bronlabs/bron-crypto/pkg/base/curves"
	bls12381Impl "github.com/bronlabs/bron-crypto/pkg/base/curves/bls12381/impl"
)

var (
	_ curves.Pairing[*CurveG1, *PointG1, *BaseFieldElementG1, *CurveG2, *PointG2, *BaseFieldElementG2, *Gt, *GtElement, *Scalar] = (*BlsPairing)(nil)
)

type BlsPairing struct{}

func (p *BlsPairing) G1() *CurveG1 {
	return NewG1Curve()
}

func (p *BlsPairing) G2() *CurveG2 {
	return NewG2Curve()
}

func (p *BlsPairing) Gt() *Gt {
	return NewGt()
}

func (p *BlsPairing) Pair(q1 *PointG1, q2 *PointG2) (*GtElement, error) {
	engine := new(bls12381Impl.Engine)
	engine.Reset()
	engine.AddPair(&q1.V, &q2.V)
	raw := engine.Result()

	var result GtElement
	result.V.Fp12.Set(raw)
	return &result, nil
}

func (p *BlsPairing) MultiPair(q1s []*PointG1, q2s []*PointG2) (*GtElement, error) {
	engine := new(bls12381Impl.Engine)
	engine.Reset()
	for i := range q1s {
		engine.AddPair(&q1s[i].V, &q2s[i].V)
	}
	raw := engine.Result()

	var result GtElement
	result.V.Fp12.Set(raw)
	return &result, nil
}
