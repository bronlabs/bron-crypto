package bls12381

import (
	"github.com/bronlabs/bron-crypto/pkg/base/curves"
	bls12381Impl "github.com/bronlabs/bron-crypto/pkg/base/curves/pairable/bls12381/impl"
	"github.com/bronlabs/bron-crypto/pkg/base/errs"
)

var (
	_ curves.PPE[*PointG1, *BaseFieldElementG1, *PointG2, *BaseFieldElementG2, *GtElement, *Scalar] = (*OptimalAtePPE)(nil)
)

const (
	OptimalAteAlgorithm curves.PairingAlgorithm = "OptimalAte"
)

func NewOptimalAtePPE() curves.PPE[*PointG1, *BaseFieldElementG1, *PointG2, *BaseFieldElementG2, *GtElement, *Scalar] {
	p := &OptimalAtePPE{
		engine: bls12381Impl.Engine{},
	}
	return p
}

type OptimalAtePPE struct {
	engine bls12381Impl.Engine
}

func (p *OptimalAtePPE) Add(g1 *PointG1, g2 *PointG2) error {
	if g1 == nil || g2 == nil || g1.IsZero() || g2.IsZero() {
		return errs.NewFailed("g1 or g2 cannot be nil/identity")
	}
	p.engine.AddPair(&g1.V, &g2.V)
	return nil
}

func (p *OptimalAtePPE) AddAndInvG1(g1 *PointG1, g2 *PointG2) error {
	if g1 == nil || g2 == nil || g1.IsZero() || g2.IsZero() {
		return errs.NewFailed("g1 or g2 cannot be nil/identity")
	}
	p.engine.AddPairInvG1(&g1.V, &g2.V)
	return nil
}

func (p *OptimalAtePPE) AddAndInvG2(g1 *PointG1, g2 *PointG2) error {
	if g1 == nil || g2 == nil || g1.IsZero() || g2.IsZero() {
		return errs.NewFailed("g1 or g2 cannot be nil/identity")
	}
	p.engine.AddPairInvG2(&g1.V, &g2.V)
	return nil
}

func (p *OptimalAtePPE) Result() *GtElement {
	var result GtElement
	result.V.Set(p.engine.Result())
	return &result
}

func (p *OptimalAtePPE) Check() bool {
	return p.engine.Check()
}

func (p *OptimalAtePPE) Reset() {
	p.engine.Reset()
}

func (p *OptimalAtePPE) Name() curves.PairingAlgorithm {
	return OptimalAteAlgorithm
}

func (p *OptimalAtePPE) Equal(other curves.PPE[*PointG1, *BaseFieldElementG1, *PointG2, *BaseFieldElementG2, *GtElement, *Scalar]) bool {
	if other == nil {
		return false
	}
	o, ok := other.(*OptimalAtePPE)
	if !ok {
		return false
	}
	return p.Name() != o.Name()
}

func (p *OptimalAtePPE) Type() curves.PairingType {
	return curves.TypeIII
}

// func NewPairing() curves.Pairing[*PointG1, *BaseFieldElementG1, *PointG2, *BaseFieldElementG2, *GtElement, *Scalar] {
// 	return &Pairing{
// 		core: NewOptimalAtePPE().(*OptimalAtePPE),
// 	}
// }

// type Pairing struct {
// 	core *OptimalAtePPE
// }

// func (p *Pairing) Name() curves.PairingAlgorithm {
// 	return OptimalAteAlgorithm
// }

// func (p *Pairing) Type() curves.PairingType {
// 	return curves.TypeIII
// }

// func (p *Pairing) Pair(g1 *PointG1, g2 *PointG2) (*GtElement, error) {
// 	defer p.core.Reset()
// 	if err := p.core.Add(g1, g2); err != nil {
// 		return nil, err
// 	}
// 	return p.core.Result(), nil
// }

// func (p *Pairing) MultiPair(g1 []*PointG1, g2 []*PointG2) (*GtElement, error) {
// 	defer p.core.Reset()
// 	if len(g1) != len(g2) {
// 		return nil, errs.NewFailed("g1 and g2 must have the same length")
// 	}

// 	for i := range g1 {
// 		if err := p.core.Add(g1[i], g2[i]); err != nil {
// 			return nil, err
// 		}
// 	}

// 	return p.core.Result(), nil
// }

// func (p *Pairing) Equal(other curves.Pairing[*PointG1, *BaseFieldElementG1, *PointG2, *BaseFieldElementG2, *GtElement, *Scalar]) bool {
// 	if other == nil {
// 		return false
// 	}
// 	o, ok := other.(*Pairing)
// 	if !ok {
// 		return false
// 	}
// 	return p.Name() == o.Name()
// }
