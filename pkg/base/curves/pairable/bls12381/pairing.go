package bls12381

import (
	"github.com/bronlabs/bron-crypto/pkg/base/curves"
	bls12381Impl "github.com/bronlabs/bron-crypto/pkg/base/curves/pairable/bls12381/impl"
)

var (
	_ curves.PPE[*PointG1, *BaseFieldElementG1, *PointG2, *BaseFieldElementG2, *GtElement, *Scalar] = (*OptimalAtePPE)(nil)
)

const (
	OptimalAteAlgorithm curves.PairingAlgorithm = "OptimalAte"
)

// NewOptimalAtePPE returns the optimal ate pairing engine.
func NewOptimalAtePPE() curves.PPE[*PointG1, *BaseFieldElementG1, *PointG2, *BaseFieldElementG2, *GtElement, *Scalar] {
	p := &OptimalAtePPE{
		engine: bls12381Impl.Engine{},
	}
	return p
}

// OptimalAtePPE implements the optimal ate pairing engine.
type OptimalAtePPE struct {
	engine bls12381Impl.Engine
}

// Add sets the receiver to lhs + rhs.
func (p *OptimalAtePPE) Add(g1 *PointG1, g2 *PointG2) error {
	if g1 == nil || g2 == nil || g1.IsZero() || g2.IsZero() {
		return curves.ErrFailed.WithMessage("g1 or g2 cannot be nil/identity")
	}
	p.engine.AddPair(&g1.V, &g2.V)
	return nil
}

// AddAndInvG1 adds a pair with G1 inverted.
func (p *OptimalAtePPE) AddAndInvG1(g1 *PointG1, g2 *PointG2) error {
	if g1 == nil || g2 == nil || g1.IsZero() || g2.IsZero() {
		return curves.ErrFailed.WithMessage("g1 or g2 cannot be nil/identity")
	}
	p.engine.AddPairInvG1(&g1.V, &g2.V)
	return nil
}

// AddAndInvG2 adds a pair with G2 inverted.
func (p *OptimalAtePPE) AddAndInvG2(g1 *PointG1, g2 *PointG2) error {
	if g1 == nil || g2 == nil || g1.IsZero() || g2.IsZero() {
		return curves.ErrFailed.WithMessage("g1 or g2 cannot be nil/identity")
	}
	p.engine.AddPairInvG2(&g1.V, &g2.V)
	return nil
}

// Result returns the accumulated pairing result.
func (p *OptimalAtePPE) Result() *GtElement {
	var result GtElement
	result.V.Set(p.engine.Result())
	return &result
}

// Check verifies the accumulated pairing.
func (p *OptimalAtePPE) Check() bool {
	return p.engine.Check()
}

// Reset clears the pairing engine state.
func (p *OptimalAtePPE) Reset() {
	p.engine.Reset()
}

// Name returns the name of the structure.
func (p *OptimalAtePPE) Name() curves.PairingAlgorithm {
	return OptimalAteAlgorithm
}

// Equal reports whether the receiver equals v.
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

// Type returns the pairing type.
func (p *OptimalAtePPE) Type() curves.PairingType {
	return curves.TypeIII
}

// func NewPairing() curves.Pairing[*PointG1, *BaseFieldElementG1, *PointG2, *BaseFieldElementG2, *GtElement, *Scalar] {
// 	return &Pairing{
// 		core: NewOptimalAtePPE().(*OptimalAtePPE),
// 	}
// }.

// type Pairing struct {
// 	core *OptimalAtePPE
// }.

// func (p *Pairing) Name() curves.PairingAlgorithm {
// 	return OptimalAteAlgorithm
// }.

// func (p *Pairing) Type() curves.PairingType {
// 	return curves.TypeIII
// }.

// func (p *Pairing) Pair(g1 *PointG1, g2 *PointG2) (*GtElement, error) {
// 	defer p.core.Reset()
// 	if err := p.core.Add(g1, g2); err != nil {
// 		return nil, err
// 	}
// 	return p.core.Result(), nil
// }.

// func (p *Pairing) MultiPair(g1 []*PointG1, g2 []*PointG2) (*GtElement, error) {
// 	defer p.core.Reset()
// 	if len(g1) != len(g2) {
// 		return nil, curves.ErrFailed.WithMessage("g1 and g2 must have the same length")
// 	}

// 	for i := range g1 {
// 		if err := p.core.Add(g1[i], g2[i]); err != nil {
// 			return nil, err
// 		}
// 	}

// 	return p.core.Result(), nil
// }.

// func (p *Pairing) Equal(other curves.Pairing[*PointG1, *BaseFieldElementG1, *PointG2, *BaseFieldElementG2, *GtElement, *Scalar]) bool {
// 	if other == nil {
// 		return false
// 	}
// 	o, ok := other.(*Pairing)
// 	if !ok {
// 		return false
// 	}
// 	return p.Name() == o.Name()
// }.
