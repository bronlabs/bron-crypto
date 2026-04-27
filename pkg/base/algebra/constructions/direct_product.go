package constructions

import (
	"github.com/bronlabs/errs-go/errs"

	"github.com/bronlabs/bron-crypto/pkg/base/algebra"
	"github.com/bronlabs/bron-crypto/pkg/base/algebra/constructions/traits"
)

// =========== Group ===========.

func NewDirectProductGroup[G1 algebra.Group[E1], G2 algebra.Group[E2], E1 algebra.GroupElement[E1], E2 algebra.GroupElement[E2]](g1 G1, g2 G2) (*DirectProductGroup[G1, G2, E1, E2], error) {
	out := &DirectProductGroup[G1, G2, E1, E2]{}
	if err := out.Set(g1, g2); err != nil {
		return nil, errs.Wrap(err).WithMessage("failed to set groups")
	}
	var _ algebra.Group[*DirectProductGroupElement[E1, E2]] = out
	return out, nil
}

type DirectProductGroup[G1 algebra.Group[E1], G2 algebra.Group[E2], E1 algebra.GroupElement[E1], E2 algebra.GroupElement[E2]] struct {
	traits.DirectProductGroup[G1, G2, E1, E2, *DirectProductGroupElement[E1, E2], DirectProductGroupElement[E1, E2]]
}

func NewFiniteDirectProductGroup[G1 algebra.FiniteGroup[E1], G2 algebra.FiniteGroup[E2], E1 algebra.GroupElement[E1], E2 algebra.GroupElement[E2]](g1 G1, g2 G2) (*FiniteDirectProductGroup[G1, G2, E1, E2], error) {
	out := &FiniteDirectProductGroup[G1, G2, E1, E2]{}
	if err := out.Set(g1, g2); err != nil {
		return nil, errs.Wrap(err).WithMessage("failed to set groups")
	}
	if err := out.SetFiniteStructureAttributes(g1, g2); err != nil {
		return nil, errs.Wrap(err).WithMessage("failed to set finite structure attributes")
	}
	var _ algebra.Group[*FiniteDirectProductGroupElement[E1, E2]] = out
	return out, nil
}

type FiniteDirectProductGroup[G1 algebra.FiniteGroup[E1], G2 algebra.FiniteGroup[E2], E1 algebra.GroupElement[E1], E2 algebra.GroupElement[E2]] struct {
	traits.DirectProductGroup[G1, G2, E1, E2, *FiniteDirectProductGroupElement[E1, E2], FiniteDirectProductGroupElement[E1, E2]]
	traits.DirectProductOfFiniteStructures[G1, G2, E1, E2, *FiniteDirectProductGroupElement[E1, E2], FiniteDirectProductGroupElement[E1, E2]]
}

type DirectProductGroupElement[E1 algebra.GroupElement[E1], E2 algebra.GroupElement[E2]] struct {
	traits.DirectProductGroupElement[E1, E2, *DirectProductGroupElement[E1, E2], DirectProductGroupElement[E1, E2]]
}

func (g *DirectProductGroupElement[E1, E2]) Structure() algebra.Structure[*DirectProductGroupElement[E1, E2]] {
	c1, c2 := g.Components()
	group1 := algebra.StructureMustBeAs[algebra.Group[E1]](c1.Structure())
	group2 := algebra.StructureMustBeAs[algebra.Group[E2]](c2.Structure())
	out, _ := NewDirectProductGroup(group1, group2)
	return out
}

type FiniteDirectProductGroupElement[E1 algebra.GroupElement[E1], E2 algebra.GroupElement[E2]] struct {
	traits.DirectProductGroupElement[E1, E2, *FiniteDirectProductGroupElement[E1, E2], FiniteDirectProductGroupElement[E1, E2]]
}

func (g *FiniteDirectProductGroupElement[E1, E2]) Structure() algebra.Structure[*FiniteDirectProductGroupElement[E1, E2]] {
	c1, c2 := g.Components()
	group1 := algebra.StructureMustBeAs[algebra.FiniteGroup[E1]](c1.Structure())
	group2 := algebra.StructureMustBeAs[algebra.FiniteGroup[E2]](c2.Structure())
	out, _ := NewFiniteDirectProductGroup(group1, group2)
	return out
}

// =========== Ring ===========.

func NewDirectProductRing[R1 algebra.Ring[E1], R2 algebra.Ring[E2], E1 algebra.RingElement[E1], E2 algebra.RingElement[E2]](r1 R1, r2 R2) (*DirectProductRing[R1, R2, E1, E2], error) {
	out := &DirectProductRing[R1, R2, E1, E2]{}
	if err := out.Set(r1, r2); err != nil {
		return nil, errs.Wrap(err).WithMessage("failed to set rings")
	}
	var _ algebra.Ring[*DirectProductRingElement[E1, E2]] = out
	return out, nil
}

func NewFiniteDirectProductRing[R1 algebra.FiniteRing[E1], R2 algebra.FiniteRing[E2], E1 algebra.RingElement[E1], E2 algebra.RingElement[E2]](r1 R1, r2 R2) (*FiniteDirectProductRing[R1, R2, E1, E2], error) {
	out := &FiniteDirectProductRing[R1, R2, E1, E2]{}
	if err := out.Set(r1, r2); err != nil {
		return nil, errs.Wrap(err).WithMessage("failed to set rings")
	}
	if err := out.SetFiniteStructureAttributes(r1, r2); err != nil {
		return nil, errs.Wrap(err).WithMessage("failed to set finite structure attributes")
	}
	var _ algebra.Ring[*FiniteDirectProductRingElement[E1, E2]] = out
	return out, nil
}

type DirectProductRing[R1 algebra.Ring[E1], R2 algebra.Ring[E2], E1 algebra.RingElement[E1], E2 algebra.RingElement[E2]] struct {
	traits.DirectProductRing[R1, R2, E1, E2, *DirectProductRingElement[E1, E2], DirectProductRingElement[E1, E2]]
}

type FiniteDirectProductRing[R1 algebra.FiniteRing[E1], R2 algebra.FiniteRing[E2], E1 algebra.RingElement[E1], E2 algebra.RingElement[E2]] struct {
	traits.DirectProductRing[R1, R2, E1, E2, *FiniteDirectProductRingElement[E1, E2], FiniteDirectProductRingElement[E1, E2]]
	traits.DirectProductOfFiniteStructures[R1, R2, E1, E2, *FiniteDirectProductRingElement[E1, E2], FiniteDirectProductRingElement[E1, E2]]
}

type DirectProductRingElement[E1 algebra.RingElement[E1], E2 algebra.RingElement[E2]] struct {
	traits.DirectProductRingElement[E1, E2, *DirectProductRingElement[E1, E2], DirectProductRingElement[E1, E2]]
}

func (r *DirectProductRingElement[E1, E2]) Structure() algebra.Structure[*DirectProductRingElement[E1, E2]] {
	c1, c2 := r.Components()
	ring1 := algebra.StructureMustBeAs[algebra.Ring[E1]](c1.Structure())
	ring2 := algebra.StructureMustBeAs[algebra.Ring[E2]](c2.Structure())
	out, _ := NewDirectProductRing(ring1, ring2)
	return out
}

type FiniteDirectProductRingElement[E1 algebra.RingElement[E1], E2 algebra.RingElement[E2]] struct {
	traits.DirectProductRingElement[E1, E2, *FiniteDirectProductRingElement[E1, E2], FiniteDirectProductRingElement[E1, E2]]
}

func (r *FiniteDirectProductRingElement[E1, E2]) Structure() algebra.Structure[*FiniteDirectProductRingElement[E1, E2]] {
	c1, c2 := r.Components()
	ring1 := algebra.StructureMustBeAs[algebra.FiniteRing[E1]](c1.Structure())
	ring2 := algebra.StructureMustBeAs[algebra.FiniteRing[E2]](c2.Structure())
	out, _ := NewFiniteDirectProductRing(ring1, ring2)
	return out
}

// =========== Module ===========.

func NewDirectProductModule[M1 algebra.Module[E1, S], M2 algebra.Module[E2, S], E1 algebra.ModuleElement[E1, S], E2 algebra.ModuleElement[E2, S], S algebra.RingElement[S]](m1 M1, m2 M2) (*DirectProductModule[M1, M2, E1, E2, S], error) {
	out := &DirectProductModule[M1, M2, E1, E2, S]{}
	if err := out.Set(m1, m2); err != nil {
		return nil, errs.Wrap(err).WithMessage("failed to set modules")
	}
	var _ algebra.Module[*DirectProductModuleElement[E1, E2, S], S] = out
	return out, nil
}

func NewFiniteDirectProductModule[M1 algebra.FiniteModule[E1, S], M2 algebra.FiniteModule[E2, S], E1 algebra.ModuleElement[E1, S], E2 algebra.ModuleElement[E2, S], S algebra.RingElement[S]](m1 M1, m2 M2) (*FiniteDirectProductModule[M1, M2, E1, E2, S], error) {
	out := &FiniteDirectProductModule[M1, M2, E1, E2, S]{}
	if err := out.Set(m1, m2); err != nil {
		return nil, errs.Wrap(err).WithMessage("failed to set modules")
	}
	if err := out.SetFiniteStructureAttributes(m1, m2); err != nil {
		return nil, errs.Wrap(err).WithMessage("failed to set finite structure attributes")
	}
	var _ algebra.Module[*FiniteDirectProductModuleElement[E1, E2, S], S] = out
	return out, nil
}

type DirectProductModule[M1 algebra.Module[E1, S], M2 algebra.Module[E2, S], E1 algebra.ModuleElement[E1, S], E2 algebra.ModuleElement[E2, S], S algebra.RingElement[S]] struct {
	traits.DirectProductModule[M1, M2, E1, E2, S, *DirectProductModuleElement[E1, E2, S], DirectProductModuleElement[E1, E2, S]]
}

type FiniteDirectProductModule[M1 algebra.FiniteModule[E1, S], M2 algebra.FiniteModule[E2, S], E1 algebra.ModuleElement[E1, S], E2 algebra.ModuleElement[E2, S], S algebra.RingElement[S]] struct {
	traits.DirectProductModule[M1, M2, E1, E2, S, *FiniteDirectProductModuleElement[E1, E2, S], FiniteDirectProductModuleElement[E1, E2, S]]
	traits.DirectProductOfFiniteStructures[M1, M2, E1, E2, *FiniteDirectProductModuleElement[E1, E2, S], FiniteDirectProductModuleElement[E1, E2, S]]
}

type DirectProductModuleElement[E1 algebra.ModuleElement[E1, S], E2 algebra.ModuleElement[E2, S], S algebra.RingElement[S]] struct {
	traits.DirectProductModuleElement[E1, E2, S, *DirectProductModuleElement[E1, E2, S], DirectProductModuleElement[E1, E2, S]]
}

func (m *DirectProductModuleElement[E1, E2, S]) Structure() algebra.Structure[*DirectProductModuleElement[E1, E2, S]] {
	c1, c2 := m.Components()
	module1 := algebra.StructureMustBeAs[algebra.Module[E1, S]](c1.Structure())
	module2 := algebra.StructureMustBeAs[algebra.Module[E2, S]](c2.Structure())
	out, _ := NewDirectProductModule(module1, module2)
	return out
}

type FiniteDirectProductModuleElement[E1 algebra.ModuleElement[E1, S], E2 algebra.ModuleElement[E2, S], S algebra.RingElement[S]] struct {
	traits.DirectProductModuleElement[E1, E2, S, *FiniteDirectProductModuleElement[E1, E2, S], FiniteDirectProductModuleElement[E1, E2, S]]
}

func (m *FiniteDirectProductModuleElement[E1, E2, S]) Structure() algebra.Structure[*FiniteDirectProductModuleElement[E1, E2, S]] {
	c1, c2 := m.Components()
	module1 := algebra.StructureMustBeAs[algebra.FiniteModule[E1, S]](c1.Structure())
	module2 := algebra.StructureMustBeAs[algebra.FiniteModule[E2, S]](c2.Structure())
	out, _ := NewFiniteDirectProductModule(module1, module2)
	return out
}
