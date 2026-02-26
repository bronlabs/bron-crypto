package constructions

import (
	"github.com/bronlabs/bron-crypto/pkg/base/algebra"
	"github.com/bronlabs/bron-crypto/pkg/base/algebra/constructions/traits"
	"github.com/bronlabs/errs-go/errs"
)

// =========== Group ===========.

func NewDirectPowerGroup[G algebra.Group[E], E algebra.GroupElement[E]](g G, arity uint) (*DirectPowerGroup[G, E], error) {
	out := &DirectPowerGroup[G, E]{}
	if err := out.Set(g, arity); err != nil {
		return nil, errs.Wrap(err).WithMessage("failed to set group and arity")
	}
	var _ algebra.Group[*DirectPowerGroupElement[E]] = out
	return out, nil
}

type DirectPowerGroup[G algebra.Group[E], E algebra.GroupElement[E]] struct {
	traits.DirectPowerGroup[G, E, *DirectPowerGroupElement[E], DirectPowerGroupElement[E]]
}

func NewFiniteDirectPowerGroup[G algebra.FiniteGroup[E], E algebra.GroupElement[E]](g G, arity uint) (*FiniteDirectPowerGroup[G, E], error) {
	out := &FiniteDirectPowerGroup[G, E]{}
	if err := out.Set(g, arity); err != nil {
		return nil, errs.Wrap(err).WithMessage("failed to set group and arity")
	}
	if err := out.SetFiniteStructureAttributes(g, arity); err != nil {
		return nil, errs.Wrap(err).WithMessage("failed to set finite structure attributes")
	}
	var _ algebra.Group[*FiniteDirectPowerGroupElement[E]] = out
	return out, nil
}

type FiniteDirectPowerGroup[G algebra.FiniteGroup[E], E algebra.GroupElement[E]] struct {
	traits.DirectPowerGroup[G, E, *FiniteDirectPowerGroupElement[E], FiniteDirectPowerGroupElement[E]]
	traits.DirectPowerOfFiniteStructures[G, E, *FiniteDirectPowerGroupElement[E], FiniteDirectPowerGroupElement[E]]
}

type DirectPowerGroupElement[E algebra.GroupElement[E]] struct {
	traits.DirectPowerGroupElement[E, *DirectPowerGroupElement[E], DirectPowerGroupElement[E]]
}

func (g *DirectPowerGroupElement[E]) Structure() algebra.Structure[*DirectPowerGroupElement[E]] {
	group := algebra.StructureMustBeAs[algebra.Group[E]](g.Components()[0].Structure())
	out, _ := NewDirectPowerGroup(group, uint(g.Arity().Uint64()))
	return out
}

type FiniteDirectPowerGroupElement[E algebra.GroupElement[E]] struct {
	traits.DirectPowerGroupElement[E, *FiniteDirectPowerGroupElement[E], FiniteDirectPowerGroupElement[E]]
}

func (g *FiniteDirectPowerGroupElement[E]) Structure() algebra.Structure[*FiniteDirectPowerGroupElement[E]] {
	group := algebra.StructureMustBeAs[algebra.FiniteGroup[E]](g.Components()[0].Structure())
	out, _ := NewFiniteDirectPowerGroup(group, uint(g.Arity().Uint64()))
	return out
}

// =========== Ring ===========.

func NewDirectPowerRing[R algebra.Ring[E], E algebra.RingElement[E]](r R, arity uint) (*DirectPowerRing[R, E], error) {
	out := &DirectPowerRing[R, E]{}
	if err := out.Set(r, arity); err != nil {
		return nil, errs.Wrap(err).WithMessage("failed to set ring and arity")
	}
	var _ algebra.Ring[*DirectPowerRingElement[E]] = out
	return out, nil
}

func NewFiniteDirectPowerRing[R algebra.FiniteRing[E], E algebra.RingElement[E]](r R, arity uint) (*FiniteDirectPowerRing[R, E], error) {
	out := &FiniteDirectPowerRing[R, E]{}
	if err := out.Set(r, arity); err != nil {
		return nil, errs.Wrap(err).WithMessage("failed to set ring and arity")
	}
	if err := out.SetFiniteStructureAttributes(r, arity); err != nil {
		return nil, errs.Wrap(err).WithMessage("failed to set finite structure attributes")
	}
	var _ algebra.Ring[*FiniteDirectPowerRingElement[E]] = out
	return out, nil
}

type DirectPowerRing[R algebra.Ring[E], E algebra.RingElement[E]] struct {
	traits.DirectPowerRing[R, E, *DirectPowerRingElement[E], DirectPowerRingElement[E]]
}

type FiniteDirectPowerRing[R algebra.FiniteRing[E], E algebra.RingElement[E]] struct {
	traits.DirectPowerRing[R, E, *FiniteDirectPowerRingElement[E], FiniteDirectPowerRingElement[E]]
	traits.DirectPowerOfFiniteStructures[R, E, *FiniteDirectPowerRingElement[E], FiniteDirectPowerRingElement[E]]
}

type DirectPowerRingElement[E algebra.RingElement[E]] struct {
	traits.DirectPowerRingElement[E, *DirectPowerRingElement[E], DirectPowerRingElement[E]]
}

func (r *DirectPowerRingElement[E]) Structure() algebra.Structure[*DirectPowerRingElement[E]] {
	ring := algebra.StructureMustBeAs[algebra.Ring[E]](r.Components()[0].Structure())
	out, _ := NewDirectPowerRing(ring, uint(r.Arity().Uint64()))
	return out
}

type FiniteDirectPowerRingElement[E algebra.RingElement[E]] struct {
	traits.DirectPowerRingElement[E, *FiniteDirectPowerRingElement[E], FiniteDirectPowerRingElement[E]]
}

func (r *FiniteDirectPowerRingElement[E]) Structure() algebra.Structure[*FiniteDirectPowerRingElement[E]] {
	ring := algebra.StructureMustBeAs[algebra.FiniteRing[E]](r.Components()[0].Structure())
	out, _ := NewFiniteDirectPowerRing(ring, uint(r.Arity().Uint64()))
	return out
}

// =========== Module ===========.

func NewDirectSumModule[M algebra.Module[E, S], E algebra.ModuleElement[E, S], S algebra.RingElement[S]](m M, arity uint) (*DirectSumModule[M, E, S], error) {
	out := &DirectSumModule[M, E, S]{}
	if err := out.Set(m, arity); err != nil {
		return nil, errs.Wrap(err).WithMessage("failed to set module and arity")
	}
	var _ algebra.Module[*DirectSumModuleElement[E, S], S] = out
	return out, nil
}

func NewFiniteDirectSumModule[M algebra.FiniteModule[E, S], E algebra.ModuleElement[E, S], S algebra.RingElement[S]](m M, arity uint) (*FiniteDirectSumModule[M, E, S], error) {
	out := &FiniteDirectSumModule[M, E, S]{}
	if err := out.Set(m, arity); err != nil {
		return nil, errs.Wrap(err).WithMessage("failed to set module and arity")
	}
	if err := out.SetFiniteStructureAttributes(m, arity); err != nil {
		return nil, errs.Wrap(err).WithMessage("failed to set finite structure attributes")
	}
	var _ algebra.Module[*FiniteDirectSumModuleElement[E, S], S] = out
	return out, nil
}

type DirectSumModule[M algebra.Module[E, S], E algebra.ModuleElement[E, S], S algebra.RingElement[S]] struct {
	traits.DirectSumModule[M, E, S, *DirectSumModuleElement[E, S], DirectSumModuleElement[E, S]]
}

type FiniteDirectSumModule[M algebra.FiniteModule[E, S], E algebra.ModuleElement[E, S], S algebra.RingElement[S]] struct {
	traits.DirectSumModule[M, E, S, *FiniteDirectSumModuleElement[E, S], FiniteDirectSumModuleElement[E, S]]
	traits.DirectPowerOfFiniteStructures[M, E, *FiniteDirectSumModuleElement[E, S], FiniteDirectSumModuleElement[E, S]]
}

type DirectSumModuleElement[E algebra.ModuleElement[E, S], S algebra.RingElement[S]] struct {
	traits.DirectSumModuleElement[E, S, *DirectSumModuleElement[E, S], DirectSumModuleElement[E, S]]
}

func (m *DirectSumModuleElement[E, S]) Structure() algebra.Structure[*DirectSumModuleElement[E, S]] {
	module := algebra.StructureMustBeAs[algebra.Module[E, S]](m.Components()[0].Structure())
	out, _ := NewDirectSumModule(module, uint(m.Arity().Uint64()))
	return out
}

func (m *DirectSumModuleElement[E, S]) ScalarDiagonal(s *DirectPowerRingElement[S]) *DirectSumModuleElement[E, S] {
	arity := m.Arity().Uint64()
	scaledComponents := make([]E, arity)
	for i := range arity {
		scaledComponents[i] = m.Components()[i].ScalarOp(s.Components()[i])
	}
	module := algebra.StructureMustBeAs[algebra.Module[E, S]](m.Components()[0].Structure())
	directSumModule, err := NewDirectSumModule(module, uint(m.Arity().Uint64()))
	if err != nil {
		panic(errs.Wrap(err).WithMessage("failed to create direct sum module for scalar diagonal operation"))
	}
	out, err := directSumModule.New(scaledComponents...)
	if err != nil {
		panic(errs.Wrap(err).WithMessage("failed to create direct sum module element for scalar diagonal operation"))
	}
	return out
}

type FiniteDirectSumModuleElement[E algebra.ModuleElement[E, S], S algebra.RingElement[S]] struct {
	traits.DirectSumModuleElement[E, S, *FiniteDirectSumModuleElement[E, S], FiniteDirectSumModuleElement[E, S]]
}

func (m *FiniteDirectSumModuleElement[E, S]) Structure() algebra.Structure[*FiniteDirectSumModuleElement[E, S]] {
	module := algebra.StructureMustBeAs[algebra.FiniteModule[E, S]](m.Components()[0].Structure())
	out, _ := NewFiniteDirectSumModule(module, uint(m.Arity().Uint64()))
	return out
}

func (m *FiniteDirectSumModuleElement[E, S]) ScalarDiagonal(s *FiniteDirectPowerRingElement[S]) *FiniteDirectSumModuleElement[E, S] {
	arity := m.Arity().Uint64()
	scaledComponents := make([]E, arity)
	for i := range arity {
		scaledComponents[i] = m.Components()[i].ScalarOp(s.Components()[i])
	}
	module := algebra.StructureMustBeAs[algebra.FiniteModule[E, S]](m.Components()[0].Structure())
	directSumModule, err := NewFiniteDirectSumModule(module, uint(m.Arity().Uint64()))
	if err != nil {
		panic(errs.Wrap(err).WithMessage("failed to create direct sum module for scalar diagonal operation"))
	}
	out, err := directSumModule.New(scaledComponents...)
	if err != nil {
		panic(errs.Wrap(err).WithMessage("failed to create direct sum module element for scalar diagonal operation"))
	}
	return out
}
