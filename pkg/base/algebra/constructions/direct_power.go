package constructions

import (
	"github.com/bronlabs/errs-go/errs"

	"github.com/bronlabs/bron-crypto/pkg/base/algebra"
	"github.com/bronlabs/bron-crypto/pkg/base/algebra/constructions/traits"
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

func NewDirectPowerModule[M algebra.Module[E, S], E algebra.ModuleElement[E, S], S algebra.RingElement[S]](m M, arity uint) (*DirectPowerModule[M, E, S], error) {
	out := &DirectPowerModule[M, E, S]{}
	if err := out.Set(m, arity); err != nil {
		return nil, errs.Wrap(err).WithMessage("failed to set module and arity")
	}
	var _ algebra.Module[*DirectPowerModuleElement[E, S], S] = out
	return out, nil
}

func NewFiniteDirectPowerModule[M algebra.FiniteModule[E, S], E algebra.ModuleElement[E, S], S algebra.RingElement[S]](m M, arity uint) (*FiniteDirectPowerModule[M, E, S], error) {
	out := &FiniteDirectPowerModule[M, E, S]{}
	if err := out.Set(m, arity); err != nil {
		return nil, errs.Wrap(err).WithMessage("failed to set module and arity")
	}
	if err := out.SetFiniteStructureAttributes(m, arity); err != nil {
		return nil, errs.Wrap(err).WithMessage("failed to set finite structure attributes")
	}
	var _ algebra.Module[*FiniteDirectPowerModuleElement[E, S], S] = out
	return out, nil
}

type DirectPowerModule[M algebra.Module[E, S], E algebra.ModuleElement[E, S], S algebra.RingElement[S]] struct {
	traits.DirectPowerModule[M, E, S, *DirectPowerModuleElement[E, S], DirectPowerModuleElement[E, S]]
}

type FiniteDirectPowerModule[M algebra.FiniteModule[E, S], E algebra.ModuleElement[E, S], S algebra.RingElement[S]] struct {
	traits.DirectPowerModule[M, E, S, *FiniteDirectPowerModuleElement[E, S], FiniteDirectPowerModuleElement[E, S]]
	traits.DirectPowerOfFiniteStructures[M, E, *FiniteDirectPowerModuleElement[E, S], FiniteDirectPowerModuleElement[E, S]]
}

type DirectPowerModuleElement[E algebra.ModuleElement[E, S], S algebra.RingElement[S]] struct {
	traits.DirectPowerModuleElement[E, S, *DirectPowerModuleElement[E, S], DirectPowerModuleElement[E, S]]
}

func (m *DirectPowerModuleElement[E, S]) Structure() algebra.Structure[*DirectPowerModuleElement[E, S]] {
	module := algebra.StructureMustBeAs[algebra.Module[E, S]](m.Components()[0].Structure())
	out, _ := NewDirectPowerModule(module, uint(m.Arity().Uint64()))
	return out
}

func (m *DirectPowerModuleElement[E, S]) ScalarDiagonal(s *DirectPowerRingElement[S]) *DirectPowerModuleElement[E, S] {
	arity := m.Arity().Uint64()
	scaledComponents := make([]E, arity)
	for i := range arity {
		scaledComponents[i] = m.Components()[i].ScalarOp(s.Components()[i])
	}
	module := algebra.StructureMustBeAs[algebra.Module[E, S]](m.Components()[0].Structure())
	directPowerModule, err := NewDirectPowerModule(module, uint(m.Arity().Uint64()))
	if err != nil {
		panic(errs.Wrap(err).WithMessage("failed to create direct power module for scalar diagonal operation"))
	}
	out, err := directPowerModule.New(scaledComponents...)
	if err != nil {
		panic(errs.Wrap(err).WithMessage("failed to create direct power module element for scalar diagonal operation"))
	}
	return out
}

type FiniteDirectPowerModuleElement[E algebra.ModuleElement[E, S], S algebra.RingElement[S]] struct {
	traits.DirectPowerModuleElement[E, S, *FiniteDirectPowerModuleElement[E, S], FiniteDirectPowerModuleElement[E, S]]
}

func (m *FiniteDirectPowerModuleElement[E, S]) Structure() algebra.Structure[*FiniteDirectPowerModuleElement[E, S]] {
	module := algebra.StructureMustBeAs[algebra.FiniteModule[E, S]](m.Components()[0].Structure())
	out, _ := NewFiniteDirectPowerModule(module, uint(m.Arity().Uint64()))
	return out
}

func (m *FiniteDirectPowerModuleElement[E, S]) ScalarDiagonal(s *FiniteDirectPowerRingElement[S]) *FiniteDirectPowerModuleElement[E, S] {
	arity := m.Arity().Uint64()
	scaledComponents := make([]E, arity)
	for i := range arity {
		scaledComponents[i] = m.Components()[i].ScalarOp(s.Components()[i])
	}
	module := algebra.StructureMustBeAs[algebra.FiniteModule[E, S]](m.Components()[0].Structure())
	directPowerModule, err := NewFiniteDirectPowerModule(module, uint(m.Arity().Uint64()))
	if err != nil {
		panic(errs.Wrap(err).WithMessage("failed to create direct power module for scalar diagonal operation"))
	}
	out, err := directPowerModule.New(scaledComponents...)
	if err != nil {
		panic(errs.Wrap(err).WithMessage("failed to create direct power module element for scalar diagonal operation"))
	}
	return out
}
