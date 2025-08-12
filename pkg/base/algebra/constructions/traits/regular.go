package traits

import (
	"io"

	"github.com/bronlabs/bron-crypto/pkg/base"
	"github.com/bronlabs/bron-crypto/pkg/base/algebra"
	"github.com/bronlabs/bron-crypto/pkg/base/algebra/universal"
	"github.com/bronlabs/bron-crypto/pkg/base/errs"
	"github.com/bronlabs/bron-crypto/pkg/base/nt/cardinal"
	"github.com/bronlabs/bron-crypto/pkg/base/utils"
)

type RingElementInheritter[E algebra.RingElement[E]] interface {
	set(v E) error
	Value() E
}

type RingElementInheritterPtrConstraint[E algebra.RingElement[E], T any] interface {
	*T
	RingElementInheritter[E]
}

type RegularModule[R algebra.Ring[E], E algebra.RingElement[E], W RingElementInheritterPtrConstraint[E, WT], WT any] struct {
	Ring R
}

func (m *RegularModule[R, E, W, WT]) Name() string {
	return "RegularModule[" + m.Ring.Name() + "]"
}

func (m *RegularModule[R, E, W, WT]) Model() *universal.Model[W] {
	panic("RegularModule does not have a model")
}

func (m *RegularModule[R, E, W, WT]) Characteristic() cardinal.Cardinal {
	return m.Ring.Characteristic()
}

func (m *RegularModule[R, E, W, WT]) IsSemiDomain() bool {
	return m.Ring.IsSemiDomain()
}

func (m *RegularModule[R, E, W, WT]) Order() cardinal.Cardinal {
	return m.Ring.Order()
}

func (m *RegularModule[R, E, W, WT]) FromBytes(b []byte) (W, error) {
	el, err := m.Ring.FromBytes(b)
	if err != nil {
		return *new(W), err
	}
	var out WT
	if err := W(&out).set(el); err != nil {
		return nil, errs.WrapFailed(err, "failed to set element from bytes")
	}
	return W(&out), nil
}

func (m *RegularModule[R, E, W, WT]) OpIdentity() W {
	var out WT
	if err := W(&out).set(m.Ring.OpIdentity()); err != nil {
		panic(errs.WrapFailed(err, "failed to set op identity"))
	}
	return W(&out)
}

func (m *RegularModule[R, E, W, WT]) Zero() W {
	var out WT
	if err := W(&out).set(m.Ring.Zero()); err != nil {
		panic(errs.WrapFailed(err, "failed to set zero element"))
	}
	return W(&out)
}

func (m *RegularModule[R, E, W, WT]) New(e E) (W, error) {
	var out WT
	if err := W(&out).set(e); err != nil {
		return nil, errs.WrapFailed(err, "failed to create new element")
	}
	return W(&out), nil
}

func (m *RegularModule[R, E, W, WT]) MultiScalarOp(scs []E, els []W) (W, error) {
	return m.MultiScalarMul(scs, els)
}

func (m *RegularModule[R, E, W, WT]) MultiScalarMul(scs []E, els []W) (W, error) {
	if len(scs) != len(els) {
		return nil, errs.NewSize("number of scalars must match number of elements")
	}
	acc := m.Ring.OpIdentity()
	for i, el := range els {
		if el == nil {
			return nil, errs.NewIsNil("element at index %d is nil", i)
		}
		acc = acc.Add(el.Value().Mul(scs[i]))
	}
	var out WT
	W(&out).set(acc)
	return W(&out), nil
}

func (m *RegularModule[R, E, W, WT]) ScalarStructure() algebra.Structure[E] {
	return m.Ring
}

func (m *RegularModule[R, E, W, WT]) ElementSize() int {
	return m.Ring.ElementSize()
}

type RegularModuleElement[E algebra.RingElement[E], W RingElementInheritterPtrConstraint[E, WT], WT any] struct {
	v E
}

func (m *RegularModuleElement[E, W, WT]) set(v E) error {
	if utils.IsNil(v) {
		return errs.NewIsNil("value is nil")
	}
	m.v = v
	return nil
}

func (m *RegularModuleElement[E, W, WT]) Value() E {
	return m.v
}

func (m *RegularModuleElement[E, W, WT]) Op(other W) W {
	if other == nil {
		panic(errs.NewIsNil("other element is nil"))
	}
	var out WT
	if err := W(&out).set(m.v.Op(other.Value())); err != nil {
		panic(errs.WrapFailed(err, "failed to apply operation"))
	}
	return W(&out)
}

func (m *RegularModuleElement[E, W, WT]) IsOpIdentity() bool {
	return m.v.IsOpIdentity()
}

func (m *RegularModuleElement[E, W, WT]) IsZero() bool {
	return m.v.IsZero()
}

func (m *RegularModuleElement[E, W, WT]) Add(other W) W {
	if other == nil {
		panic(errs.NewIsNil("other element is nil"))
	}
	var out WT
	if err := W(&out).set(m.v.Add(other.Value())); err != nil {
		panic(errs.WrapFailed(err, "failed to add element"))
	}
	return W(&out)
}

func (m *RegularModuleElement[E, W, WT]) TrySub(other W) (W, error) {
	if other == nil {
		return nil, errs.NewIsNil("other element is nil")
	}
	var out WT
	v, err := m.v.TrySub(other.Value())
	if err != nil {
		return nil, errs.WrapFailed(err, "failed to subtract element")
	}
	W(&out).set(v)
	return W(&out), nil
}

func (m *RegularModuleElement[E, W, WT]) Sub(other W) W {
	if other == nil {
		panic(errs.NewIsNil("other element is nil"))
	}
	var out WT
	if err := W(&out).set(m.v.Sub(other.Value())); err != nil {
		panic(errs.WrapFailed(err, "failed to subtract element"))
	}
	return W(&out)
}

func (m *RegularModuleElement[E, W, WT]) Double() W {
	var out WT
	if err := W(&out).set(m.v.Double()); err != nil {
		panic(errs.WrapFailed(err, "failed to double element"))
	}
	return W(&out)
}

func (m *RegularModuleElement[E, W, WT]) TryNeg() (W, error) {
	var out WT
	v, err := m.v.TryNeg()
	if err != nil {
		return nil, errs.WrapFailed(err, "failed to negate element")
	}
	if err := W(&out).set(v); err != nil {
		return nil, errs.WrapFailed(err, "failed to set negated element")
	}
	return W(&out), nil
}

func (m *RegularModuleElement[E, W, WT]) Neg() W {
	var out WT
	if err := W(&out).set(m.v.Neg()); err != nil {
		panic(errs.WrapFailed(err, "failed to negate element"))
	}
	return W(&out)
}

func (m *RegularModuleElement[E, W, WT]) Bytes() []byte {
	return m.v.Bytes()
}

func (m *RegularModuleElement[E, W, WT]) ScalarOp(s E) W {
	return m.ScalarMul(s)
}

func (m *RegularModuleElement[E, W, WT]) ScalarMul(s E) W {
	var out WT
	W(&out).set(m.v.Mul(s))
	return W(&out)
}

func (m *RegularModuleElement[E, W, WT]) HashCode() base.HashCode {
	return m.v.HashCode()
}

func (m *RegularModuleElement[E, W, WT]) Equal(other W) bool {
	if m == nil || other == nil {
		return any(m) == any(other)
	}
	return m.v.Equal(other.Value())
}

func (m *RegularModuleElement[E, W, WT]) String() string {
	return m.v.String()
}

func (m *RegularModuleElement[E, W, WT]) Clone() W {
	var out WT
	W(&out).set(m.v.Clone())
	return W(&out)
}

func (m *RegularModuleElement[E, W, WT]) ScalarStructure() algebra.Structure[E] {
	return m.v.Structure()
}

type RegularAlgebra[R algebra.Ring[E], E algebra.RingElement[E], W RingElementInheritterPtrConstraint[E, WT], WT any] struct {
	RegularModule[R, E, W, WT]
}

func (m *RegularAlgebra[R, E, W, WT]) Name() string {
	return "RegularAlgebra[" + m.Ring.Name() + "]"
}

func (m *RegularAlgebra[R, E, W, WT]) One() W {
	var out WT
	if err := W(&out).set(m.RegularModule.Ring.One()); err != nil {
		panic(errs.WrapFailed(err, "failed to set one element"))
	}
	return W(&out)
}

type RegularAlgebraElement[E algebra.RingElement[E], W RingElementInheritterPtrConstraint[E, WT], WT any] struct {
	RegularModuleElement[E, W, WT]
}

func (m *RegularAlgebraElement[E, W, WT]) IsOne() bool {
	return m.v.IsOne()
}

func (m *RegularAlgebraElement[E, W, WT]) TryInv() (W, error) {
	vv, err := m.v.TryInv()
	if err != nil {
		return nil, errs.WrapFailed(err, "failed to invert RegularAlgebraElement")
	}
	var out WT
	if err := W(&out).set(vv); err != nil {
		return nil, errs.WrapFailed(err, "failed to set inverted RegularAlgebraElement")
	}
	return W(&out), nil
}

func (m *RegularAlgebraElement[E, W, WT]) TryOpInv() (W, error) {
	vv, err := m.v.TryOpInv()
	if err != nil {
		return nil, errs.WrapFailed(err, "failed to invert RegularAlgebraElement")
	}
	var out WT
	if err := W(&out).set(vv); err != nil {
		return nil, errs.WrapFailed(err, "failed to set inverted RegularAlgebraElement")
	}
	return W(&out), nil
}

func (m *RegularAlgebraElement[E, W, WT]) OpInv() W {
	var out WT
	if err := W(&out).set(m.v.OpInv()); err != nil {
		panic(errs.WrapFailed(err, "failed to invert RegularAlgebraElement"))
	}
	return W(&out)
}

func (m *RegularAlgebraElement[E, W, WT]) TryDiv(other W) (W, error) {
	if other == nil {
		return nil, errs.NewIsNil("other element is nil")
	}
	vv, err := m.v.TryDiv(other.Value())
	if err != nil {
		return nil, errs.WrapFailed(err, "failed to divide RegularAlgebraElement")
	}
	var out WT
	if err := W(&out).set(vv); err != nil {
		return nil, errs.WrapFailed(err, "failed to set divided RegularAlgebraElement")
	}
	return W(&out), nil
}

func (m *RegularAlgebraElement[E, W, WT]) OtherOp(other W) W {
	return m.Mul(other)
}

func (m *RegularAlgebraElement[E, W, WT]) Mul(other W) W {
	if other == nil {
		panic(errs.NewIsNil("other element is nil"))
	}
	var out WT
	if err := W(&out).set(m.v.Mul(other.Value())); err != nil {
		panic(errs.WrapFailed(err, "failed to multiply RegularAlgebraElement"))
	}
	return W(&out)
}

func (m *RegularAlgebraElement[E, W, WT]) Square() W {
	var out WT
	if err := W(&out).set(m.v.Square()); err != nil {
		panic(errs.WrapFailed(err, "failed to square RegularAlgebraElement"))
	}
	return W(&out)
}

type FiniteRegularStructure[R interface {
	algebra.Ring[E]
	algebra.FiniteStructure[E]
}, E algebra.RingElement[E], W RingElementInheritterPtrConstraint[E, WT], WT any] struct {
	R R
}

func (m *FiniteRegularStructure[R, E, W, WT]) Random(prng io.Reader) (W, error) {
	if prng == nil {
		return nil, errs.NewIsNil("prng is nil")
	}
	v, err := m.R.Random(prng)
	if err != nil {
		return nil, errs.WrapRandomSample(err, "could not sample random element")
	}
	var out WT
	if err := W(&out).set(v); err != nil {
		return nil, errs.WrapFailed(err, "could not set random element")
	}
	return W(&out), nil
}

func (m *FiniteRegularStructure[R, E, W, WT]) Hash(input []byte) (W, error) {
	if input == nil {
		return nil, errs.NewIsNil("input is nil")
	}
	v, err := m.R.Hash(input)
	if err != nil {
		return nil, errs.WrapFailed(err, "could not hash input")
	}
	var out WT
	if err := W(&out).set(v); err != nil {
		return nil, errs.WrapFailed(err, "could not set hashed element")
	}
	return W(&out), nil
}
