package traits

import (
	"encoding/binary"
	"fmt"
	"hash/fnv"
	"io"

	"github.com/bronlabs/bron-crypto/pkg/base"
	"github.com/bronlabs/bron-crypto/pkg/base/algebra"
	"github.com/bronlabs/bron-crypto/pkg/base/errs"
	"github.com/bronlabs/bron-crypto/pkg/base/nt/cardinal"
	"github.com/bronlabs/bron-crypto/pkg/base/utils"
	"github.com/bronlabs/bron-crypto/pkg/base/utils/sliceutils"
)

type DirectPower[E algebra.SemiGroupElement[E]] interface {
	algebra.NAry[E]
	set(arity int, components ...E) error
}

type DirectPowerInheritter[E algebra.SemiGroupElement[E]] interface {
	DirectPower[E]
}

type DirectPowerInheritterPtrConstraint[E algebra.SemiGroupElement[E], T any] interface {
	*T
	DirectPowerInheritter[E]
}

// ========== SemiGroup ==========

type DirectPowerSemiGroup[S algebra.SemiGroup[E], E algebra.SemiGroupElement[E], W DirectPowerInheritterPtrConstraint[E, WT], WT any] struct {
	base  S
	arity int
}

func (s *DirectPowerSemiGroup[S, E, W, WT]) Base() S {
	if s == nil {
		return *new(S)
	}
	return s.base
}

func (s *DirectPowerSemiGroup[S, E, W, WT]) Arity() cardinal.Cardinal {
	return cardinal.New(uint64(s.arity))
}

func (s *DirectPowerSemiGroup[S, E, W, WT]) ElementSize() int {
	if s.arity == 0 {
		return 0
	}
	return s.base.ElementSize() * s.arity
}

func (s *DirectPowerSemiGroup[S, E, W, WT]) Name() string {
	return fmt.Sprintf("(%s)^%d", s.base.Name(), s.arity)
}

func (s *DirectPowerSemiGroup[S, E, W, WT]) FromBytes(input []byte) (W, error) {
	componentSize := s.base.ElementSize()
	if len(input)%componentSize != 0 {
		return nil, errs.NewValue("input length is not a multiple of element size")
	}
	values := make([]E, len(input)/componentSize)
	for i := 0; i < len(input); i += componentSize {
		component, err := s.base.FromBytes(input[i : i+componentSize])
		if err != nil {
			return nil, errs.WrapSerialisation(err, "failed to decode component %d", i/componentSize)
		}
		values[i/componentSize] = component
	}
	var out WT
	if err := W(&out).set(s.arity, values...); err != nil {
		return nil, errs.WrapFailed(err, "failed to set components")
	}
	return W(&out), nil
}

func (s *DirectPowerSemiGroup[S, E, W, WT]) New(es ...E) (W, error) {
	if len(es) != s.arity {
		return nil, errs.NewLength("incorrect component count")
	}
	var out WT
	if err := W(&out).set(s.arity, es...); err != nil {
		return nil, errs.WrapFailed(err, "failed to set components")
	}
	return W(&out), nil
}

func (s *DirectPowerSemiGroup[S, E, W, WT]) Diagonal(e E) (W, error) {
	return s.New(sliceutils.Repeat[[]E](e, s.arity)...)
}

func (s *DirectPowerSemiGroup[S, E, W, WT]) Set(base S, dim uint) error {
	if utils.IsNil(base) {
		return (errs.NewIsNil("base cannot be nil"))
	}
	if dim == 0 {
		return errs.NewIsZero("arity must be greater than 0")
	}
	s.base = base
	s.arity = int(dim)
	return nil
}

func (s *DirectPowerSemiGroup[S, E, W, WT]) Factor() S {
	return s.base
}

func (s *DirectPowerSemiGroup[S, E, W, WT]) Order() cardinal.Cardinal {
	out := cardinal.New(1)
	for range s.arity {
		out = out.Mul(s.base.Order())
		if out.IsZero() {
			return out // if any component has zero order, the product has zero order
		}
		if out.IsUnknown() {
			return out // if any component has unknown order, the product has unknown order
		}
	}
	return out
}

type DirectPowerSemiGroupElement[E algebra.SemiGroupElement[E], W DirectPowerInheritterPtrConstraint[E, WT], WT any] struct {
	components []E
	arity      int
}

func (d *DirectPowerSemiGroupElement[E, W, WT]) Arity() cardinal.Cardinal {
	return cardinal.New(uint64(d.arity))
}

func (d *DirectPowerSemiGroupElement[E, W, WT]) Bytes() []byte {
	if d.arity == 0 {
		return nil
	}
	out := []byte{}
	for _, c := range d.components {
		out = append(out, c.Bytes()...)
	}
	return out
}

func (d *DirectPowerSemiGroupElement[E, W, WT]) set(arity int, components ...E) error {
	d.components = components
	d.arity = arity
	return nil
}

func (d *DirectPowerSemiGroupElement[E, W, WT]) Components() []E {
	return d.components
}

func (d *DirectPowerSemiGroupElement[E, W, WT]) Op(x W) W {
	if !d.Arity().Equal(x.Arity()) {
		panic("incorrect component count")
	}
	values := make([]E, d.arity)
	for i, c := range d.components {
		values[i] = c.Op(x.Components()[i])
	}
	var out WT
	if err := W(&out).set(d.arity, values...); err != nil {
		panic(errs.WrapFailed(err, "failed to set components"))
	}
	return W(&out)
}

func (d *DirectPowerSemiGroupElement[E, W, WT]) Equal(x W) bool {
	if !d.Arity().Equal(x.Arity()) {
		return false
	}
	for i, c := range d.components {
		if !c.Equal(x.Components()[i]) {
			return false
		}
	}
	return true
}

func (d *DirectPowerSemiGroupElement[E, W, WT]) HashCode() base.HashCode {
	h := fnv.New64a()
	for _, x := range d.components {
		var buf [8]byte
		binary.LittleEndian.PutUint64(buf[:], uint64(x.HashCode()))
		if _, err := h.Write(buf[:]); err != nil {
			panic(errs.WrapHashing(err, "could not write to hash function"))
		}
	}
	return base.HashCode(h.Sum64())
}

func (d *DirectPowerSemiGroupElement[E, W, WT]) Clone() W {
	values := make([]E, d.arity)
	for i, c := range d.components {
		values[i] = c.Clone()
	}
	var out WT
	if err := W(&out).set(d.arity, values...); err != nil {
		panic(errs.WrapFailed(err, "failed to set components"))
	}
	return W(&out)
}

func (d *DirectPowerSemiGroupElement[E, W, WT]) String() string {
	if d.Arity().IsZero() {
		return "∅"
	}
	out := "("
	for i, c := range d.components {
		if i > 0 {
			out += ", "
		}
		out += c.String()
	}
	out += ")"
	return out
}

// ========== Group ==========

type DirectPowerGroup[S algebra.Group[E], E algebra.GroupElement[E], W DirectPowerInheritterPtrConstraint[E, WT], WT any] struct {
	DirectPowerSemiGroup[S, E, W, WT]
}

func (s *DirectPowerGroup[S, E, W, WT]) OpIdentity() W {
	var out WT
	if err := W(&out).set(s.arity, sliceutils.Repeat[[]E](s.base.OpIdentity(), s.arity)...); err != nil {
		panic(errs.WrapFailed(err, "failed to set components"))
	}
	return W(&out)
}

type DirectPowerGroupElement[E algebra.GroupElement[E], W DirectPowerInheritterPtrConstraint[E, WT], WT any] struct {
	DirectPowerSemiGroupElement[E, W, WT]
}

func (d *DirectPowerGroupElement[E, W, WT]) IsOpIdentity() bool {
	return sliceutils.All(d.components, func(c E) bool {
		return c.IsOpIdentity()
	})
}

func (d *DirectPowerGroupElement[E, W, WT]) TryOpInv() (W, error) {
	values := make([]E, d.arity)
	for i, c := range d.components {
		inv, err := c.TryOpInv()
		if err != nil {
			return nil, err
		}
		values[i] = inv
	}
	var out WT
	if err := W(&out).set(d.arity, values...); err != nil {
		return nil, errs.WrapFailed(err, "failed to set components")
	}
	return W(&out), nil
}

func (d *DirectPowerGroupElement[E, W, WT]) OpInv() W {
	values := make([]E, d.arity)
	for i, c := range d.components {
		values[i] = c.OpInv()
	}
	var out WT
	if err := W(&out).set(d.arity, values...); err != nil {
		panic(errs.WrapFailed(err, "failed to set components"))
	}
	return W(&out)
}

// ========== Ring ==========

type DirectPowerRing[R algebra.Ring[E], E algebra.RingElement[E], W DirectPowerInheritterPtrConstraint[E, WT], WT any] struct {
	DirectPowerGroup[R, E, W, WT]
}

func (s *DirectPowerRing[R, E, W, WT]) IsSemiDomain() bool {
	return false
}

func (s *DirectPowerRing[R, E, W, WT]) Zero() W {
	var out WT
	if err := W(&out).set(s.arity, sliceutils.Repeat[[]E](s.base.Zero(), s.arity)...); err != nil {
		panic(errs.WrapFailed(err, "failed to set components"))
	}
	return W(&out)
}

func (s *DirectPowerRing[R, E, W, WT]) One() W {
	var out WT
	if err := W(&out).set(s.arity, sliceutils.Repeat[[]E](s.base.One(), s.arity)...); err != nil {
		panic(errs.WrapFailed(err, "failed to set components"))
	}
	return W(&out)
}

func (s *DirectPowerRing[R, E, W, WT]) Characteristic() cardinal.Cardinal {
	return s.base.Characteristic()
}

type DirectPowerRingElement[
	E algebra.RingElement[E], W DirectPowerInheritterPtrConstraint[E, WT], WT any] struct {
	DirectPowerGroupElement[E, W, WT]
}

func (d *DirectPowerRingElement[E, W, WT]) OtherOp(x W) W {
	return d.Mul(x)
}

func (d *DirectPowerRingElement[E, W, WT]) IsZero() bool {
	return sliceutils.All(d.components, func(c E) bool {
		return c.IsZero()
	})
}

func (d *DirectPowerRingElement[E, W, WT]) IsOne() bool {
	for _, c := range d.components {
		if !c.IsOne() {
			return false
		}
	}
	return true
}

func (d *DirectPowerRingElement[E, W, WT]) Add(x W) W {
	if !d.Arity().Equal(x.Arity()) {
		panic("incorrect component count")
	}
	values := make([]E, d.arity)
	for i, c := range d.components {
		values[i] = c.Add(x.Components()[i])
	}
	var out WT
	if err := W(&out).set(d.arity, values...); err != nil {
		panic(errs.WrapFailed(err, "failed to set components"))
	}
	return W(&out)
}

func (d *DirectPowerRingElement[E, W, WT]) TrySub(x W) (W, error) {
	if !d.Arity().Equal(x.Arity()) {
		return nil, errs.NewLength("incorrect component count")
	}
	var err error
	values := make([]E, d.arity)
	for i, c := range d.components {
		values[i], err = c.TrySub(x.Components()[i])
		if err != nil {
			return nil, errs.WrapFailed(err, "failed to subtract component %d", i)
		}
	}
	var out WT
	if err := W(&out).set(d.arity, values...); err != nil {
		return nil, errs.WrapFailed(err, "failed to set components")
	}
	return W(&out), nil
}

func (d *DirectPowerRingElement[E, W, WT]) Sub(x W) W {
	if !d.Arity().Equal(x.Arity()) {
		panic("incorrect component count")
	}
	values := make([]E, d.arity)
	for i, c := range d.components {
		values[i] = c.Sub(x.Components()[i])
	}
	var out WT
	if err := W(&out).set(d.arity, values...); err != nil {
		panic(errs.WrapFailed(err, "failed to set components"))
	}
	return W(&out)
}

func (d *DirectPowerRingElement[E, W, WT]) Mul(x W) W {
	if !d.Arity().Equal(x.Arity()) {
		panic("incorrect component count")
	}
	values := make([]E, d.arity)
	for i, c := range d.components {
		values[i] = c.Mul(x.Components()[i])
	}
	var out WT
	if err := W(&out).set(d.arity, values...); err != nil {
		panic(errs.WrapFailed(err, "failed to set components"))
	}
	return W(&out)
}

func (d *DirectPowerRingElement[E, W, WT]) TryDiv(x W) (W, error) {
	if !d.Arity().Equal(x.Arity()) {
		return nil, errs.NewLength("incorrect component count")
	}
	var err error
	values := make([]E, d.arity)
	for i, c := range d.components {
		values[i], err = c.TryDiv(x.Components()[i])
		if err != nil {
			return nil, errs.WrapFailed(err, "failed to divide component %d", i)
		}
	}
	var out WT
	if err := W(&out).set(d.arity, values...); err != nil {
		return nil, errs.WrapFailed(err, "failed to set components")
	}
	return W(&out), nil
}

func (d *DirectPowerRingElement[E, W, WT]) TryInv() (W, error) {
	var err error
	values := make([]E, d.arity)
	for i, c := range d.components {
		values[i], err = c.TryInv()
		if err != nil {
			return nil, errs.WrapFailed(err, "failed to invert component %d", i)
		}
	}
	var out WT
	if err := W(&out).set(d.arity, values...); err != nil {
		return nil, errs.WrapFailed(err, "failed to set components")
	}
	return W(&out), nil
}

func (d *DirectPowerRingElement[E, W, WT]) TryNeg() (W, error) {
	var err error
	values := make([]E, d.arity)
	for i, c := range d.components {
		values[i], err = c.TryNeg()
		if err != nil {
			return nil, errs.WrapFailed(err, "failed to negate component %d", i)
		}
	}
	var out WT
	if err := W(&out).set(d.arity, values...); err != nil {
		return nil, errs.WrapFailed(err, "failed to set components")
	}
	return W(&out), nil
}

func (d *DirectPowerRingElement[E, W, WT]) Double() W {
	values := make([]E, d.arity)
	for i, c := range d.components {
		values[i] = c.Double()
	}
	var out WT
	if err := W(&out).set(d.arity, values...); err != nil {
		panic(errs.WrapFailed(err, "failed to set components"))
	}
	return W(&out)
}

func (d *DirectPowerRingElement[E, W, WT]) Square() W {
	values := make([]E, d.arity)
	for i, c := range d.components {
		values[i] = c.Square()
	}
	var out WT
	if err := W(&out).set(d.arity, values...); err != nil {
		panic(errs.WrapFailed(err, "failed to set components"))
	}
	return W(&out)
}

func (d *DirectPowerRingElement[E, W, WT]) Neg() W {
	values := make([]E, d.arity)
	for i, c := range d.components {
		values[i] = c.Neg()
	}
	var out WT
	if err := W(&out).set(d.arity, values...); err != nil {
		panic(errs.WrapFailed(err, "failed to set components"))
	}
	return W(&out)
}

// =============== Polynomial Likes ==================

func EvalDirectProductOfPolynomialLikes[
	Ps algebra.CoProduct[Ps, P],
	P algebra.UnivariatePolynomialLike[P, S, C],
	C algebra.GroupElement[C],
	S algebra.FiniteRingElement[S],
](product Ps, at S) ([]C, error) {
	if utils.IsNil(product) {
		return nil, errs.NewIsNil("product cannot be nil")
	}
	if utils.IsNil(at) {
		return nil, errs.NewIsNil("evaluation point cannot be nil")
	}
	components := product.Components()
	arity := product.Arity()
	if arity.IsZero() || !arity.IsFinite() {
		return nil, errs.NewSize("product must have finite and positive arity")
	}
	values := make([]C, arity.Uint64())
	for i, c := range components {
		values[i] = c.Eval(at)
	}
	return values, nil
}

// ================ Misc =======================

type DirectPowerOfFiniteStructures[S interface {
	algebra.SemiGroup[E]
	algebra.FiniteStructure[E]
}, E algebra.SemiGroupElement[E], W DirectPowerInheritterPtrConstraint[E, WT], WT any] struct {
	base S
	dim  int
}

func (s *DirectPowerOfFiniteStructures[S, E, W, WT]) SetFiniteStructureAttributes(base S, dim uint) error {
	if utils.IsNil(base) {
		return errs.NewIsNil("base cannot be nil")
	}
	if dim == 0 {
		return errs.NewIsZero("dimension must be greater than 0")
	}
	s.base = base
	s.dim = int(dim)
	return nil
}

func (s *DirectPowerOfFiniteStructures[S, E, W, WT]) Random(prng io.Reader) (W, error) {
	var err error
	values := make([]E, s.dim)
	for i := range s.dim {
		values[i], err = s.base.Random(prng)
		if err != nil {
			return nil, errs.WrapFailed(err, "failed to generate random component %d", i)
		}
	}
	var out WT
	if err := W(&out).set(s.dim, values...); err != nil {
		return nil, errs.WrapFailed(err, "failed to set components")
	}
	return W(&out), nil
}

func (s *DirectPowerOfFiniteStructures[S, E, W, WT]) Hash(input []byte) (W, error) {
	var err error
	values := make([]E, s.dim)
	for i := range s.dim {
		values[i], err = s.base.Hash(input)
		if err != nil {
			return nil, errs.WrapFailed(err, "failed to hash component %d", i)
		}
	}
	var out WT
	if err := W(&out).set(s.dim, values...); err != nil {
		return nil, errs.WrapFailed(err, "failed to set components")
	}
	return W(&out), nil
}

// ========== Module ==========

type DirectSumModule[M algebra.Module[E, S], E algebra.ModuleElement[E, S], S algebra.RingElement[S], W DirectPowerInheritterPtrConstraint[E, WT], WT any] struct {
	DirectPowerGroup[M, E, W, WT]
}

func (s *DirectSumModule[M, E, S, W, WT]) ScalarStructure() algebra.Structure[S] {
	return s.base.ScalarStructure()
}

func (s *DirectSumModule[M, E, S, W, WT]) MultiScalarOp(scalars []S, elements []W) (W, error) {
	if len(scalars) != len(elements) {
		return nil, errs.NewLength("incorrect component count")
	}
	componentWiseElements := make([][]E, s.arity)
	for i := range s.arity {
		componentWiseElements[i] = make([]E, len(elements))
		for j, e := range elements {
			if !e.Arity().Equal(s.Arity()) {
				return nil, errs.NewLength("incorrect component count")
			}
			componentWiseElements[i][j] = e.Components()[i]
		}
	}
	var err error
	values := make([]E, s.arity)
	for i := range s.arity {
		values[i], err = s.base.MultiScalarOp(scalars, componentWiseElements[i])
		if err != nil {
			return nil, errs.WrapFailed(err, "failed to compute scalar operation for component %d", i)
		}
	}
	var out WT
	if err := W(&out).set(s.arity, values...); err != nil {
		return nil, errs.WrapFailed(err, "failed to set components")
	}
	return W(&out), nil
}

type DirectSumModuleElement[E algebra.ModuleElement[E, S], S algebra.RingElement[S], W DirectPowerInheritterPtrConstraint[E, WT], WT any] struct {
	DirectPowerGroupElement[E, W, WT]
}

func (d *DirectSumModuleElement[E, S, W, WT]) CoDiagonal() E {
	if d.Arity().IsZero() {
		panic(errs.NewSize("cannot compute diagonal of empty element"))
	}
	out := d.components[0]
	for _, c := range d.components[1:] {
		out = out.Op(c)
	}
	return out
}

func (d *DirectSumModuleElement[E, S, W, WT]) IsTorsionFree() bool {
	return sliceutils.All(d.components, func(c E) bool {
		return c.IsTorsionFree()
	})
}

func (d *DirectSumModuleElement[E, S, W, WT]) ScalarOp(s S) W {
	values := make([]E, d.arity)
	for i, c := range d.components {
		values[i] = c.ScalarOp(s)
	}
	var out WT
	if err := W(&out).set(d.arity, values...); err != nil {
		panic(errs.WrapFailed(err, "failed to set components"))
	}
	return W(&out)
}
