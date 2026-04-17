package traits

import (
	"fmt"
	"io"
	"slices"

	"github.com/bronlabs/errs-go/errs"

	"github.com/bronlabs/bron-crypto/pkg/base"
	"github.com/bronlabs/bron-crypto/pkg/base/algebra"
	"github.com/bronlabs/bron-crypto/pkg/base/nt/cardinal"
	"github.com/bronlabs/bron-crypto/pkg/base/nt/numct"
	"github.com/bronlabs/bron-crypto/pkg/base/serde"
	"github.com/bronlabs/bron-crypto/pkg/base/utils"
)

type DirectProduct[E1 algebra.SemiGroupElement[E1], E2 algebra.SemiGroupElement[E2]] interface {
	algebra.NAry
	Components() (E1, E2)
	set(E1, E2) error
}

type DirectProductInheritter[E1 algebra.SemiGroupElement[E1], E2 algebra.SemiGroupElement[E2]] interface {
	DirectProduct[E1, E2]
}

type DirectProductInheritterPtrConstraint[E1 algebra.SemiGroupElement[E1], E2 algebra.SemiGroupElement[E2], T any] interface {
	*T
	DirectProductInheritter[E1, E2]
}

// ========== SemiGroup ===========.

type DirectProductSemiGroup[S1 algebra.SemiGroup[E1], S2 algebra.SemiGroup[E2], E1 algebra.SemiGroupElement[E1], E2 algebra.SemiGroupElement[E2], W DirectProductInheritterPtrConstraint[E1, E2, WT], WT any] struct {
	s1 S1
	s2 S2
}

type directProductSemiGroupDTO[S1 algebra.SemiGroup[E1], S2 algebra.SemiGroup[E2], E1 algebra.SemiGroupElement[E1], E2 algebra.SemiGroupElement[E2]] struct {
	S1 S1 `cbor:"s1"`
	S2 S2 `cbor:"s2"`
}

func (d *DirectProductSemiGroup[S1, S2, E1, E2, W, WT]) Components() (first S1, second S2) {
	return d.s1, d.s2
}

func (*DirectProductSemiGroup[S1, S2, E1, E2, W, WT]) Arity() cardinal.Cardinal {
	return cardinal.New(2)
}

func (d *DirectProductSemiGroup[S1, S2, E1, E2, W, WT]) set(s1 S1, s2 S2) error { //nolint:unused // needed for trait interface compliance.
	if utils.IsNil(s1) || utils.IsNil(s2) {
		return ErrInvalidArgument.WithMessage("components cannot be nil")
	}
	d.s1 = s1
	d.s2 = s2
	return nil
}

func (d *DirectProductSemiGroup[S1, S2, E1, E2, W, WT]) ElementSize() int {
	return d.s1.ElementSize() + d.s2.ElementSize()
}

func (d *DirectProductSemiGroup[S1, S2, E1, E2, W, WT]) Name() string {
	return fmt.Sprintf("(%s x %s)", d.s1.Name(), d.s2.Name())
}

func (d *DirectProductSemiGroup[S1, S2, E1, E2, W, WT]) FromBytes(input []byte) (W, error) {
	if len(input) != d.ElementSize() {
		return nil, ErrInvalidArgument.WithMessage("input length does not match element size")
	}
	e1Bytes := input[:d.s1.ElementSize()]
	e2Bytes := input[d.s1.ElementSize():]
	e1, err := d.s1.FromBytes(e1Bytes)
	if err != nil {
		return nil, errs.Wrap(err).WithMessage("failed to parse first component")
	}
	e2, err := d.s2.FromBytes(e2Bytes)
	if err != nil {
		return nil, errs.Wrap(err).WithMessage("failed to parse second component")
	}
	var out WT
	if err := W(&out).set(e1, e2); err != nil {
		return nil, errs.Wrap(err).WithMessage("failed to set components")
	}
	return W(&out), nil
}

func (*DirectProductSemiGroup[S1, S2, E1, E2, W, WT]) New(e1 E1, e2 E2) (W, error) {
	var out WT
	if err := W(&out).set(e1, e2); err != nil {
		return nil, errs.Wrap(err).WithMessage("failed to set components")
	}
	return W(&out), nil
}

func (d *DirectProductSemiGroup[S1, S2, E1, E2, W, WT]) Set(s1 S1, s2 S2) error {
	if utils.IsNil(s1) || utils.IsNil(s2) {
		return ErrInvalidArgument.WithMessage("components cannot be nil")
	}
	d.s1 = s1
	d.s2 = s2
	return nil
}

func (d *DirectProductSemiGroup[S1, S2, E1, E2, W, WT]) Order() cardinal.Cardinal {
	return d.s1.Order().Mul(d.s2.Order())
}

func (d *DirectProductSemiGroup[S1, S2, E1, E2, W, WT]) MarshalCBOR() ([]byte, error) {
	dto := directProductSemiGroupDTO[S1, S2, E1, E2]{
		S1: d.s1,
		S2: d.s2,
	}
	out, err := serde.MarshalCBOR(dto)
	if err != nil {
		return nil, errs.Wrap(err).WithMessage("failed to marshal direct product semi-group to CBOR")
	}
	return out, nil
}

func (d *DirectProductSemiGroup[S1, S2, E1, E2, W, WT]) UnmarshalCBOR(data []byte) error {
	dto, err := serde.UnmarshalCBOR[directProductSemiGroupDTO[S1, S2, E1, E2]](data)
	if err != nil {
		return errs.Wrap(err).WithMessage("failed to unmarshal direct product semi-group from CBOR")
	}
	if err := d.Set(dto.S1, dto.S2); err != nil {
		return errs.Wrap(err).WithMessage("failed to set direct product semi-group from unmarshaled DTO")
	}
	return nil
}

type DirectProductSemiGroupElement[E1 algebra.SemiGroupElement[E1], E2 algebra.SemiGroupElement[E2], W DirectProductInheritterPtrConstraint[E1, E2, WT], WT any] struct {
	e1 E1
	e2 E2
}

type directProductSemiGroupElementDTO[E1 algebra.SemiGroupElement[E1], E2 algebra.SemiGroupElement[E2]] struct {
	E1 E1 `cbor:"e1"`
	E2 E2 `cbor:"e2"`
}

func (*DirectProductSemiGroupElement[E1, E2, W, WT]) Arity() cardinal.Cardinal {
	return cardinal.New(2)
}

func (d *DirectProductSemiGroupElement[E1, E2, W, WT]) Components() (first E1, second E2) {
	return d.e1, d.e2
}

func (d *DirectProductSemiGroupElement[E1, E2, W, WT]) Bytes() []byte {
	return slices.Concat(d.e1.Bytes(), d.e2.Bytes())
}

func (d *DirectProductSemiGroupElement[E1, E2, W, WT]) set(e1 E1, e2 E2) error {
	if utils.IsNil(e1) || utils.IsNil(e2) {
		return ErrInvalidArgument.WithMessage("components cannot be nil")
	}
	d.e1 = e1
	d.e2 = e2
	return nil
}

func (d *DirectProductSemiGroupElement[E1, E2, W, WT]) Op(other W) W {
	if utils.IsNil(other) {
		panic(ErrInvalidArgument.WithMessage("other cannot be nil"))
	}
	e1, e2 := other.Components()
	newE1 := d.e1.Op(e1)
	newE2 := d.e2.Op(e2)

	var out WT
	if err := W(&out).set(newE1, newE2); err != nil {
		panic(errs.Wrap(err).WithMessage("failed to set components of result"))
	}
	return W(&out)
}

func (d *DirectProductSemiGroupElement[E1, E2, W, WT]) Equal(other W) bool {
	if utils.IsNil(other) {
		return false
	}
	e1, e2 := other.Components()
	return d.e1.Equal(e1) && d.e2.Equal(e2)
}

func (d *DirectProductSemiGroupElement[E1, E2, W, WT]) HashCode() base.HashCode {
	return d.e1.HashCode().Combine(d.e2.HashCode())
}

func (d *DirectProductSemiGroupElement[E1, E2, W, WT]) Clone() W {
	e1Clone := d.e1.Clone()
	e2Clone := d.e2.Clone()

	var out WT
	if err := W(&out).set(e1Clone, e2Clone); err != nil {
		panic(errs.Wrap(err).WithMessage("failed to set components of clone"))
	}
	return W(&out)
}

func (d *DirectProductSemiGroupElement[E1, E2, W, WT]) String() string {
	return fmt.Sprintf("(%s, %s)", d.e1.String(), d.e2.String())
}

func (d *DirectProductSemiGroupElement[E1, E2, W, WT]) MarshalCBOR() ([]byte, error) {
	dto := directProductSemiGroupElementDTO[E1, E2]{
		E1: d.e1,
		E2: d.e2,
	}
	out, err := serde.MarshalCBOR(dto)
	if err != nil {
		return nil, errs.Wrap(err).WithMessage("failed to marshal direct product semi-group element to CBOR")
	}
	return out, nil
}

func (d *DirectProductSemiGroupElement[E1, E2, W, WT]) UnmarshalCBOR(data []byte) error {
	dto, err := serde.UnmarshalCBOR[directProductSemiGroupElementDTO[E1, E2]](data)
	if err != nil {
		return errs.Wrap(err).WithMessage("failed to unmarshal direct product semi-group element from CBOR")
	}
	if utils.IsNil(dto.E1) || utils.IsNil(dto.E2) {
		return ErrInvalidArgument.WithMessage("components in unmarshaled DTO cannot be nil")
	}
	if err := d.set(dto.E1, dto.E2); err != nil {
		return errs.Wrap(err).WithMessage("failed to set direct product semi-group element from unmarshaled DTO")
	}
	return nil
}

// ========== Group ==========.

type DirectProductGroup[S1 algebra.Group[E1], S2 algebra.Group[E2], E1 algebra.GroupElement[E1], E2 algebra.GroupElement[E2], W DirectProductInheritterPtrConstraint[E1, E2, WT], WT any] struct {
	DirectProductSemiGroup[S1, S2, E1, E2, W, WT]
}

func (s *DirectProductGroup[S1, S2, E1, E2, W, WT]) OpIdentity() W {
	var out WT
	if err := W(&out).set(s.s1.OpIdentity(), s.s2.OpIdentity()); err != nil {
		panic(errs.Wrap(err).WithMessage("failed to set components"))
	}
	return W(&out)
}

type DirectProductGroupElement[E1 algebra.GroupElement[E1], E2 algebra.GroupElement[E2], W DirectProductInheritterPtrConstraint[E1, E2, WT], WT any] struct {
	DirectProductSemiGroupElement[E1, E2, W, WT]
}

func (d *DirectProductGroupElement[E1, E2, W, WT]) IsOpIdentity() bool {
	return d.e1.IsOpIdentity() && d.e2.IsOpIdentity()
}

func (d *DirectProductGroupElement[E1, E2, W, WT]) OpInv() W {
	var out WT
	if err := W(&out).set(d.e1.OpInv(), d.e2.OpInv()); err != nil {
		panic(errs.Wrap(err).WithMessage("failed to set components"))
	}
	return W(&out)
}

// ========== Ring ==========.

type DirectProductRing[R1 algebra.Ring[E1], R2 algebra.Ring[E2], E1 algebra.RingElement[E1], E2 algebra.RingElement[E2], W DirectProductInheritterPtrConstraint[E1, E2, WT], WT any] struct {
	DirectProductGroup[R1, R2, E1, E2, W, WT]
}

func (*DirectProductRing[R1, R2, E1, E2, W, WT]) IsDomain() bool {
	return false
}

func (s *DirectProductRing[R1, R2, E1, E2, W, WT]) Zero() W {
	var out WT
	if err := W(&out).set(s.s1.Zero(), s.s2.Zero()); err != nil {
		panic(errs.Wrap(err).WithMessage("failed to set components"))
	}
	return W(&out)
}

func (s *DirectProductRing[R1, R2, E1, E2, W, WT]) One() W {
	var out WT
	if err := W(&out).set(s.s1.One(), s.s2.One()); err != nil {
		panic(errs.Wrap(err).WithMessage("failed to set components"))
	}
	return W(&out)
}

// Characteristic returns lcm(char R1, char R2), the true characteristic of
// R1 x R2. Unknown on either side is contagious; a zero characteristic on
// either side (no finite annihilator) propagates as zero via numct.LCM.
func (s *DirectProductRing[R1, R2, E1, E2, W, WT]) Characteristic() cardinal.Cardinal {
	c1 := s.s1.Characteristic()
	c2 := s.s2.Characteristic()
	if c1.IsUnknown() || c2.IsUnknown() {
		return cardinal.Unknown()
	}
	k1, ok1 := c1.(cardinal.Known)
	k2, ok2 := c2.(cardinal.Known)
	if !ok1 || !ok2 {
		return cardinal.Unknown()
	}
	var out numct.Nat
	numct.LCM(&out, k1.Nat(), k2.Nat())
	return cardinal.Known(out.BytesBE())
}

type DirectProductRingElement[E1 algebra.RingElement[E1], E2 algebra.RingElement[E2], W DirectProductInheritterPtrConstraint[E1, E2, WT], WT any] struct {
	DirectProductGroupElement[E1, E2, W, WT]
}

func (d *DirectProductRingElement[E1, E2, W, WT]) OtherOp(x W) W {
	return d.Mul(x)
}

func (d *DirectProductRingElement[E1, E2, W, WT]) IsZero() bool {
	return d.e1.IsZero() && d.e2.IsZero()
}

func (d *DirectProductRingElement[E1, E2, W, WT]) IsOne() bool {
	return d.e1.IsOne() && d.e2.IsOne()
}

func (d *DirectProductRingElement[E1, E2, W, WT]) Add(x W) W {
	if utils.IsNil(x) {
		panic(ErrInvalidArgument.WithMessage("other cannot be nil"))
	}
	e1, e2 := x.Components()
	var out WT
	if err := W(&out).set(d.e1.Add(e1), d.e2.Add(e2)); err != nil {
		panic(errs.Wrap(err).WithMessage("failed to set components"))
	}
	return W(&out)
}

func (d *DirectProductRingElement[E1, E2, W, WT]) Sub(x W) W {
	if utils.IsNil(x) {
		panic(ErrInvalidArgument.WithMessage("other cannot be nil"))
	}
	e1, e2 := x.Components()
	var out WT
	if err := W(&out).set(d.e1.Sub(e1), d.e2.Sub(e2)); err != nil {
		panic(errs.Wrap(err).WithMessage("failed to set components"))
	}
	return W(&out)
}

func (d *DirectProductRingElement[E1, E2, W, WT]) TrySub(x W) (W, error) {
	if utils.IsNil(x) {
		return nil, ErrInvalidArgument.WithMessage("other cannot be nil")
	}
	e1, e2 := x.Components()
	r1, err := d.e1.TrySub(e1)
	if err != nil {
		return nil, errs.Wrap(err).WithMessage("failed to subtract first component")
	}
	r2, err := d.e2.TrySub(e2)
	if err != nil {
		return nil, errs.Wrap(err).WithMessage("failed to subtract second component")
	}
	var out WT
	if err := W(&out).set(r1, r2); err != nil {
		return nil, errs.Wrap(err).WithMessage("failed to set components")
	}
	return W(&out), nil
}

func (d *DirectProductRingElement[E1, E2, W, WT]) Mul(x W) W {
	if utils.IsNil(x) {
		panic(ErrInvalidArgument.WithMessage("other cannot be nil"))
	}
	e1, e2 := x.Components()
	var out WT
	if err := W(&out).set(d.e1.Mul(e1), d.e2.Mul(e2)); err != nil {
		panic(errs.Wrap(err).WithMessage("failed to set components"))
	}
	return W(&out)
}

func (d *DirectProductRingElement[E1, E2, W, WT]) TryDiv(x W) (W, error) {
	if utils.IsNil(x) {
		return nil, ErrInvalidArgument.WithMessage("other cannot be nil")
	}
	e1, e2 := x.Components()
	r1, err := d.e1.TryDiv(e1)
	if err != nil {
		return nil, errs.Wrap(err).WithMessage("failed to divide first component")
	}
	r2, err := d.e2.TryDiv(e2)
	if err != nil {
		return nil, errs.Wrap(err).WithMessage("failed to divide second component")
	}
	var out WT
	if err := W(&out).set(r1, r2); err != nil {
		return nil, errs.Wrap(err).WithMessage("failed to set components")
	}
	return W(&out), nil
}

func (d *DirectProductRingElement[E1, E2, W, WT]) TryInv() (W, error) {
	r1, err := d.e1.TryInv()
	if err != nil {
		return nil, errs.Wrap(err).WithMessage("failed to invert first component")
	}
	r2, err := d.e2.TryInv()
	if err != nil {
		return nil, errs.Wrap(err).WithMessage("failed to invert second component")
	}
	var out WT
	if err := W(&out).set(r1, r2); err != nil {
		return nil, errs.Wrap(err).WithMessage("failed to set components")
	}
	return W(&out), nil
}

func (d *DirectProductRingElement[E1, E2, W, WT]) TryNeg() (W, error) {
	r1, err := d.e1.TryNeg()
	if err != nil {
		return nil, errs.Wrap(err).WithMessage("failed to negate first component")
	}
	r2, err := d.e2.TryNeg()
	if err != nil {
		return nil, errs.Wrap(err).WithMessage("failed to negate second component")
	}
	var out WT
	if err := W(&out).set(r1, r2); err != nil {
		return nil, errs.Wrap(err).WithMessage("failed to set components")
	}
	return W(&out), nil
}

func (d *DirectProductRingElement[E1, E2, W, WT]) Double() W {
	var out WT
	if err := W(&out).set(d.e1.Double(), d.e2.Double()); err != nil {
		panic(errs.Wrap(err).WithMessage("failed to set components"))
	}
	return W(&out)
}

func (d *DirectProductRingElement[E1, E2, W, WT]) Square() W {
	var out WT
	if err := W(&out).set(d.e1.Square(), d.e2.Square()); err != nil {
		panic(errs.Wrap(err).WithMessage("failed to set components"))
	}
	return W(&out)
}

func (d *DirectProductRingElement[E1, E2, W, WT]) Neg() W {
	var out WT
	if err := W(&out).set(d.e1.Neg(), d.e2.Neg()); err != nil {
		panic(errs.Wrap(err).WithMessage("failed to set components"))
	}
	return W(&out)
}

// ================ Misc =======================.

type DirectProductOfFiniteStructures[S1 interface {
	algebra.SemiGroup[E1]
	algebra.FiniteStructure[E1]
}, S2 interface {
	algebra.SemiGroup[E2]
	algebra.FiniteStructure[E2]
}, E1 algebra.SemiGroupElement[E1], E2 algebra.SemiGroupElement[E2], W DirectProductInheritterPtrConstraint[E1, E2, WT], WT any] struct {
	s1 S1
	s2 S2
}

func (s *DirectProductOfFiniteStructures[S1, S2, E1, E2, W, WT]) SetFiniteStructureAttributes(s1 S1, s2 S2) error {
	if utils.IsNil(s1) || utils.IsNil(s2) {
		return ErrInvalidArgument.WithMessage("components cannot be nil")
	}
	s.s1 = s1
	s.s2 = s2
	return nil
}

func (s *DirectProductOfFiniteStructures[S1, S2, E1, E2, W, WT]) Random(prng io.Reader) (W, error) {
	e1, err := s.s1.Random(prng)
	if err != nil {
		return nil, errs.Wrap(err).WithMessage("failed to generate random first component")
	}
	e2, err := s.s2.Random(prng)
	if err != nil {
		return nil, errs.Wrap(err).WithMessage("failed to generate random second component")
	}
	var out WT
	if err := W(&out).set(e1, e2); err != nil {
		return nil, errs.Wrap(err).WithMessage("failed to set components")
	}
	return W(&out), nil
}

func (s *DirectProductOfFiniteStructures[S1, S2, E1, E2, W, WT]) Hash(input []byte) (W, error) {
	e1, err := s.s1.Hash(input)
	if err != nil {
		return nil, errs.Wrap(err).WithMessage("failed to hash first component")
	}
	e2, err := s.s2.Hash(input)
	if err != nil {
		return nil, errs.Wrap(err).WithMessage("failed to hash second component")
	}
	var out WT
	if err := W(&out).set(e1, e2); err != nil {
		return nil, errs.Wrap(err).WithMessage("failed to set components")
	}
	return W(&out), nil
}

// ========== Module ==========.

type DirectProductModule[M1 algebra.Module[E1, S], M2 algebra.Module[E2, S], E1 algebra.ModuleElement[E1, S], E2 algebra.ModuleElement[E2, S], S algebra.RingElement[S], W DirectProductInheritterPtrConstraint[E1, E2, WT], WT any] struct {
	DirectProductGroup[M1, M2, E1, E2, W, WT]
}

func (s *DirectProductModule[M1, M2, E1, E2, S, W, WT]) ScalarStructure() algebra.Structure[S] {
	return s.s1.ScalarStructure()
}

type DirectProductModuleElement[E1 algebra.ModuleElement[E1, S], E2 algebra.ModuleElement[E2, S], S algebra.RingElement[S], W DirectProductInheritterPtrConstraint[E1, E2, WT], WT any] struct {
	DirectProductGroupElement[E1, E2, W, WT]
}

func (d *DirectProductModuleElement[E1, E2, S, W, WT]) IsTorsionFree() bool {
	return d.e1.IsTorsionFree() && d.e2.IsTorsionFree()
}

func (d *DirectProductModuleElement[E1, E2, S, W, WT]) ScalarOp(s S) W {
	var out WT
	if err := W(&out).set(d.e1.ScalarOp(s), d.e2.ScalarOp(s)); err != nil {
		panic(errs.Wrap(err).WithMessage("failed to set components"))
	}
	return W(&out)
}

// ========== Algebra ==========.

type DirectProductAlgebra[A1 algebra.Algebra[E1, S], A2 algebra.Algebra[E2, S], E1 algebra.AlgebraElement[E1, S], E2 algebra.AlgebraElement[E2, S], S algebra.RingElement[S], W DirectProductInheritterPtrConstraint[E1, E2, WT], WT any] struct {
	DirectProductRing[A1, A2, E1, E2, W, WT]
}

func (s *DirectProductAlgebra[A1, A2, E1, E2, S, W, WT]) ScalarStructure() algebra.Structure[S] {
	return s.s1.ScalarStructure()
}

type DirectProductAlgebraElement[E1 algebra.AlgebraElement[E1, S], E2 algebra.AlgebraElement[E2, S], S algebra.RingElement[S], W DirectProductInheritterPtrConstraint[E1, E2, WT], WT any] struct {
	DirectProductRingElement[E1, E2, W, WT]
}

func (d *DirectProductAlgebraElement[E1, E2, S, W, WT]) IsTorsionFree() bool {
	return d.e1.IsTorsionFree() && d.e2.IsTorsionFree()
}

func (d *DirectProductAlgebraElement[E1, E2, S, W, WT]) ScalarOp(s S) W {
	return d.ScalarMul(s)
}

func (d *DirectProductAlgebraElement[E1, E2, S, W, WT]) ScalarMul(s S) W {
	var out WT
	if err := W(&out).set(d.e1.ScalarMul(s), d.e2.ScalarMul(s)); err != nil {
		panic(errs.Wrap(err).WithMessage("failed to set components"))
	}
	return W(&out)
}
