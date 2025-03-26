package traits

import (
	"github.com/bronlabs/bron-crypto/pkg/base/algebra"
	"github.com/cronokirby/saferith"
)

type DirectProduct[L algebra.SemiGroupElement[L], R algebra.SemiGroupElement[R]] interface {
	Components() (L, R)
	Left() L
	Right() R
}

type DirectProductInheriter[L algebra.SemiGroupElement[L], R algebra.SemiGroupElement[R]] interface {
	Set(left L, right R)
	DirectProduct[L, R]
}

type DirectProductInheriterPtrConstraint[L algebra.SemiGroupElement[L], R algebra.SemiGroupElement[R], T any] interface {
	*T
	DirectProductInheriter[L, R]
}

type DirectProductSemiGroupElement[L algebra.SemiGroupElement[L], R algebra.SemiGroupElement[R], W DirectProductInheriterPtrConstraint[L, R, WT], WT any] struct {
	left  L
	right R
}

func (d *DirectProductSemiGroupElement[L, R, W, WT]) Set(left L, right R) {
	d.left = left
	d.right = right
}

func (d *DirectProductSemiGroupElement[L, R, W, WT]) Left() L {
	return d.left
}

func (d *DirectProductSemiGroupElement[L, R, W, WT]) Right() R {
	return d.right
}

func (d *DirectProductSemiGroupElement[L, R, W, WT]) Components() (L, R) {
	return d.Left(), d.Right()
}

func (d *DirectProductSemiGroupElement[L, R, W, WT]) Op(x W) W {
	var out WT
	W(&out).Set(d.left.Op(x.Left()), d.right.Op(x.Right()))
	return W(&out)
}

func (d *DirectProductSemiGroupElement[L, R, W, WT]) Equal(x W) bool {
	return d.left.Equal(x.Left()) && d.right.Equal(x.Right())
}

func (d *DirectProductSemiGroupElement[L, R, W, WT]) HashCode() uint64 {
	return d.left.HashCode() ^ d.right.HashCode()
}

type DirectProductGroupElement[L algebra.GroupElement[L], R algebra.GroupElement[R], W DirectProductInheriterPtrConstraint[L, R, WT], WT any] struct {
	DirectProductSemiGroupElement[L, R, W, WT]
}

func (d *DirectProductGroupElement[L, R, W, WT]) IsOpIdentity() bool {
	return d.left.IsOpIdentity() && d.right.IsOpIdentity()
}

func (d *DirectProductGroupElement[L, R, W, WT]) TryOpInv() (W, error) {
	left, err := d.left.TryOpInv()
	if err != nil {
		return nil, err
	}
	right, err := d.right.TryOpInv()
	if err != nil {
		return nil, err
	}
	var out WT
	W(&out).Set(left, right)
	return W(&out), nil
}

func (d *DirectProductGroupElement[L, R, W, WT]) OpInv() W {
	var out WT
	W(&out).Set(d.left.OpInv(), d.right.OpInv())
	return W(&out)
}

type DirectProductRingElement[L algebra.RingElement[L], R algebra.RingElement[R], W DirectProductInheriterPtrConstraint[L, R, WT], WT any] struct {
	DirectProductGroupElement[L, R, W, WT]
}

func (d *DirectProductRingElement[L, R, W, WT]) OtherOp(x W) W {
	return d.Mul(x)
}

func (d *DirectProductRingElement[L, R, W, WT]) IsOne() bool {
	return d.left.IsOne() && d.right.IsOne()
}

func (d *DirectProductRingElement[L, R, W, WT]) IsZero() bool {
	return d.left.IsZero() && d.right.IsZero()
}

func (d *DirectProductRingElement[L, R, W, WT]) Add(x W) W {
	var out WT
	W(&out).Set(d.left.Add(x.Left()), d.right.Add(x.Right()))
	return W(&out)
}

func (d *DirectProductRingElement[L, R, W, WT]) TrySub(x W) (W, error) {
	left, err := d.left.TrySub(x.Left())
	if err != nil {
		return nil, err
	}
	right, err := d.right.TrySub(x.Right())
	if err != nil {
		return nil, err
	}
	var out WT
	W(&out).Set(left, right)
	return W(&out), nil
}

func (d *DirectProductRingElement[L, R, W, WT]) Sub(x W) W {
	var out WT
	W(&out).Set(d.left.Sub(x.Left()), d.right.Sub(x.Right()))
	return W(&out)
}

func (d *DirectProductRingElement[L, R, W, WT]) Mul(x W) W {
	var out WT
	W(&out).Set(d.left.Mul(x.Left()), d.right.Mul(x.Right()))
	return W(&out)
}

func (d *DirectProductRingElement[L, R, W, WT]) TryDiv(x W) (W, error) {
	left, err := d.left.TryDiv(x.Left())
	if err != nil {
		return nil, err
	}
	right, err := d.right.TryDiv(x.Right())
	if err != nil {
		return nil, err
	}
	var out WT
	W(&out).Set(left, right)
	return W(&out), nil
}

func (d *DirectProductRingElement[L, R, W, WT]) TryInv() (W, error) {
	left, err := d.left.TryInv()
	if err != nil {
		return nil, err
	}
	right, err := d.right.TryInv()
	if err != nil {
		return nil, err
	}
	var out WT
	W(&out).Set(left, right)
	return W(&out), nil
}

func (d *DirectProductRingElement[L, R, W, WT]) TryNeg() (W, error) {
	left, err := d.left.TryNeg()
	if err != nil {
		return nil, err
	}
	right, err := d.right.TryNeg()
	if err != nil {
		return nil, err
	}
	var out WT
	W(&out).Set(left, right)
	return W(&out), nil
}

func (d *DirectProductRingElement[L, R, W, WT]) Double() W {
	var out WT
	W(&out).Set(d.left.Double(), d.right.Double())
	return W(&out)
}

func (d *DirectProductRingElement[L, R, W, WT]) Square() W {
	var out WT
	W(&out).Set(d.left.Square(), d.right.Square())
	return W(&out)
}

func (d *DirectProductRingElement[L, R, W, WT]) Neg() W {
	var out WT
	W(&out).Set(d.left.Neg(), d.right.Neg())
	return W(&out)
}

type DirectProductModuleElement[
	L algebra.ModuleElement[L, SL],
	SL algebra.RingElement[SL],
	R algebra.ModuleElement[R, SR],
	SR algebra.RingElement[SR],
	S DirectProduct[SL, SR],
	W DirectProductInheriterPtrConstraint[L, R, WT], WT any] struct {
	DirectProductGroupElement[L, R, W, WT]
}

func (d *DirectProductModuleElement[L, SL, R, SR, S, W, WT]) IsTorsionFree() bool {
	return d.left.IsTorsionFree() && d.right.IsTorsionFree()
}

func (d *DirectProductModuleElement[L, SL, R, SR, S, W, WT]) ScalarMul(s S) W {
	var out WT
	W(&out).Set(d.left.ScalarMul(s.Left()), d.right.ScalarMul(s.Right()))
	return W(&out)
}

type DirectProductSemiGroup[S1 algebra.SemiGroup[E1], E1 algebra.SemiGroupElement[E1], S2 algebra.SemiGroup[E2], E2 algebra.SemiGroupElement[E2], W DirectProductInheriterPtrConstraint[E1, E2, WT], WT any] struct {
	left  S1
	right S2
}

func (s *DirectProductSemiGroup[S1, E1, S2, E2, W, WT]) Set(left S1, right S2) {
	s.left = left
	s.right = right
}

func (s *DirectProductSemiGroup[S1, E1, S2, E2, W, WT]) Left() S1 {
	return s.left
}

func (s *DirectProductSemiGroup[S1, E1, S2, E2, W, WT]) Right() S2 {
	return s.right
}

func (s *DirectProductSemiGroup[S1, E1, S2, E2, W, WT]) Components() (S1, S2) {
	return s.Left(), s.Right()
}

func (s *DirectProductSemiGroup[S1, E1, S2, E2, W, WT]) Order() algebra.Cardinal {
	if s.left.Order() == algebra.Infinite || s.right.Order() == algebra.Infinite {
		return algebra.Infinite
	}
	return algebra.Cardinal(new(saferith.Nat).Mul(s.left.Order(), s.right.Order(), -1))
}

type DirectProductGroup[S1 algebra.Group[E1], E1 algebra.GroupElement[E1], S2 algebra.Group[E2], E2 algebra.GroupElement[E2], W DirectProductInheriterPtrConstraint[E1, E2, WT], WT any] struct {
	DirectProductSemiGroup[S1, E1, S2, E2, W, WT]
}

func (s *DirectProductGroup[S1, E1, S2, E2, W, WT]) OpIdentity() W {
	var out WT
	W(&out).Set(s.left.OpIdentity(), s.right.OpIdentity())
	return W(&out)
}
