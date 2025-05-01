package products

import (
	"fmt"

	"github.com/bronlabs/bron-crypto/pkg/base/algebra"
	"github.com/bronlabs/bron-crypto/pkg/base/algebra/impl/traits"
	"github.com/bronlabs/bron-crypto/pkg/base/algebra/rings"
)

func NewDirectProductRing[R1 rings.Ring[E1], E1 rings.RingElement[E1], R2 rings.Ring[E2], E2 rings.RingElement[E2]](r1 R1, r2 R2) *DirectProductRing[R1, E1, R2, E2] {
	out := &DirectProductRing[R1, E1, R2, E2]{}
	out.Set(r1, r2)
	var _ rings.Ring[*DirectProductRingElement[E1, E2]] = out
	return out
}

func NewDirectProductRingElement[E1 rings.RingElement[E1], E2 rings.RingElement[E2]](left E1, right E2) *DirectProductRingElement[E1, E2] {
	out := &DirectProductRingElement[E1, E2]{}
	out.Set(left, right)
	var _ rings.RingElement[*DirectProductRingElement[E1, E2]] = out
	return out
}

type DirectProductRing[R1 rings.Ring[E1], E1 rings.RingElement[E1], R2 rings.Ring[E2], E2 rings.RingElement[E2]] struct {
	traits.DirectProductRing[R1, E1, R2, E2, *DirectProductRingElement[E1, E2], DirectProductRingElement[E1, E2]]
}

func (r *DirectProductRing[R1, E1, R2, E2]) Name() string {
	return fmt.Sprintf("direct product of %s and %s", r.Left().Name(), r.Right().Name())
}

func (r *DirectProductRing[R1, E1, R2, E2]) Operator() algebra.BinaryOperator[*DirectProductRingElement[E1, E2]] {
	return algebra.Add[*DirectProductRingElement[E1, E2]]
}

func (r *DirectProductRing[R1, E1, R2, E2]) OtherOperator() algebra.BinaryOperator[*DirectProductRingElement[E1, E2]] {
	return algebra.Mul[*DirectProductRingElement[E1, E2]]
}

type DirectProductRingElement[E1 rings.RingElement[E1], E2 rings.RingElement[E2]] struct {
	traits.DirectProductRingElement[E1, E2, *DirectProductRingElement[E1, E2], DirectProductRingElement[E1, E2]]
}

func (r *DirectProductRingElement[E1, E2]) Structure() algebra.Structure[*DirectProductRingElement[E1, E2]] {
	return NewDirectProductRing(rings.GetRing(r.Left()), rings.GetRing(r.Right()))
}

func (r *DirectProductRingElement[E1, E2]) Clone() *DirectProductRingElement[E1, E2] {
	out := &DirectProductRingElement[E1, E2]{}
	out.Set(r.Left().Clone(), r.Right().Clone())
	return out
}

func (r *DirectProductRingElement[E1, E2]) MarshalBinary() ([]byte, error) {
	left, err := r.Left().MarshalBinary()
	if err != nil {
		return nil, err
	}
	right, err := r.Right().MarshalBinary()
	if err != nil {
		return nil, err
	}
	return append(left, right...), nil
}

func (r *DirectProductRingElement[E1, E2]) UnmarshalBinary(input []byte) error {
	if len(input) == 0 || len(input)%2 != 0 {
		return fmt.Errorf("invalid binary representation")
	}
	if err := r.Left().UnmarshalBinary(input[:len(input)/2]); err != nil {
		return err
	}
	if err := r.Right().UnmarshalBinary(input[len(input)/2:]); err != nil {
		return err
	}
	return nil
}
