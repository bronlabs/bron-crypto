package products

import (
	"fmt"
	"slices"

	"github.com/bronlabs/bron-crypto/pkg/base/algebra"
	"github.com/bronlabs/bron-crypto/pkg/base/algebra/groups"
	"github.com/bronlabs/bron-crypto/pkg/base/algebra/impl/traits"
	"github.com/bronlabs/bron-crypto/pkg/base/errs"
)

func NewDirectProductGroup[G1 groups.Group[E1], E1 groups.GroupElement[E1], G2 groups.Group[E2], E2 groups.GroupElement[E2]](g1 G1, g2 G2) *DirectProductGroup[G1, E1, G2, E2] {
	out := &DirectProductGroup[G1, E1, G2, E2]{}
	out.Set(g1, g2)
	var _ groups.Group[*DirectProductGroupElement[E1, E2]] = out
	return out
}

func NewDirectProductGroupElement[E1 groups.GroupElement[E1], E2 groups.GroupElement[E2]](left E1, right E2) *DirectProductGroupElement[E1, E2] {
	out := &DirectProductGroupElement[E1, E2]{}
	out.Set(left, right)
	var _ groups.GroupElement[*DirectProductGroupElement[E1, E2]] = out
	return out
}

type DirectProductGroup[G1 groups.Group[E1], E1 groups.GroupElement[E1], G2 groups.Group[E2], E2 groups.GroupElement[E2]] struct {
	traits.DirectProductGroup[G1, E1, G2, E2, *DirectProductGroupElement[E1, E2], DirectProductGroupElement[E1, E2]]
}

func (g *DirectProductGroup[G1, E1, G2, E2]) Name() string {
	return fmt.Sprintf("direct product of %s and %s", g.Left().Name(), g.Right().Name())
}

func (g *DirectProductGroup[G1, E1, G2, E2]) Operator() algebra.BinaryOperator[*DirectProductGroupElement[E1, E2]] {
	return algebra.Operate[*DirectProductGroupElement[E1, E2]]
}

type DirectProductGroupElement[E1 groups.GroupElement[E1], E2 groups.GroupElement[E2]] struct {
	traits.DirectProductGroupElement[E1, E2, *DirectProductGroupElement[E1, E2], DirectProductGroupElement[E1, E2]]
}

func (g *DirectProductGroupElement[E1, E2]) Structure() algebra.Structure[*DirectProductGroupElement[E1, E2]] {
	return NewDirectProductGroup(groups.GetGroup(g.Left()), groups.GetGroup(g.Right()))
}

func (g *DirectProductGroupElement[E1, E2]) Clone() *DirectProductGroupElement[E1, E2] {
	out := &DirectProductGroupElement[E1, E2]{}
	out.Set(g.Left().Clone(), g.Right().Clone())
	return out
}

func (g *DirectProductGroupElement[E1, E2]) MarshalBinary() ([]byte, error) {
	left, err := g.Left().MarshalBinary()
	if err != nil {
		return nil, errs.WrapSerialisation(err, "failed to marshal left element")
	}
	right, err := g.Right().MarshalBinary()
	if err != nil {
		return nil, errs.WrapSerialisation(err, "failed to marshal right element")
	}
	return slices.Concat(left, right), nil
}

func (g *DirectProductGroupElement[E1, E2]) UnmarshalBinary(input []byte) error {
	if len(input) == 0 || len(input)%2 != 0 {
		return errs.NewArgument("invalid binary representation")
	}
	var left E1
	if err := left.UnmarshalBinary(input[:len(input)/2]); err != nil {
		return errs.WrapSerialisation(err, "failed to unmarshal left element")
	}
	var right E2
	if err := right.UnmarshalBinary(input[len(input)/2:]); err != nil {
		return errs.WrapSerialisation(err, "failed to unmarshal right element")
	}
	g.Set(left, right)
	return nil
}
