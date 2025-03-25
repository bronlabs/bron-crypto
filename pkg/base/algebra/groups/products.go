package groups

import (
	"fmt"

	"github.com/bronlabs/bron-crypto/pkg/base/algebra"
	"github.com/bronlabs/bron-crypto/pkg/base/errs"
	"github.com/cronokirby/saferith"
)

type DirectProductGroup[G1 Group[E1], E1 GroupElement[E1], G2 Group[E2], E2 GroupElement[E2]] struct {
	g1 G1
	g2 G2
}

func (g *DirectProductGroup[G1, E1, G2, E2]) Name() string {
	return fmt.Sprintf("direct product of %s and %s", g.g1.Name(), g.g2.Name())
}

func (*DirectProductGroup[G1, E1, G2, E2]) Operator() algebra.BinaryOperator[*DirectProduct[E1, E2]] {
	return algebra.Operate[*DirectProduct[E1, E2]]
}

func (g *DirectProductGroup[G1, E1, G2, E2]) Order() algebra.Cardinal {
	if g.g1.Order() == algebra.Infinite || g.g2.Order() == algebra.Infinite {
		return algebra.Infinite
	}
	return algebra.Cardinal(new(saferith.Nat).Mul(g.g1.Order(), g.g2.Order(), -1))
}

func (g *DirectProductGroup[G1, E1, G2, E2]) OpIdentity() *DirectProduct[E1, E2] {
	return &DirectProduct[E1, E2]{g.g1.OpIdentity(), g.g2.OpIdentity()}
}

type DirectProduct[E1 GroupElement[E1], E2 GroupElement[E2]] struct {
	e1 E1
	e2 E2
}

func (p *DirectProduct[E1, E2]) Left() E1 {
	return p.e1
}

func (p *DirectProduct[E1, E2]) Right() E2 {
	return p.e2
}

func (p *DirectProduct[E1, E2]) Structure() algebra.Structure[*DirectProduct[E1, E2]] {
	panic("implement me")
}

func (p *DirectProduct[E1, E2]) Op(x *DirectProduct[E1, E2]) *DirectProduct[E1, E2] {
	return &DirectProduct[E1, E2]{p.e1.Op(x.e1), p.e2.Op(x.e2)}
}

func (p *DirectProduct[E1, E2]) OpInv() *DirectProduct[E1, E2] {
	return &DirectProduct[E1, E2]{p.e1.OpInv(), p.e2.OpInv()}
}

func (p *DirectProduct[E1, E2]) IsOpIdentity() bool {
	return p.e1.IsOpIdentity() && p.e2.IsOpIdentity()
}

func (p *DirectProduct[E1, E2]) TryOpInv() (*DirectProduct[E1, E2], error) {
	e1, err := p.e1.TryOpInv()
	if err != nil {
		return nil, errs.WrapFailed(err, "failed to invert left element")
	}
	e2, err := p.e2.TryOpInv()
	if err != nil {
		return nil, errs.WrapFailed(err, "failed to invert left element")
	}
	return &DirectProduct[E1, E2]{e1, e2}, nil
}

func (p *DirectProduct[E1, E2]) Equal(x *DirectProduct[E1, E2]) bool {
	return p.e1.Equal(x.e1) && p.e2.Equal(x.e2)
}

func (p *DirectProduct[E1, E2]) Clone() *DirectProduct[E1, E2] {
	return &DirectProduct[E1, E2]{p.e1.Clone(), p.e2.Clone()}
}

func (p *DirectProduct[E1, E2]) HashCode() uint64 {
	return p.e1.HashCode() ^ p.e2.HashCode()
}

func (p *DirectProduct[E1, E2]) MarshalBinary() ([]byte, error) {
	b1, err := p.e1.MarshalBinary()
	if err != nil {
		return nil, errs.WrapFailed(err, "failed to marshal left element")
	}
	b2, err := p.e2.MarshalBinary()
	if err != nil {
		return nil, errs.WrapFailed(err, "failed to marshal right element")
	}
	return append(b1, b2...), nil
}

func (p *DirectProduct[E1, E2]) UnmarshalBinary(data []byte) error {
	if len(data) < 1 || len(data)%2 != 0 {
		return errs.NewArgument("invalid data length")
	}
	if err := p.e1.UnmarshalBinary(data[:len(data)/2]); err != nil {
		return errs.WrapFailed(err, "failed to unmarshal left element")
	}
	if err := p.e2.UnmarshalBinary(data[len(data)/2:]); err != nil {
		return errs.WrapFailed(err, "failed to unmarshal right element")
	}
	return nil
}

// type AbelianDirectProductGroup[G1 AbelianGroup[E1, S1], E1 AbelianGroupElement[E1, S1], S1 algebra.IntLike[S1], G2 AbelianGroup[E2, S2], E2 AbelianGroupElement[E2, S2], S2 algebra.IntLike[S2]] struct {
// 	DirectProductGroup[G1, E1, G2, E2]
// 	g1 G1
// 	g2 G2
// }

// type AbelianDirectProduct[E1 AbelianGroupElement[E1, S1], S1 algebra.IntLike[S1], E2 AbelianGroupElement[E2, S2], S2 algebra.IntLike[S2]] struct {
// 	DirectProduct[E1, E2]
// 	e1 E1
// 	e2 E2
// }

func _[G1 Group[E1], E1 GroupElement[E1], G2 Group[E2], E2 GroupElement[E2]]() {
	var _ Group[*DirectProduct[E1, E2]] = (*DirectProductGroup[G1, E1, G2, E2])(nil)
	var _ GroupElement[*DirectProduct[E1, E2]] = (*DirectProduct[E1, E2])(nil)
}

// func _[M1 AbelianGroup[E1, S1], E1 AbelianGroupElement[E1, S1], S1 algebra.IntLike[S1], M2 AbelianGroup[E2, S2], E2 AbelianGroupElement[E2, S2], S2 algebra.IntLike[S2]]() {
// 	var _ algebra.Module[*DirectProduct[E1, E2], *DirectProduct[S1, S2]] = (*AbelianDirectProductGroup[M1, E1, S1, M2, E2, S2])(nil)
// 	var _ algebra.ModuleElement[*DirectProduct[E1, E2], *DirectProduct[S1, S2]] = (*AbelianDirectProduct[E1, S1, E2, S2])(nil)
// }
