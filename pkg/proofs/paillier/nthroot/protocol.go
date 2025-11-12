package nthroot

import (
	"io"

	"github.com/bronlabs/bron-crypto/pkg/base/errs"
	"github.com/bronlabs/bron-crypto/pkg/base/nt/num"
	"github.com/bronlabs/bron-crypto/pkg/base/nt/znstar"
	"github.com/bronlabs/bron-crypto/pkg/proofs/internal/meta/maurer09"
	"github.com/bronlabs/bron-crypto/pkg/proofs/sigma"
)

const Name sigma.Name = "PAILLIER_NTH_ROOTS"

type (
	Witness[A znstar.ArithmeticPaillier]    = maurer09.Witness[*znstar.PaillierGroupElement[A]]
	Statement[A znstar.ArithmeticPaillier]  = maurer09.Statement[*znstar.PaillierGroupElement[A]]
	State[A znstar.ArithmeticPaillier]      = maurer09.State[*znstar.PaillierGroupElement[A]]
	Commitment[A znstar.ArithmeticPaillier] = maurer09.Commitment[*znstar.PaillierGroupElement[A]]
	Response[A znstar.ArithmeticPaillier]   = maurer09.Response[*znstar.PaillierGroupElement[A]]
)

func NewStatement[X znstar.ArithmeticPaillier](x *znstar.PaillierGroupElement[X]) *Statement[X] {
	return &Statement[X]{
		X: x,
	}
}

func NewWitness[X znstar.ArithmeticPaillier](w *znstar.PaillierGroupElement[X]) *Witness[X] {
	return &Witness[X]{
		W: w,
	}
}

type Protocol[A znstar.ArithmeticPaillier] struct {
	maurer09.Protocol[*znstar.PaillierGroupElement[A], *znstar.PaillierGroupElement[A]]
}

func NewProtocol[A znstar.ArithmeticPaillier](group *znstar.PaillierGroup[A], prng io.Reader) (*Protocol[A], error) {
	oneWayHomomorphism := func(x *znstar.PaillierGroupElement[A]) *znstar.PaillierGroupElement[A] {
		y, _ := group.NthResidue(x.ForgetOrder())
		return y
	}
	anc := &anchor[A]{
		n: group.N().Nat(),
	}
	challengeBitLen := 128
	challengeByteLen := (challengeBitLen + 7) / 8
	soundnessError := uint(challengeBitLen)
	scalarMul := func(unit *znstar.PaillierGroupElement[A], eBytes []byte) *znstar.PaillierGroupElement[A] {
		e, _ := num.N().FromBytes(eBytes)
		return unit.Exp(e)
	}

	proto, err := maurer09.NewProtocol(
		challengeByteLen,
		soundnessError,
		Name,
		group,
		group,
		oneWayHomomorphism,
		anc,
		prng,
		maurer09.WithImageScalarMul[*znstar.PaillierGroupElement[A], *znstar.PaillierGroupElement[A]](scalarMul),
		maurer09.WithPreImageScalarMul[*znstar.PaillierGroupElement[A], *znstar.PaillierGroupElement[A]](scalarMul),
	)
	if err != nil {
		return nil, errs.WrapFailed(err, "cannot create underlying Maurer09 protocol")
	}
	return &Protocol[A]{*proto}, nil
}

type anchor[A znstar.ArithmeticPaillier] struct {
	n *num.Nat
}

func (a *anchor[A]) L() *num.Nat {
	return a.n
}

func (a *anchor[A]) PreImage(x *znstar.PaillierGroupElement[A]) (w *znstar.PaillierGroupElement[A]) {
	return x
}
