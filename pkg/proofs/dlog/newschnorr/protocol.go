package newschnorr

import (
	"io"

	"github.com/bronlabs/bron-crypto/pkg/base/algebra"
	"github.com/bronlabs/bron-crypto/pkg/base/errs"
	"github.com/bronlabs/bron-crypto/pkg/base/nt/num"
	"github.com/bronlabs/bron-crypto/pkg/proofs/dlog"
	"github.com/bronlabs/bron-crypto/pkg/proofs/internal/meta/newmaurer09"
	"github.com/bronlabs/bron-crypto/pkg/proofs/sigma"
)

const Name sigma.Name = "SCHNORR" + dlog.Type

type (
	Witness[S algebra.PrimeFieldElement[S]]                                       = newmaurer09.Witness[S]
	Statement[G algebra.PrimeGroupElement[G, S], S algebra.PrimeFieldElement[S]]  = newmaurer09.Statement[G]
	State[S algebra.PrimeFieldElement[S]]                                         = newmaurer09.State[S]
	Commitment[G algebra.PrimeGroupElement[G, S], S algebra.PrimeFieldElement[S]] = newmaurer09.Commitment[G]
	Response[S algebra.PrimeFieldElement[S]]                                      = newmaurer09.Response[S]
)

func NewWitness[S algebra.PrimeFieldElement[S]](w S) *Witness[S] {
	return &Witness[S]{W: w}
}

func NewStatement[G algebra.PrimeGroupElement[G, S], S algebra.PrimeFieldElement[S]](x G) *Statement[G, S] {
	return &Statement[G, S]{X: x}
}

type Protocol[G algebra.PrimeGroupElement[G, S], S algebra.PrimeFieldElement[S]] struct {
	newmaurer09.Protocol[G, S]
}

func NewProtocol[G algebra.PrimeGroupElement[G, S], S algebra.PrimeFieldElement[S]](generator G, prng io.Reader) (*Protocol[G, S], error) {
	group := algebra.StructureMustBeAs[algebra.PrimeGroup[G, S]](generator.Structure())
	scalarField := algebra.StructureMustBeAs[algebra.PrimeField[S]](group.ScalarStructure())
	challengeByteLen := 16
	soundnessError := uint(challengeByteLen * 8)
	homomorphism := func(s S) G { return generator.ScalarOp(s) }
	l, err := num.N().FromBytes(group.Order().Bytes())
	if err != nil {
		return nil, errs.WrapFailed(err, "cannot create anchor")
	}
	anc := &anchor[G, S]{l, scalarField.Zero()}

	maurerProto, err := newmaurer09.NewProtocol(
		challengeByteLen,
		soundnessError,
		Name,
		group,
		scalarField,
		homomorphism,
		anc,
		prng,
	)
	if err != nil {
		return nil, errs.NewFailed("cannot create Maurer protocol")
	}

	return &Protocol[G, S]{*maurerProto}, nil
}

type anchor[G algebra.PrimeGroupElement[G, S], S algebra.PrimeFieldElement[S]] struct {
	l  *num.Nat
	id S
}

func (a *anchor[G, S]) L() *num.Nat {
	return a.l
}

func (a *anchor[G, S]) PreImage(_ G) (w S) {
	return a.id
}

func _[G algebra.PrimeGroupElement[G, S], S algebra.PrimeFieldElement[S]](proto *Protocol[G, S]) {
	var _ sigma.MaurerProtocol[G, S, *Statement[G, S], *Witness[S], *Commitment[G, S], *State[S], *Response[S]] = proto
}
