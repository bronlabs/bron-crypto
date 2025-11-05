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

type Protocol[G algebra.PrimeGroupElement[G, S], S algebra.PrimeFieldElement[S]] struct {
	newmaurer09.Protocol[G, S]
}

type anchor[G algebra.PrimeGroupElement[G, S], S algebra.PrimeFieldElement[S]] struct {
	l  *num.Nat
	id S
}

func newAnchor[G algebra.PrimeGroupElement[G, S], S algebra.PrimeFieldElement[S]](group algebra.PrimeGroup[G, S], scalarField algebra.PrimeField[S]) *anchor[G, S] {
	l, _ := num.N().FromBytes(group.Order().Bytes())
	id := scalarField.Zero()
	return &anchor[G, S]{
		l:  l,
		id: id,
	}
}

func (a *anchor[G, S]) L() *num.Nat {
	return a.l
}

func (a *anchor[G, S]) PreImage(_ G) (w S) {
	return a.id
}

func NewProtocol[G algebra.PrimeGroupElement[G, S], S algebra.PrimeFieldElement[S]](generator G, prng io.Reader) (*Protocol[G, S], error) {
	group := algebra.StructureMustBeAs[algebra.PrimeGroup[G, S]](generator.Structure())
	scalarField := algebra.StructureMustBeAs[algebra.PrimeField[S]](group.ScalarStructure())
	challengeByteLen := 16
	soundnessError := uint(challengeByteLen * 8)
	homomorphism := func(s S) G { return generator.ScalarOp(s) }
	anc := newAnchor(group, scalarField)

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
