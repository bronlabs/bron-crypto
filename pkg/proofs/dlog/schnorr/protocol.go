package schnorr

import (
	"io"

	"github.com/bronlabs/bron-crypto/pkg/base/algebra"
	"github.com/bronlabs/bron-crypto/pkg/base/errs2"
	"github.com/bronlabs/bron-crypto/pkg/base/nt/num"
	"github.com/bronlabs/bron-crypto/pkg/proofs/dlog"
	"github.com/bronlabs/bron-crypto/pkg/proofs/internal/meta/maurer09"
	"github.com/bronlabs/bron-crypto/pkg/proofs/sigma"
)

// Name is the protocol identifier for Schnorr's discrete log proof.
const Name sigma.Name = "SCHNORR" + dlog.Type

type (
	// Witness contains the secret scalar w such that X = g^w.
	Witness[S algebra.PrimeFieldElement[S]] = maurer09.Witness[S]
	// Statement contains the public group element X being proven.
	Statement[G algebra.PrimeGroupElement[G, S], S algebra.PrimeFieldElement[S]] = maurer09.Statement[G]
	// State holds the prover's randomness during the protocol execution.
	State[S algebra.PrimeFieldElement[S]] = maurer09.State[S]
	// Commitment is the first message sent by the prover.
	Commitment[G algebra.PrimeGroupElement[G, S], S algebra.PrimeFieldElement[S]] = maurer09.Commitment[G]
	// Response is the prover's answer to the verifier's challenge.
	Response[S algebra.PrimeFieldElement[S]] = maurer09.Response[S]
)

// NewWitness creates a new witness from a secret scalar.
func NewWitness[S algebra.PrimeFieldElement[S]](w S) *Witness[S] {
	return &Witness[S]{W: w}
}

// NewStatement creates a new statement from a public group element.
func NewStatement[G algebra.PrimeGroupElement[G, S], S algebra.PrimeFieldElement[S]](x G) *Statement[G, S] {
	return &Statement[G, S]{X: x}
}

// Protocol implements Schnorr's sigma protocol for proving knowledge of a discrete logarithm.
// Given a generator g and public element X, it proves knowledge of w such that X = g^w.
type Protocol[G algebra.PrimeGroupElement[G, S], S algebra.PrimeFieldElement[S]] struct {
	maurer09.Protocol[G, S]
}

// NewProtocol creates a new Schnorr protocol instance with the given generator and randomness source.
func NewProtocol[G algebra.PrimeGroupElement[G, S], S algebra.PrimeFieldElement[S]](generator G, prng io.Reader) (*Protocol[G, S], error) {
	group := algebra.StructureMustBeAs[algebra.PrimeGroup[G, S]](generator.Structure())
	scalarField := algebra.StructureMustBeAs[algebra.PrimeField[S]](group.ScalarStructure())
	challengeByteLen := 16
	soundnessError := uint(challengeByteLen * 8)
	homomorphism := func(s S) G { return generator.ScalarOp(s) }
	l, err := num.N().FromBytes(group.Order().Bytes())
	if err != nil {
		return nil, errs2.Wrap(err).WithMessage("cannot create anchor")
	}
	anc := &anchor[G, S]{l, scalarField.Zero()}

	maurerProto, err := maurer09.NewProtocol(
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
		return nil, errs2.Wrap(err)
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
