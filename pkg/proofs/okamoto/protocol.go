package okamoto

import (
	"io"

	"github.com/bronlabs/bron-crypto/pkg/base"
	"github.com/bronlabs/bron-crypto/pkg/base/algebra"
	"github.com/bronlabs/bron-crypto/pkg/base/algebra/constructions"
	"github.com/bronlabs/bron-crypto/pkg/base/nt/num"
	"github.com/bronlabs/bron-crypto/pkg/proofs/internal/meta/maurer09"
	"github.com/bronlabs/bron-crypto/pkg/proofs/sigma"
	"github.com/bronlabs/errs-go/errs"
)

// Name is the protocol identifier for Okamoto's proof of knowledge of a representation.
const Name sigma.Name = "OKAMOTO_PROOF_OF_KNOWLEDGE_OF_REPRESENTATION"

type (
	// Witness holds the secret exponents (x_1, ..., x_m) forming a representation of the public element z.
	Witness[S algebra.PrimeFieldElement[S]] = maurer09.Witness[*constructions.FiniteDirectPowerRingElement[S]]

	// Statement holds the public group element z whose representation is being proven.
	Statement[G algebra.PrimeGroupElement[G, S], S algebra.PrimeFieldElement[S]] = maurer09.Statement[G]

	// State holds the prover's ephemeral randomness during the protocol execution.
	State[S algebra.PrimeFieldElement[S]] = maurer09.State[*constructions.FiniteDirectPowerRingElement[S]]

	// Commitment is the first-round message sent by the prover.
	Commitment[G algebra.PrimeGroupElement[G, S], S algebra.PrimeFieldElement[S]] = maurer09.Commitment[G]

	// Response is the prover's answer to the verifier's challenge.
	Response[S algebra.PrimeFieldElement[S]] = maurer09.Response[*constructions.FiniteDirectPowerRingElement[S]]
)

// NewWitness constructs a witness from the secret exponents (x_1, ..., x_m).
// At least one exponent must be provided.
func NewWitness[S algebra.PrimeFieldElement[S]](ws ...S) (*Witness[S], error) {
	if len(ws) == 0 {
		return nil, ErrInvalidArgument.WithMessage("at least one witness value is required")
	}
	baseRing := algebra.StructureMustBeAs[algebra.PrimeField[S]](ws[0].Structure())
	powerRing, err := constructions.NewFiniteDirectPowerRing(baseRing, uint(len(ws)))
	if err != nil {
		return nil, errs.Wrap(err).WithMessage("cannot create direct power ring")
	}
	witnessValue, err := powerRing.New(ws...)
	if err != nil {
		return nil, errs.Wrap(err).WithMessage("cannot create witness element")
	}
	return &Witness[S]{W: witnessValue}, nil
}

// NewStatement constructs a statement from individual group elements whose product
// forms the public element z = g_1 * g_2 * ... * g_m.
// For proving knowledge of a Pedersen opening, pass the commitment value directly.
func NewStatement[G algebra.PrimeGroupElement[G, S], S algebra.PrimeFieldElement[S]](g G) *Statement[G, S] {
	return &Statement[G, S]{X: g}
}

// Protocol implements Okamoto's sigma protocol for proving knowledge of a representation.
// Given generators h_1, ..., h_m and a public element z, it proves knowledge of exponents
// (x_1, ..., x_m) such that z = h_1^{x_1} * ... * h_m^{x_m}.
//
// The protocol is a special case of Maurer's framework [Maurer09] where the one-way
// homomorphism is multi-exponentiation: phi(x_1, ..., x_m) = prod(h_i^{x_i}).
type Protocol[G algebra.PrimeGroupElement[G, S], S algebra.PrimeFieldElement[S]] struct {
	maurer09.Protocol[
		G,
		*constructions.FiniteDirectPowerRingElement[S],
	]
}

// NewProtocol creates a new Okamoto protocol instance for the given generators and randomness source.
// The number of generators m determines the dimension of the representation.
func NewProtocol[G algebra.PrimeGroupElement[G, S], S algebra.PrimeFieldElement[S]](generators []G, prng io.Reader) (*Protocol[G, S], error) {
	if len(generators) == 0 {
		return nil, ErrInvalidArgument.WithMessage("at least one generator is required")
	}
	group := algebra.StructureMustBeAs[algebra.PrimeGroup[G, S]](generators[0].Structure())
	baseScalarField := algebra.StructureMustBeAs[algebra.PrimeField[S]](group.ScalarStructure())

	directSumModule, err := constructions.NewFiniteDirectSumModule(group, uint(len(generators)))
	if err != nil {
		return nil, errs.Wrap(err).WithMessage("cannot create direct sum module")
	}
	scalarDirectPowerRing, err := constructions.NewFiniteDirectPowerRing(baseScalarField, uint(len(generators)))
	if err != nil {
		return nil, errs.Wrap(err).WithMessage("cannot create direct power ring")
	}

	challengeByteLen := base.ComputationalSecurityBytesCeil // To make it non interactive, it has to be at least equal to computational security parameter.
	soundnessError := uint(challengeByteLen * 8)

	generatorsVector, err := directSumModule.New(generators...)
	if err != nil {
		return nil, errs.Wrap(err).WithMessage("cannot create direct sum module element for generators")
	}
	homomorphism := func(s *constructions.FiniteDirectPowerRingElement[S]) G {
		return generatorsVector.ScalarDiagonal(s).CoDiagonal()
	}

	l, err := num.N().FromBytes(group.Order().Bytes())
	if err != nil {
		return nil, errs.Wrap(err).WithMessage("cannot create anchor")
	}
	anc := &anchor[G, S]{l, scalarDirectPowerRing.Zero()}

	maurerProtocol, err := maurer09.NewProtocol(
		challengeByteLen,
		soundnessError,
		Name,
		group,
		scalarDirectPowerRing,
		homomorphism,
		anc,
		prng,
	)
	if err != nil {
		return nil, errs.Wrap(err)
	}

	return &Protocol[G, S]{*maurerProtocol}, nil
}

type anchor[G algebra.PrimeGroupElement[G, S], S algebra.PrimeFieldElement[S]] struct {
	l  *num.Nat
	id *constructions.FiniteDirectPowerRingElement[S]
}

func (a *anchor[G, S]) L() *num.Nat {
	return a.l
}

func (a *anchor[G, S]) PreImage(_ G) (w *constructions.FiniteDirectPowerRingElement[S]) {
	return a.id
}
