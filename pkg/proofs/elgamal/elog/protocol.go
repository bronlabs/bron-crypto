package elog

import (
	"io"

	"github.com/bronlabs/errs-go/errs"

	"github.com/bronlabs/bron-crypto/pkg/base"
	"github.com/bronlabs/bron-crypto/pkg/base/algebra"
	"github.com/bronlabs/bron-crypto/pkg/base/algebra/constructions"
	"github.com/bronlabs/bron-crypto/pkg/base/nt/num"
	"github.com/bronlabs/bron-crypto/pkg/base/utils"
	"github.com/bronlabs/bron-crypto/pkg/encryption/elgamal"
	"github.com/bronlabs/bron-crypto/pkg/proofs/internal/meta/maurer09"
	"github.com/bronlabs/bron-crypto/pkg/proofs/sigma"
)

// Name identifies the elog sigma protocol.
const Name sigma.Name = "PROOF_OF_KNOWLEDGE_DISCRETE_LOGARITHM_OF_ELGAMAL_COMMITMENT"

type (
	// Witness holds the secret scalars (lambda, y) where lambda is the ElGamal
	// encryption randomness and y is the committed discrete logarithm.
	Witness[S algebra.PrimeFieldElement[S]] = maurer09.Witness[*constructions.FiniteDirectPowerRingElement[S]]

	// Statement holds the public triple (L, M, Y) where L = g^lambda,
	// M = g^y * X^lambda (ElGamal ciphertext components), and Y = h^y.
	Statement[G algebra.PrimeGroupElement[G, S], S algebra.PrimeFieldElement[S]] = maurer09.Statement[*constructions.FiniteDirectPowerGroupElement[G]]

	// State holds the prover's ephemeral randomness during the protocol execution.
	State[S algebra.PrimeFieldElement[S]] = maurer09.State[*constructions.FiniteDirectPowerRingElement[S]]

	// Commitment is the first-round message (A, N, B) sent by the prover.
	Commitment[G algebra.PrimeGroupElement[G, S], S algebra.PrimeFieldElement[S]] = maurer09.Commitment[*constructions.FiniteDirectPowerGroupElement[G]]

	// Response is the prover's answer (z, u) to the verifier's challenge.
	Response[S algebra.PrimeFieldElement[S]] = maurer09.Response[*constructions.FiniteDirectPowerRingElement[S]]
)

// NewWitness constructs a witness from the ElGamal randomness lambda and the
// secret exponent y.
func NewWitness[S algebra.PrimeFieldElement[S]](lambda *elgamal.Nonce[S], y S) (*Witness[S], error) {
	if lambda == nil || utils.IsNil(y) {
		return nil, ErrInvalidArgument.WithMessage("witness values cannot be nil")
	}
	baseRing := algebra.StructureMustBeAs[algebra.PrimeField[S]](lambda.Value().Structure())
	powerRing, err := constructions.NewFiniteDirectPowerRing(baseRing, 2)
	if err != nil {
		return nil, errs.Wrap(err).WithMessage("cannot create direct power ring")
	}
	witnessValue, err := powerRing.New(lambda.Value(), y)
	if err != nil {
		return nil, errs.Wrap(err).WithMessage("cannot create witness element")
	}
	return &Witness[S]{W: witnessValue}, nil
}

// NewStatement constructs a statement from the three public group elements:
//   - bigL = g^lambda (first ElGamal ciphertext component)
//   - bigM = g^y * X^lambda (second ElGamal ciphertext component)
//   - bigY = h^y (commitment under the second generator h)
func NewStatement[G algebra.PrimeGroupElement[G, S], S algebra.PrimeFieldElement[S]](bigL, bigM, bigY G) (*Statement[G, S], error) {
	if utils.IsNil(bigL) || utils.IsNil(bigM) || utils.IsNil(bigY) {
		return nil, ErrInvalidArgument.WithMessage("statement values cannot be nil")
	}
	baseGroup := algebra.StructureMustBeAs[algebra.PrimeGroup[G, S]](bigL.Structure())
	powerGroup, err := constructions.NewFiniteDirectPowerGroup(baseGroup, 3)
	if err != nil {
		return nil, errs.Wrap(err).WithMessage("cannot create direct power group")
	}
	statementValue, err := powerGroup.New(bigL, bigM, bigY)
	if err != nil {
		return nil, errs.Wrap(err).WithMessage("cannot create statement element")
	}
	return &Statement[G, S]{X: statementValue}, nil
}

// Protocol implements the elog sigma protocol (Figure 23 of Canetti et al.,
// ePrint 2021/060) for proving knowledge of (lambda, y) such that an ElGamal
// ciphertext (L, M) = (g^lambda, g^y * X^lambda) encrypts g^y and Y = h^y
// commits to y under a second generator h.
//
// The one-way homomorphism is:
//
//	phi(lambda, y) = (g^lambda, g^y * X^lambda, h^y)
//
// Public parameters are the group generator g, a public key X, and a second
// generator h (independent of g).
type Protocol[G algebra.PrimeGroupElement[G, S], S algebra.PrimeFieldElement[S]] struct {
	*maurer09.Protocol[
		*constructions.FiniteDirectPowerGroupElement[G],
		*constructions.FiniteDirectPowerRingElement[S],
	]
}

// NewProtocol creates a new elog protocol instance.
//
// Parameters:
//   - group: the prime-order group G with generator g
//   - bigX: ElGamal public key X
//   - h: second generator (independent of g), used for the Y = h^y component
//   - prng: randomness source
func NewProtocol[G algebra.PrimeGroupElement[G, S], S algebra.PrimeFieldElement[S]](group algebra.PrimeGroup[G, S], bigX *elgamal.PublicKey[G, S], h G, prng io.Reader) (*Protocol[G, S], error) {
	if group == nil || bigX == nil || utils.IsNil(h) || prng == nil {
		return nil, ErrInvalidArgument.WithMessage("nil argument")
	}

	g := group.Generator()
	identity := group.OpIdentity()
	baseScalarField := algebra.StructureMustBeAs[algebra.PrimeField[S]](group.ScalarStructure())

	// Pre-image group: Z_q^2 for witness (lambda, y).
	scalarPowerRing, err := constructions.NewFiniteDirectPowerRing(baseScalarField, 2)
	if err != nil {
		return nil, errs.Wrap(err).WithMessage("cannot create scalar power ring")
	}

	// Image group: G^3 for statement (L, M, Y).
	powerGroup, err := constructions.NewFiniteDirectPowerGroup(group, 3)
	if err != nil {
		return nil, errs.Wrap(err).WithMessage("cannot create power group")
	}

	// Build the generator rows for the homomorphism matrix:
	//
	//   | g    id |   | lambda |     | g^lambda              |   | L |
	//   | X    g  | * |   y    |  =  | g^y * X^lambda        | = | M |
	//   | id   h  |   |        |     | h^y                   |   | Y |
	//
	// Each row is a direct-sum module element of arity 2. ScalarDiagonal
	// with the witness (lambda, y) and CoDiagonal produces the row's output.
	directSum, err := constructions.NewFiniteDirectPowerModule(group, 2)
	if err != nil {
		return nil, errs.Wrap(err).WithMessage("cannot create direct sum module")
	}
	row1, err := directSum.New(g, identity)
	if err != nil {
		return nil, errs.Wrap(err).WithMessage("cannot create generator row 1")
	}
	row2, err := directSum.New(bigX.Value(), g)
	if err != nil {
		return nil, errs.Wrap(err).WithMessage("cannot create generator row 2")
	}
	row3, err := directSum.New(identity, h)
	if err != nil {
		return nil, errs.Wrap(err).WithMessage("cannot create generator row 3")
	}

	homomorphism := func(w *constructions.FiniteDirectPowerRingElement[S]) (*constructions.FiniteDirectPowerGroupElement[G], error) {
		// (x, y) * s ==> scalar multiply
		// (x, y) * (s1, s2) == (s1 x , s2 y) ==> scalar diagonal
		x1 := row1.ScalarDiagonal(w).CoDiagonal()
		x2 := row2.ScalarDiagonal(w).CoDiagonal()
		x3 := row3.ScalarDiagonal(w).CoDiagonal()
		result, err := powerGroup.New(x1, x2, x3)
		if err != nil {
			return nil, errs.Wrap(err).WithMessage("cannot create homomorphism output")
		}
		return result, nil
	}

	challengeByteLen := base.ComputationalSecurityBytesCeil
	soundnessError := uint(challengeByteLen * 8)

	l, err := num.N().FromBytes(group.Order().Bytes())
	if err != nil {
		return nil, errs.Wrap(err).WithMessage("cannot create anchor")
	}
	anc := &anchor[G, S]{l, scalarPowerRing.Zero()}

	maurerProtocol, err := maurer09.NewProtocol(
		challengeByteLen,
		soundnessError,
		Name,
		powerGroup,
		scalarPowerRing,
		homomorphism,
		anc,
		prng,
	)
	if err != nil {
		return nil, errs.Wrap(err)
	}

	return &Protocol[G, S]{maurerProtocol}, nil
}

type anchor[G algebra.PrimeGroupElement[G, S], S algebra.PrimeFieldElement[S]] struct {
	l  *num.Nat
	id *constructions.FiniteDirectPowerRingElement[S]
}

func (a *anchor[G, S]) L() *num.Nat {
	return a.l
}

func (a *anchor[G, S]) PreImage(_ *constructions.FiniteDirectPowerGroupElement[G]) (w *constructions.FiniteDirectPowerRingElement[S]) {
	return a.id
}
