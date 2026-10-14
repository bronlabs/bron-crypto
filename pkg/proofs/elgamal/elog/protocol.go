package elog

import (
	"io"

	"github.com/bronlabs/errs-go/errs"

	"github.com/bronlabs/bron-crypto/pkg/base"
	"github.com/bronlabs/bron-crypto/pkg/base/algebra"
	"github.com/bronlabs/bron-crypto/pkg/base/algebra/constructions"
	"github.com/bronlabs/bron-crypto/pkg/base/nt/num"
	"github.com/bronlabs/bron-crypto/pkg/base/utils"
	"github.com/bronlabs/bron-crypto/pkg/commitments/indcpacom"
	"github.com/bronlabs/bron-crypto/pkg/encryption/elgamal"
	"github.com/bronlabs/bron-crypto/pkg/proofs"
	"github.com/bronlabs/bron-crypto/pkg/proofs/internal/meta/maurer09"
	"github.com/bronlabs/bron-crypto/pkg/proofs/sigma"
)

// Name identifies the elog sigma protocol.
const Name sigma.Name = "PROOF_OF_KNOWLEDGE_OF_DISCRETE_LOGARITHM_OF_ELGAMAL_COMMITMENT"

const (
	// witnessArity is the dimension of the witness vector (y, lambda).
	witnessArity = 2
	// statementArity is the dimension of the statement vector (L, M, Y).
	statementArity = 3
	// ciphertextArity is the dimension of an ElGamal ciphertext (L, M).
	ciphertextArity = 2
)

type (
	// Witness is the elog witness (y, lambda) in F_q x F_q: the discrete
	// logarithm y and the ElGamal commitment nonce lambda. It is secret.
	Witness[S algebra.PrimeFieldElement[S]] = maurer09.Witness[*constructions.FiniteDirectPowerRingElement[S]]
	// Statement is the elog statement (L, M, Y) in G x G x G: the ElGamal
	// commitment (L, M) = (g^lambda, g^y * X^lambda) and the public element
	// Y = h^y.
	Statement[G algebra.PrimeGroupElement[G, S], S algebra.PrimeFieldElement[S]] = maurer09.Statement[*constructions.FiniteDirectPowerModuleElement[G, S]]
	// State holds the prover's mask (m, alpha) in F_q x F_q during a run.
	State[S algebra.PrimeFieldElement[S]] = maurer09.State[*constructions.FiniteDirectPowerRingElement[S]]
	// Commitment is the prover's first message (A, N, B) in G x G x G.
	Commitment[G algebra.PrimeGroupElement[G, S], S algebra.PrimeFieldElement[S]] = maurer09.Commitment[*constructions.FiniteDirectPowerModuleElement[G, S]]
	// Response is the prover's reply (u, z) = (m + e*y, alpha + e*lambda) in
	// F_q x F_q.
	Response[S algebra.PrimeFieldElement[S]] = maurer09.Response[*constructions.FiniteDirectPowerRingElement[S]]
)

// NewWitness constructs an elog witness from the discrete logarithm y and the
// nonce lambda used to produce the ElGamal commitment (L, M) to g^y.
func NewWitness[S algebra.PrimeFieldElement[S]](y S, nonce *indcpacom.Witness[*elgamal.Nonce[S]]) (*Witness[S], error) {
	if utils.IsNil(y) || nonce == nil || nonce.Value() == nil || utils.IsNil(nonce.Value().Value()) {
		return nil, proofs.ErrInvalidArgument.WithMessage("witness values cannot be nil")
	}
	scalarField := algebra.StructureMustBeAs[algebra.PrimeField[S]](y.Structure())
	powerRing, err := constructions.NewFiniteDirectPowerRing(scalarField, witnessArity)
	if err != nil {
		return nil, errs.Wrap(err).WithMessage("cannot create direct power ring")
	}
	witnessValue, err := powerRing.New(y, nonce.Value().Value())
	if err != nil {
		return nil, errs.Wrap(err).WithMessage("cannot create witness element")
	}
	return &Witness[S]{W: witnessValue}, nil
}

// NewStatement constructs an elog statement (L, M, Y) from the ElGamal
// commitment (L, M) and the public element Y. The commitment may come from an
// untrusted party, so its shape is validated here.
func NewStatement[G algebra.PrimeGroupElement[G, S], S algebra.PrimeFieldElement[S]](commitment *indcpacom.Commitment[*elgamal.Ciphertext[G, S]], bigY G) (*Statement[G, S], error) {
	if commitment == nil || commitment.Value() == nil || utils.IsNil(commitment.Value().Value()) || utils.IsNil(bigY) {
		return nil, proofs.ErrInvalidArgument.WithMessage("statement values cannot be nil")
	}
	lm := commitment.Value().Value().Components()
	if len(lm) != ciphertextArity {
		return nil, proofs.ErrInvalidArgument.WithMessage("ElGamal commitment must have %d components, got %d", ciphertextArity, len(lm))
	}
	group := algebra.StructureMustBeAs[algebra.PrimeGroup[G, S]](bigY.Structure())
	imageGroup, err := constructions.NewFiniteDirectPowerModule(group, statementArity)
	if err != nil {
		return nil, errs.Wrap(err).WithMessage("cannot create image group")
	}
	statementValue, err := imageGroup.New(lm[0], lm[1], bigY)
	if err != nil {
		return nil, errs.Wrap(err).WithMessage("cannot create statement element")
	}
	return &Statement[G, S]{X: statementValue}, nil
}

// Protocol is the elog sigma protocol, a Maurer instance whose homomorphism
// maps (y, lambda) in F_q x F_q to (g^lambda, g^y * X^lambda, h^y) in
// G x G x G. Because the verifier checks phi applied to the single shared
// witness, the committed value g^y and the discrete logarithm of Y are bound
// by verification itself, not by prover-side witness construction.
type Protocol[G algebra.PrimeGroupElement[G, S], S algebra.PrimeFieldElement[S]] struct {
	*maurer09.Protocol[
		*constructions.FiniteDirectPowerModuleElement[G, S],
		*constructions.FiniteDirectPowerRingElement[S],
	]
}

// NewProtocol constructs the elog protocol for the given prime-order group,
// ElGamal commitment key bigX, and second base h. The commitment (L, M) inside
// the homomorphism is computed with bigX itself, so the proof is bound to the
// same encoding the committer uses. h must not be the identity, otherwise
// Y = h^y carries no information about y.
func NewProtocol[EK elgamal.EncryptionKey[EK, G, S], G algebra.PrimeGroupElement[G, S], S algebra.PrimeFieldElement[S]](
	group algebra.PrimeGroup[G, S],
	bigX *indcpacom.CommitmentKey[EK, *elgamal.Plaintext[G, S], *elgamal.Nonce[S], *elgamal.Ciphertext[G, S]],
	h G,
	prng io.Reader,
) (*Protocol[G, S], error) {
	if group == nil || bigX == nil || utils.IsNil(h) || prng == nil {
		return nil, proofs.ErrInvalidArgument.WithMessage("group, commitment key, h, and prng cannot be nil")
	}
	if h.IsOpIdentity() {
		return nil, proofs.ErrInvalidArgument.WithMessage("h cannot be the identity element")
	}
	scalarField := algebra.StructureMustBeAs[algebra.PrimeField[S]](group.ScalarStructure())

	preImageGroup, err := constructions.NewFiniteDirectPowerRing(scalarField, witnessArity)
	if err != nil {
		return nil, errs.Wrap(err).WithMessage("cannot create pre-image group")
	}

	imageGroup, err := constructions.NewFiniteDirectPowerModule(group, statementArity)
	if err != nil {
		return nil, errs.Wrap(err).WithMessage("cannot create image group")
	}

	homomorphism := func(w *constructions.FiniteDirectPowerRingElement[S]) (*constructions.FiniteDirectPowerModuleElement[G, S], error) {
		if w == nil {
			return nil, proofs.ErrInvalidArgument.WithMessage("homomorphism input cannot be nil")
		}
		// The response is deserialised from the prover, so its shape cannot be
		// trusted.
		ws := w.Components()
		if len(ws) != witnessArity {
			return nil, proofs.ErrInvalidArgument.WithMessage("homomorphism input must have %d components, got %d", witnessArity, len(ws))
		}
		y, lambda := ws[0], ws[1]
		nonce, err := elgamal.NewNonce(lambda)
		if err != nil {
			return nil, errs.Wrap(err).WithMessage("failed to create nonce from homomorphism input")
		}
		witness, err := indcpacom.NewWitness(nonce)
		if err != nil {
			return nil, errs.Wrap(err).WithMessage("failed to create commitment witness from homomorphism input")
		}
		plaintext, err := elgamal.NewPlaintext(group.ScalarBaseOp(y))
		if err != nil {
			return nil, errs.Wrap(err).WithMessage("failed to create plaintext from homomorphism input")
		}
		message, err := indcpacom.NewMessage(plaintext)
		if err != nil {
			return nil, errs.Wrap(err).WithMessage("failed to create commitment message from homomorphism input")
		}
		commitment, err := bigX.CommitWithWitness(message, witness)
		if err != nil {
			return nil, errs.Wrap(err).WithMessage("failed to compute commitment from homomorphism input")
		}
		lm := commitment.Value().Value().Components()
		if len(lm) != ciphertextArity {
			return nil, proofs.ErrFailed.WithMessage("BUG: ElGamal commitment must have %d components, got %d", ciphertextArity, len(lm))
		}
		out, err := imageGroup.New(lm[0], lm[1], h.ScalarOp(y))
		if err != nil {
			return nil, errs.Wrap(err).WithMessage("failed to create homomorphism output")
		}
		return out, nil
	}

	challengeByteLen := base.ComputationalSecurityBytesCeil
	soundnessError := uint(challengeByteLen * 8)

	l, err := num.N().FromBytes(group.Order().Bytes())
	if err != nil {
		return nil, errs.Wrap(err).WithMessage("cannot create anchor")
	}
	anc := &anchor[G, S]{l, preImageGroup.Zero()}

	maurerProtocol, err := maurer09.NewProtocol(
		challengeByteLen,
		soundnessError,
		Name,
		imageGroup,
		preImageGroup,
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

func (a *anchor[G, S]) PreImage(_ *constructions.FiniteDirectPowerModuleElement[G, S]) (w *constructions.FiniteDirectPowerRingElement[S]) {
	return a.id
}

func _[G algebra.PrimeGroupElement[G, S], S algebra.PrimeFieldElement[S]](proto *Protocol[G, S]) {
	var _ sigma.MaurerProtocol[
		*constructions.FiniteDirectPowerModuleElement[G, S],
		*constructions.FiniteDirectPowerRingElement[S],
		*Statement[G, S], *Witness[S], *Commitment[G, S], *State[S], *Response[S],
	] = proto
}
