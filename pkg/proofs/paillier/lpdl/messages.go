package lpdl

import (
	"github.com/bronlabs/bron-crypto/pkg/base/algebra"
	"github.com/bronlabs/bron-crypto/pkg/base/ct"
	"github.com/bronlabs/bron-crypto/pkg/base/curves"
	"github.com/bronlabs/bron-crypto/pkg/base/nt/num"
	"github.com/bronlabs/bron-crypto/pkg/base/utils"
	hash_comm "github.com/bronlabs/bron-crypto/pkg/commitments/hash"
	"github.com/bronlabs/bron-crypto/pkg/encryption/paillier"
	"github.com/bronlabs/bron-crypto/pkg/mpc/sharing"
	paillierrange "github.com/bronlabs/bron-crypto/pkg/proofs/paillier/range"
)

// Round1Output carries the verifier's first-round data.
type Round1Output[P curves.Point[P, B, S], B algebra.FiniteFieldElement[B], S algebra.PrimeFieldElement[S]] struct {
	RangeVerifierOutput    hash_comm.Commitment
	CPrime                 *paillier.Ciphertext
	CDoublePrimeCommitment hash_comm.Commitment
}

// Validate checks the Round1Output shape.
func (m *Round1Output[P, B, S]) Validate(p *Prover[P, B, S], _ sharing.ID) error {
	if m == nil {
		return ErrInvalidArgument.WithMessage("round 1 output is nil")
	}
	if m.RangeVerifierOutput == [hash_comm.DigestSize]byte{} {
		return ErrInvalid.WithMessage("range verifier output is empty")
	}
	if m.CPrime == nil {
		return ErrInvalidArgument.WithMessage("CPrime is nil")
	}
	if m.CDoublePrimeCommitment == [hash_comm.DigestSize]byte{} {
		return ErrInvalid.WithMessage("CDoublePrimeCommitment is empty")
	}

	return nil
}

// Round2Output carries the prover's second-round data.
type Round2Output[P curves.Point[P, B, S], B algebra.FiniteFieldElement[B], S algebra.PrimeFieldElement[S]] struct {
	RangeProverOutput *paillierrange.Commitment
	CHat              hash_comm.Commitment
}

// Validate checks the Round2Output shape.
func (m *Round2Output[P, B, S]) Validate(_ *Verifier[P, B, S], _ sharing.ID) error {
	if m == nil {
		return ErrInvalidArgument.WithMessage("round 2 output is nil")
	}
	if m.RangeProverOutput == nil {
		return ErrInvalidArgument.WithMessage("range prover output is nil")
	}

	return nil
}

// Round3Output carries the verifier's third-round data.
type Round3Output[P curves.Point[P, B, S], B algebra.FiniteFieldElement[B], S algebra.PrimeFieldElement[S]] struct {
	RangeVerifierMessage hash_comm.Message
	RangeVerifierWitness hash_comm.Witness
	A                    *num.Uint
	B                    *num.Uint
	CDoublePrimeWitness  hash_comm.Witness
}

// Validate checks the Round3Output shape.
func (m *Round3Output[P, B, S]) Validate(_ *Prover[P, B, S], _ sharing.ID) error {
	if m == nil {
		return ErrInvalidArgument.WithMessage("round 3 output is nil")
	}
	if m.RangeVerifierMessage == nil {
		return ErrInvalidArgument.WithMessage("range verifier message")
	}
	if ct.SliceIsZero(m.RangeVerifierWitness[:]) == ct.True {
		return ErrInvalidArgument.WithMessage("range verifier witness is empty")
	}
	if m.A == nil {
		return ErrInvalidArgument.WithMessage("A is nil")
	}
	if m.B == nil {
		return ErrInvalidArgument.WithMessage("B is nil")
	}

	return nil
}

// Round4Output carries the prover's final response.
type Round4Output[P curves.Point[P, B, S], B algebra.FiniteFieldElement[B], S algebra.PrimeFieldElement[S]] struct {
	RangeProverOutput *paillierrange.Response
	BigQHat           P
	BigQHatWitness    hash_comm.Witness
}

// Validate checks the Round4Output shape.
func (m *Round4Output[P, B, S]) Validate(p *Verifier[P, B, S], _ sharing.ID) error {
	if m == nil {
		return ErrInvalidArgument.WithMessage("round 4 output is nil")
	}
	if m.RangeProverOutput == nil {
		return ErrInvalidArgument.WithMessage("range prover output is nil")
	}
	if utils.IsNil(m.BigQHat) {
		return ErrInvalidArgument.WithMessage("BigQHat is nil")
	}
	if m.BigQHat.IsOpIdentity() {
		return ErrInvalidArgument.WithMessage("BigQHat is identity")
	}

	return nil
}
