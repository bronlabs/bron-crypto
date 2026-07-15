package lpdl

import (
	"github.com/bronlabs/bron-crypto/pkg/base/algebra"
	"github.com/bronlabs/bron-crypto/pkg/base/ct"
	"github.com/bronlabs/bron-crypto/pkg/base/curves"
	"github.com/bronlabs/bron-crypto/pkg/base/nt/num"
	"github.com/bronlabs/bron-crypto/pkg/base/utils"
	"github.com/bronlabs/bron-crypto/pkg/commitments/hashcom"
	"github.com/bronlabs/bron-crypto/pkg/encryption/paillier"
	"github.com/bronlabs/bron-crypto/pkg/mpc/sharing"
	"github.com/bronlabs/bron-crypto/pkg/proofs"
	paillierrange "github.com/bronlabs/bron-crypto/pkg/proofs/paillier/range"
)

// Round1Output carries the verifier's first-round data.
type Round1Output[P curves.Point[P, B, S], B algebra.FiniteFieldElement[B], S algebra.PrimeFieldElement[S]] struct {
	RangeVerifierOutput    hashcom.Commitment
	CPrime                 *paillier.Ciphertext
	CDoublePrimeCommitment hashcom.Commitment
}

// Validate checks the Round1Output shape.
func (m *Round1Output[P, B, S]) Validate(p *Prover[P, B, S], _ sharing.ID) error {
	if m == nil {
		return proofs.ErrValidationFailed.WithMessage("round 1 output is nil")
	}
	if m.RangeVerifierOutput == [hashcom.DigestSize]byte{} {
		return proofs.ErrValidationFailed.WithMessage("range verifier output is empty")
	}
	if m.CPrime == nil {
		return proofs.ErrValidationFailed.WithMessage("CPrime is nil")
	}
	if m.CDoublePrimeCommitment == [hashcom.DigestSize]byte{} {
		return proofs.ErrValidationFailed.WithMessage("CDoublePrimeCommitment is empty")
	}

	return nil
}

// Round2Output carries the prover's second-round data.
type Round2Output[P curves.Point[P, B, S], B algebra.FiniteFieldElement[B], S algebra.PrimeFieldElement[S]] struct {
	RangeProverOutput *paillierrange.Commitment
	CHat              hashcom.Commitment
}

// Validate checks the Round2Output shape.
func (m *Round2Output[P, B, S]) Validate(_ *Verifier[P, B, S], _ sharing.ID) error {
	if m == nil {
		return proofs.ErrValidationFailed.WithMessage("round 2 output is nil")
	}
	if m.RangeProverOutput == nil {
		return proofs.ErrValidationFailed.WithMessage("range prover output is nil")
	}

	return nil
}

// Round3Output carries the verifier's third-round data.
type Round3Output[P curves.Point[P, B, S], B algebra.FiniteFieldElement[B], S algebra.PrimeFieldElement[S]] struct {
	RangeVerifierMessage hashcom.Message
	RangeVerifierWitness hashcom.Witness
	A                    *num.Uint
	B                    *num.Uint
	CDoublePrimeWitness  hashcom.Witness
}

// Validate checks the Round3Output shape.
func (m *Round3Output[P, B, S]) Validate(_ *Prover[P, B, S], _ sharing.ID) error {
	if m == nil {
		return proofs.ErrValidationFailed.WithMessage("round 3 output is nil")
	}
	if m.RangeVerifierMessage == nil {
		return proofs.ErrValidationFailed.WithMessage("range verifier message")
	}
	if ct.SliceIsZero(m.RangeVerifierWitness[:]) == ct.True {
		return proofs.ErrValidationFailed.WithMessage("range verifier witness is empty")
	}
	if m.A == nil {
		return proofs.ErrValidationFailed.WithMessage("A is nil")
	}
	if m.B == nil {
		return proofs.ErrValidationFailed.WithMessage("B is nil")
	}

	return nil
}

// Round4Output carries the prover's final response.
type Round4Output[P curves.Point[P, B, S], B algebra.FiniteFieldElement[B], S algebra.PrimeFieldElement[S]] struct {
	RangeProverOutput *paillierrange.Response
	BigQHat           P
	BigQHatWitness    hashcom.Witness
}

// Validate checks the Round4Output shape.
func (m *Round4Output[P, B, S]) Validate(p *Verifier[P, B, S], _ sharing.ID) error {
	if m == nil {
		return proofs.ErrValidationFailed.WithMessage("round 4 output is nil")
	}
	if m.RangeProverOutput == nil {
		return proofs.ErrValidationFailed.WithMessage("range prover output is nil")
	}
	if utils.IsNil(m.BigQHat) {
		return proofs.ErrValidationFailed.WithMessage("BigQHat is nil")
	}
	if m.BigQHat.IsOpIdentity() {
		return proofs.ErrValidationFailed.WithMessage("BigQHat is identity")
	}

	return nil
}
