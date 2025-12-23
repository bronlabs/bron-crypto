package lpdl

import (
	"github.com/bronlabs/bron-crypto/pkg/base/algebra"
	"github.com/bronlabs/bron-crypto/pkg/base/ct"
	"github.com/bronlabs/bron-crypto/pkg/base/curves"
	"github.com/bronlabs/bron-crypto/pkg/base/nt/num"
	"github.com/bronlabs/bron-crypto/pkg/base/utils"
	hash_comm "github.com/bronlabs/bron-crypto/pkg/commitments/hash"
	"github.com/bronlabs/bron-crypto/pkg/encryption/paillier"
	paillierrange "github.com/bronlabs/bron-crypto/pkg/proofs/paillier/range"
)

// Round1Output carries the verifier's first-round data.
type Round1Output struct {
	RangeVerifierOutput    hash_comm.Commitment
	CPrime                 *paillier.Ciphertext
	CDoublePrimeCommitment hash_comm.Commitment
}

// Validate checks the Round1Output shape.
func (r1out *Round1Output) Validate() error {
	if r1out == nil {
		return ErrInvalidArgument.WithMessage("round 1 output is nil")
	}
	if r1out.CPrime == nil {
		return ErrInvalidArgument.WithMessage("CPrime is nil")
	}

	return nil
}

// Round2Output carries the prover's second-round data.
type Round2Output struct {
	RangeProverOutput *paillierrange.Commitment
	CHat              hash_comm.Commitment
}

// Validate checks the Round2Output shape.
func (r2out *Round2Output) Validate() error {
	if r2out == nil {
		return ErrInvalidArgument.WithMessage("round 2 output is nil")
	}
	if r2out.RangeProverOutput == nil {
		return ErrInvalidArgument.WithMessage("range prover output is nil")
	}

	return nil
}

// Round3Output carries the verifier's third-round data.
type Round3Output struct {
	RangeVerifierMessage hash_comm.Message
	RangeVerifierWitness hash_comm.Witness
	A                    *num.Uint
	B                    *num.Uint
	CDoublePrimeWitness  hash_comm.Witness
}

// Validate checks the Round3Output shape.
func (r3out *Round3Output) Validate() error {
	if r3out == nil {
		return ErrInvalidArgument.WithMessage("round 3 output is nil")
	}
	if r3out.RangeVerifierMessage == nil {
		return ErrInvalidArgument.WithMessage("range verifier message")
	}
	if ct.SliceIsZero(r3out.RangeVerifierWitness[:]) == ct.True {
		return ErrInvalidArgument.WithMessage("range verifier witness is empty")
	}
	if r3out.A == nil {
		return ErrInvalidArgument.WithMessage("A is nil")
	}
	if r3out.B == nil {
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
func (r4out *Round4Output[P, B, S]) Validate() error {
	if r4out == nil {
		return ErrInvalidArgument.WithMessage("round 4 output is nil")
	}
	if r4out.RangeProverOutput == nil {
		return ErrInvalidArgument.WithMessage("range prover output is nil")
	}
	if utils.IsNil(r4out.BigQHat) {
		return ErrInvalidArgument.WithMessage("BigQHat is nil")
	}
	if r4out.BigQHat.IsOpIdentity() {
		return ErrInvalidArgument.WithMessage("BigQHat is identity")
	}

	return nil
}
