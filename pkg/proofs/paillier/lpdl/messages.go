package lpdl

import (
	"github.com/bronlabs/bron-crypto/pkg/base/algebra"
	"github.com/bronlabs/bron-crypto/pkg/base/ct"
	"github.com/bronlabs/bron-crypto/pkg/base/curves"
	"github.com/bronlabs/bron-crypto/pkg/base/errs"
	"github.com/bronlabs/bron-crypto/pkg/base/nt/num"
	"github.com/bronlabs/bron-crypto/pkg/base/utils"
	hash_comm "github.com/bronlabs/bron-crypto/pkg/commitments/hash"
	"github.com/bronlabs/bron-crypto/pkg/encryption/paillier"
	paillierrange "github.com/bronlabs/bron-crypto/pkg/proofs/paillier/range"
)

type Round1Output struct {
	RangeVerifierOutput    hash_comm.Commitment
	CPrime                 *paillier.Ciphertext
	CDoublePrimeCommitment hash_comm.Commitment
}

func (r1out *Round1Output) Validate() error {
	if r1out == nil {
		return errs.NewIsNil("round 1 output")
	}
	if r1out.CPrime == nil {
		return errs.NewIsNil("CPrime")
	}

	return nil
}

type Round2Output struct {
	RangeProverOutput *paillierrange.Commitment
	CHat              hash_comm.Commitment
}

func (r2out *Round2Output) Validate() error {
	if r2out == nil {
		return errs.NewIsNil("round 2 output")
	}
	if r2out.RangeProverOutput == nil {
		return errs.NewIsNil("range prover output")
	}

	return nil
}

type Round3Output struct {
	RangeVerifierMessage hash_comm.Message
	RangeVerifierWitness hash_comm.Witness
	A                    *num.Uint
	B                    *num.Uint
	CDoublePrimeWitness  hash_comm.Witness
}

func (r3out *Round3Output) Validate() error {
	if r3out == nil {
		return errs.NewIsNil("round 3 output")
	}
	if r3out.RangeVerifierMessage == nil {
		return errs.NewIsNil("range verifier message")
	}
	if ct.SliceIsZero(r3out.RangeVerifierWitness[:]) == ct.True {
		return errs.NewIsNil("range verifier witness")
	}
	if r3out.A == nil {
		return errs.NewIsNil("A")
	}
	if r3out.B == nil {
		return errs.NewIsNil("B")
	}

	return nil
}

type Round4Output[P curves.Point[P, B, S], B algebra.FiniteFieldElement[B], S algebra.PrimeFieldElement[S]] struct {
	RangeProverOutput *paillierrange.Response
	BigQHat           P
	BigQHatWitness    hash_comm.Witness
}

func (r4out *Round4Output[P, B, S]) Validate() error {
	if r4out == nil {
		return errs.NewIsNil("round 4 output")
	}
	if r4out.RangeProverOutput == nil {
		return errs.NewIsNil("range prover output")
	}
	if utils.IsNil(r4out.BigQHat) {
		return errs.NewIsNil("BigQHat")
	}
	if r4out.BigQHat.IsOpIdentity() {
		return errs.NewArgument("BigQHat is identity")
	}

	return nil
}
