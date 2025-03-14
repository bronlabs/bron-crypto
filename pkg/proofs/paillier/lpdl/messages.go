package lpdl

import (
	"github.com/cronokirby/saferith"

	"github.com/bronlabs/bron-crypto/pkg/base/curves"
	ds "github.com/bronlabs/bron-crypto/pkg/base/datastructures"
	"github.com/bronlabs/bron-crypto/pkg/base/errs"
	hashcommitments "github.com/bronlabs/bron-crypto/pkg/commitments/hash"
	"github.com/bronlabs/bron-crypto/pkg/encryptions/paillier"
	paillierrange "github.com/bronlabs/bron-crypto/pkg/proofs/paillier/range"
)

type Round1Output struct {
	RangeVerifierOutput    *paillierrange.Round1Output
	CPrime                 *paillier.CipherText
	CDoublePrimeCommitment *hashcommitments.Commitment

	_ ds.Incomparable
}

func (r1out *Round1Output) Validate() error {
	if r1out == nil {
		return errs.NewIsNil("round 1 output")
	}
	if r1out.RangeVerifierOutput == nil {
		return errs.NewIsNil("range verifier output")
	}
	if r1out.CPrime == nil {
		return errs.NewIsNil("CPrime")
	}
	if err := r1out.CDoublePrimeCommitment.Validate(); err != nil {
		return errs.WrapValidation(err, "invalid CDoublePrime commitment")
	}
	return nil
}

type Round2Output struct {
	RangeProverOutput *paillierrange.Round2Output
	CHat              *hashcommitments.Commitment

	_ ds.Incomparable
}

func (r2out *Round2Output) Validate() error {
	if r2out == nil {
		return errs.NewIsNil("round 2 output")
	}
	if r2out.RangeProverOutput == nil {
		return errs.NewIsNil("range prover output")
	}
	if err := r2out.CHat.Validate(); err != nil {
		return errs.WrapValidation(err, "invalid CHat commitment")
	}
	return nil
}

type Round3Output struct {
	RangeVerifierOutput *paillierrange.Round3Output
	A                   *saferith.Nat
	B                   *saferith.Nat
	CDoublePrimeOpening *hashcommitments.Opening

	_ ds.Incomparable
}

func (r3out *Round3Output) Validate() error {
	if r3out == nil {
		return errs.NewIsNil("round 3 output")
	}
	if r3out.RangeVerifierOutput == nil {
		return errs.NewIsNil("range verifier output")
	}
	if r3out.A == nil {
		return errs.NewIsNil("A")
	}
	if r3out.B == nil {
		return errs.NewIsNil("B")
	}
	if err := r3out.CDoublePrimeOpening.Validate(); err != nil {
		return errs.WrapValidation(err, "invalid CDoublePrime witness")
	}
	return nil
}

type Round4Output struct {
	RangeProverOutput *paillierrange.Round4Output
	BigQHat           curves.Point
	BigQHatOpening    *hashcommitments.Opening

	_ ds.Incomparable
}

func (r4out *Round4Output) Validate() error {
	if r4out == nil {
		return errs.NewIsNil("round 4 output")
	}
	if r4out.RangeProverOutput == nil {
		return errs.NewIsNil("range prover output")
	}
	if r4out.BigQHat == nil {
		return errs.NewIsNil("BigQHat")
	}
	if r4out.BigQHat.IsAdditiveIdentity() {
		return errs.NewArgument("BigQHat is identity")
	}
	if err := r4out.BigQHatOpening.Validate(); err != nil {
		return errs.WrapValidation(err, "invalid BigQHat witness")
	}
	return nil
}
