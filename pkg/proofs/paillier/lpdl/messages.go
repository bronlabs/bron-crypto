package lpdl

import (
	"github.com/cronokirby/saferith"

	"github.com/bronlabs/krypton-primitives/pkg/base/curves"
	ds "github.com/bronlabs/krypton-primitives/pkg/base/datastructures"
	"github.com/bronlabs/krypton-primitives/pkg/base/errs"
	"github.com/bronlabs/krypton-primitives/pkg/commitments"
	hashcommitments "github.com/bronlabs/krypton-primitives/pkg/commitments/hash"
	"github.com/bronlabs/krypton-primitives/pkg/indcpa/paillier"
	paillierrange "github.com/bronlabs/krypton-primitives/pkg/proofs/paillier/range"
)

type Round1Output struct {
	RangeVerifierOutput    hashcommitments.Commitment
	CPrime                 *paillier.CipherText
	CDoublePrimeCommitment hashcommitments.Commitment

	_ ds.Incomparable
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
	CHat              hashcommitments.Commitment

	_ ds.Incomparable
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
	RangeVerifierOutput *commitments.Opening[hashcommitments.Message, hashcommitments.Witness]
	A                   *saferith.Nat
	B                   *saferith.Nat
	CDoublePrimeWitness hashcommitments.Witness

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

	return nil
}

type Round4Output struct {
	RangeProverOutput *paillierrange.Response
	BigQHat           curves.Point
	BigQHatWitness    hashcommitments.Witness

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

	return nil
}
