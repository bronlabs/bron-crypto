package lpdl

import (
	crand "crypto/rand"
	"crypto/sha256"
	"math/big"

	"github.com/copperexchange/knox-primitives/pkg/commitments"
	"github.com/copperexchange/knox-primitives/pkg/core/curves"
	"github.com/copperexchange/knox-primitives/pkg/core/errs"
	"github.com/copperexchange/knox-primitives/pkg/core/integration/helper_types"
	"github.com/copperexchange/knox-primitives/pkg/paillier"
	paillierrange "github.com/copperexchange/knox-primitives/pkg/proofs/paillier/range"
)

var hashFunc = sha256.New

type Round1Output struct {
	RangeVerifierOutput    *paillierrange.Round1Output
	CPrime                 paillier.CipherText
	CDoublePrimeCommitment commitments.Commitment

	_ helper_types.Incomparable
}

type Round2Output struct {
	RangeProverOutput *paillierrange.ProverRound2Output
	CHat              commitments.Commitment

	_ helper_types.Incomparable
}

type Round3Output struct {
	RangeVerifierOutput *paillierrange.VerifierRound3Output
	A                   *big.Int
	B                   *big.Int
	CDoublePrimeWitness commitments.Witness

	_ helper_types.Incomparable
}

type Round4Output struct {
	RangeProverOutput *paillierrange.Round4Output
	BigQHat           curves.Point
	BigQHatWitness    commitments.Witness

	_ helper_types.Incomparable
}

func (verifier *Verifier) Round1() (output *Round1Output, err error) {
	if verifier.round != 1 {
		return nil, errs.NewInvalidRound("%d != 1", verifier.round)
	}

	// 1. choose random a, b
	verifier.state.a, err = crand.Int(verifier.prng, verifier.state.q)
	if err != nil {
		return nil, errs.WrapFailed(err, "cannot generate random integer")
	}
	verifier.state.b, err = crand.Int(verifier.prng, verifier.state.q2)
	if err != nil {
		return nil, errs.WrapFailed(err, "cannot generate random integer")
	}

	// 1.i. compute a (*) c (+) Enc(b, r) for random r
	acEnc, err := verifier.pk.Mul(verifier.state.a, verifier.c)
	if err != nil {
		return nil, errs.WrapFailed(err, "cannot perform homomorphic multiplication")
	}
	bEnc, _, err := verifier.pk.Encrypt(verifier.state.b)
	if err != nil {
		return nil, errs.WrapFailed(err, "cannot encrypt value")
	}
	cPrime, err := verifier.pk.Add(acEnc, bEnc)
	if err != nil {
		return nil, errs.WrapFailed(err, "cannot perform homomorphic addition")
	}

	// 1.ii. compute c'' = commit(a, b)
	cDoublePrimeMessage := append(verifier.state.a.Bytes(), verifier.state.b.Bytes()...)
	cDoublePrimeCommitment, cDoublePrimeWitness, err := commitments.Commit(hashFunc, cDoublePrimeMessage)
	if err != nil {
		return nil, errs.WrapFailed(err, "cannot commit to a and b")
	}
	verifier.state.cDoublePrimeWitness = cDoublePrimeWitness

	// 1.iii. compute Q' = aQ + bQ
	aScalar, err := verifier.state.curve.Scalar().SetBigInt(verifier.state.a)
	if err != nil {
		return nil, errs.WrapFailed(err, "cannot set scalar")
	}
	bScalar, err := verifier.state.curve.Scalar().SetBigInt(verifier.state.b)
	if err != nil {
		return nil, errs.WrapFailed(err, "cannot set scalar")
	}
	verifier.state.bigQPrime = verifier.bigQ.Mul(aScalar).Add(verifier.state.curve.ScalarBaseMult(bScalar))

	// 4.i. In parallel to the above, run L_P protocol
	rangeVerifierOutput, err := verifier.rangeVerifier.Round1()
	if err != nil {
		return nil, errs.WrapFailed(err, "range verifier round 1")
	}

	// 1.iv sends c' and c'' to P
	verifier.round += 2
	return &Round1Output{
		RangeVerifierOutput:    rangeVerifierOutput,
		CPrime:                 cPrime,
		CDoublePrimeCommitment: cDoublePrimeCommitment,
	}, nil
}

func (prover *Prover) Round2(input *Round1Output) (output *Round2Output, err error) {
	if prover.round != 2 {
		return nil, errs.NewInvalidRound("%d != 2", prover.round)
	}

	prover.state.cDoublePrimeCommitment = input.CDoublePrimeCommitment

	// 2.i. decrypt c' to obtain alpha, compute Q^ = alpha * G
	prover.state.alpha, err = prover.sk.Decrypt(input.CPrime)
	if err != nil {
		return nil, errs.WrapFailed(err, "cannot decrypt cipher text")
	}
	alphaScalar, err := prover.state.curve.Scalar().SetBigInt(prover.state.alpha)
	if err != nil {
		return nil, errs.WrapFailed(err, "cannot set scalar")
	}
	prover.state.bigQHat = prover.state.curve.ScalarBaseMult(alphaScalar)

	// 2.ii. compute c^ = commit(Q^) and send to V
	bigQHatMessage := prover.state.bigQHat.ToAffineCompressed()
	bigQHatCommitment, bigQHatWitness, err := commitments.Commit(hashFunc, bigQHatMessage)
	if err != nil {
		return nil, errs.WrapFailed(err, "cannot commit to Q hat")
	}
	prover.state.bigQHatWitness = bigQHatWitness

	// 4.i. In parallel to the above, run L_P protocol
	rangeProverOutput, err := prover.rangeProver.Round2(input.RangeVerifierOutput)
	if err != nil {
		return nil, errs.WrapFailed(err, "range prover round 2")
	}

	prover.round += 2
	return &Round2Output{
		RangeProverOutput: rangeProverOutput,
		CHat:              bigQHatCommitment,
	}, nil
}

func (verifier *Verifier) Round3(input *Round2Output) (output *Round3Output, err error) {
	if verifier.round != 3 {
		return nil, errs.NewInvalidRound("%d != 3", verifier.round)
	}

	verifier.state.cHat = input.CHat

	// 4.i. In parallel to the above, run L_P protocol
	rangeVerifierOutput, err := verifier.rangeVerifier.Round3(input.RangeProverOutput)
	if err != nil {
		return nil, errs.WrapFailed(err, "range verifier round 3")
	}

	// 3. decommit c'' revealing a, b
	verifier.round += 2
	return &Round3Output{
		RangeVerifierOutput: rangeVerifierOutput,
		A:                   verifier.state.a,
		B:                   verifier.state.b,
		CDoublePrimeWitness: verifier.state.cDoublePrimeWitness,
	}, nil
}

func (prover *Prover) Round4(input *Round3Output) (output *Round4Output, err error) {
	if prover.round != 4 {
		return nil, errs.NewInvalidRound("%d != 4", prover.round)
	}

	cDoublePrimeMessage := append(input.A.Bytes(), input.B.Bytes()...)
	if err := commitments.Open(hashFunc, cDoublePrimeMessage, prover.state.cDoublePrimeCommitment, input.CDoublePrimeWitness); err != nil {
		return nil, errs.WrapFailed(err, "cannot decommit a and b")
	}

	// 4. check that alpha == ax + b (over integers), if not aborts
	alphaCheck := new(big.Int).Add(new(big.Int).Mul(input.A, prover.x.BigInt()), input.B)
	if prover.state.alpha.Cmp(alphaCheck) != 0 {
		return nil, errs.NewIdentifiableAbort("verifier", "verifier is misbehaving")
	}

	rangeProverOutput, err := prover.rangeProver.Round4(input.RangeVerifierOutput)
	if err != nil {
		return nil, errs.WrapFailed(err, "range prover round 4")
	}

	// 4. decommit c^ revealing Q^
	prover.round += 2
	return &Round4Output{
		RangeProverOutput: rangeProverOutput,
		BigQHat:           prover.state.bigQHat,
		BigQHatWitness:    prover.state.bigQHatWitness,
	}, nil
}

func (verifier *Verifier) Round5(input *Round4Output) (err error) {
	if verifier.round != 5 {
		return errs.NewInvalidRound("%d != 5", verifier.round)
	}

	bigQHatMessage := input.BigQHat.ToAffineCompressed()
	if err := commitments.Open(hashFunc, bigQHatMessage, verifier.state.cHat, input.BigQHatWitness); err != nil {
		return errs.WrapFailed(err, "cannot decommit Q hat")
	}

	// 5. accepts if and only if it accepts the range proof and Q^ == Q'
	if !input.BigQHat.Equal(verifier.state.bigQPrime) {
		return errs.NewVerificationFailed("cannot verify")
	}
	err = verifier.rangeVerifier.Round5(input.RangeProverOutput)
	if err != nil {
		return errs.WrapFailed(err, "range verifier round 5")
	}

	verifier.round += 2
	return nil
}
