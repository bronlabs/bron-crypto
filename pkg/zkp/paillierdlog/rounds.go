package paillierdlog

import (
	crand "crypto/rand"
	"crypto/sha256"
	"github.com/copperexchange/crypto-primitives-go/pkg/commitments"
	"github.com/copperexchange/crypto-primitives-go/pkg/core/curves"
	"github.com/copperexchange/crypto-primitives-go/pkg/core/errs"
	"github.com/copperexchange/crypto-primitives-go/pkg/paillier"
	"github.com/copperexchange/crypto-primitives-go/pkg/zkp/paillierrange"
	"math/big"
)

var (
	hashFunc = sha256.New
)

type VerifierRound1Output struct {
	rangeVerifierOutput    *paillierrange.VerifierRound1Output
	cPrime                 paillier.CipherText
	cDoublePrimeCommitment commitments.Commitment
}

type ProverRound2Output struct {
	rangeProverOutput *paillierrange.ProverRound2Output
	cHat              commitments.Commitment
}

type VerifierRound3Output struct {
	rangeVerifierOutput *paillierrange.VerifierRound3Output
	a                   *big.Int
	b                   *big.Int
	cDoublePrimeWitness commitments.Witness
}

type ProverRound4Output struct {
	rangeProverOutput *paillierrange.ProverRound4Output
	bigQHat           curves.Point
	bigQHatWitness    commitments.Witness
}

func (verifier *Verifier) Round1() (output *VerifierRound1Output, err error) {
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

	// 1.a. compute a (*) c (+) Enc(b, r) for random r
	acEnc, err := verifier.pk.Mul(verifier.state.a, verifier.c)
	if err != nil {
		return nil, errs.WrapFailed(err, "cannot perform homomorphic multiplication")
	}
	bEnc, _, err := verifier.pk.Encrypt(verifier.state.b)
	if err != nil {
		return nil, errs.WrapFailed(err, "cannot encrypt value")
	}
	cPrime, err := verifier.pk.Add(acEnc, bEnc)

	// 1.b. compute c'' = commit(a, b)
	cDoublePrimeMessage := append(verifier.state.a.Bytes()[:], verifier.state.b.Bytes()...)
	cDoublePrimeCommitment, cDoublePrimeWitness, err := commitments.Commit(hashFunc, cDoublePrimeMessage)
	if err != nil {
		return nil, errs.WrapFailed(err, "cannot commit to a and b")
	}
	verifier.state.cDoublePrimeWitness = cDoublePrimeWitness

	// 1.c. compute Q' = aQ + bQ
	aScalar, err := verifier.state.curve.NewScalar().SetBigInt(verifier.state.a)
	if err != nil {
		return nil, errs.WrapFailed(err, "cannot set scalar")
	}
	bScalar, err := verifier.state.curve.NewScalar().SetBigInt(verifier.state.b)
	if err != nil {
		return nil, errs.WrapFailed(err, "cannot set scalar")
	}
	verifier.state.bigQPrime = verifier.bigQ.Mul(aScalar).Add(verifier.state.curve.ScalarBaseMult(bScalar))

	// 4.a. In parallel to the above, run L_P protocol
	rangeVerifierOutput, err := verifier.rangeVerifier.Round1()
	if err != nil {
		return nil, err
	}

	verifier.round += 2
	return &VerifierRound1Output{
		rangeVerifierOutput:    rangeVerifierOutput,
		cPrime:                 cPrime,
		cDoublePrimeCommitment: cDoublePrimeCommitment,
	}, nil
}

func (prover *Prover) Round2(input *VerifierRound1Output) (output *ProverRound2Output, err error) {
	if prover.round != 2 {
		return nil, errs.NewInvalidRound("%d != 2", prover.round)
	}

	prover.state.cDoublePrimeCommitment = input.cDoublePrimeCommitment

	// 2.a. decrypt c' to obtain alpha, compute Q^ = alpha * G
	prover.state.alpha, err = prover.sk.Decrypt(input.cPrime)
	if err != nil {
		return nil, errs.WrapFailed(err, "cannot decrypt cipher text")
	}
	alphaScalar, err := prover.state.curve.NewScalar().SetBigInt(prover.state.alpha)
	if err != nil {
		return nil, errs.WrapFailed(err, "cannot set scalar")
	}
	prover.state.bigQHat = prover.state.curve.ScalarBaseMult(alphaScalar)

	// 2.b. compute c^ = commit(Q^) and send to V
	bigQHatMessage := prover.state.bigQHat.ToAffineCompressed()
	bigQHatCommitment, bigQHatWitness, err := commitments.Commit(hashFunc, bigQHatMessage)
	if err != nil {
		return nil, errs.WrapFailed(err, "cannot commit to Q hat")
	}
	prover.state.bigQHatWitness = bigQHatWitness

	// 4.a. In parallel to the above, run L_P protocol
	rangeProverOutput, err := prover.rangeProver.Round2(input.rangeVerifierOutput)
	if err != nil {
		return nil, err
	}

	prover.round += 2
	return &ProverRound2Output{
		rangeProverOutput: rangeProverOutput,
		cHat:              bigQHatCommitment,
	}, nil
}

func (verifier *Verifier) Round3(input *ProverRound2Output) (output *VerifierRound3Output, err error) {
	if verifier.round != 3 {
		return nil, errs.NewInvalidRound("%d != 3", verifier.round)
	}

	verifier.state.cHat = input.cHat

	// 4.a. In parallel to the above, run L_P protocol
	rangeVerifierOutput, err := verifier.rangeVerifier.Round3(input.rangeProverOutput)
	if err != nil {
		return nil, err
	}

	// 3. decommit c'' revealing a, b
	verifier.round += 2
	return &VerifierRound3Output{
		rangeVerifierOutput: rangeVerifierOutput,
		a:                   verifier.state.a,
		b:                   verifier.state.b,
		cDoublePrimeWitness: verifier.state.cDoublePrimeWitness,
	}, nil
}

func (prover *Prover) Round4(input *VerifierRound3Output) (output *ProverRound4Output, err error) {
	if prover.round != 4 {
		return nil, errs.NewInvalidRound("%d != 4", prover.round)
	}

	cDoublePrimeMessage := append(input.a.Bytes()[:], input.b.Bytes()...)
	if err := commitments.Open(hashFunc, cDoublePrimeMessage, prover.state.cDoublePrimeCommitment, input.cDoublePrimeWitness); err != nil {
		return nil, errs.WrapFailed(err, "cannot decommit a and b")
	}

	// 4. check that alpha == ax + b (over integers), if not aborts
	alphaCheck := new(big.Int).Add(new(big.Int).Mul(input.a, prover.x.BigInt()), input.b)
	if prover.state.alpha.Cmp(alphaCheck) != 0 {
		return nil, errs.NewIdentifiableAbort("verifier is misbehaving")
	}

	rangeProverOutput, err := prover.rangeProver.Round4(input.rangeVerifierOutput)
	if err != nil {
		return nil, err
	}

	// 4. decommit c^ revealing Q^
	prover.round += 2
	return &ProverRound4Output{
		rangeProverOutput: rangeProverOutput,
		bigQHat:           prover.state.bigQHat,
		bigQHatWitness:    prover.state.bigQHatWitness,
	}, nil
}

func (verifier *Verifier) Round5(input *ProverRound4Output) (err error) {
	if verifier.round != 5 {
		return errs.NewInvalidRound("%d != 5", verifier.round)
	}

	bigQHatMessage := input.bigQHat.ToAffineCompressed()
	if err := commitments.Open(hashFunc, bigQHatMessage, verifier.state.cHat, input.bigQHatWitness); err != nil {
		return errs.WrapFailed(err, "cannot decommit Q hat")
	}

	// 5. accepts if and only if it accepts the range proof and Q^ == Q'
	if !input.bigQHat.Equal(verifier.state.bigQPrime) {
		return errs.NewVerificationFailed("cannot verify")
	}
	err = verifier.rangeVerifier.Round5(input.rangeProverOutput)
	if err != nil {
		return err
	}

	verifier.round += 2
	return nil
}
