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
	rangeVerifierOutput *paillierrange.VerifierRound1Output
	cPrime              paillier.CipherText
	cBisCommitment      commitments.Commitment
}

type ProverRound2Output struct {
	rangeProverOutput *paillierrange.ProverRound2Output
	cHat              commitments.Commitment
}

type VerifierRound3Output struct {
	rangeVerifierOutput *paillierrange.VerifierRound3Output
	a                   *big.Int
	b                   *big.Int
	cBisWitness         commitments.Witness
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

	verifier.state.a, err = crand.Int(verifier.prng, verifier.state.q)
	if err != nil {
		return nil, errs.WrapFailed(err, "cannot generate random integer")
	}
	verifier.state.b, err = crand.Int(verifier.prng, verifier.state.q2)
	if err != nil {
		return nil, errs.WrapFailed(err, "cannot generate random integer")
	}

	acEnc, err := verifier.pk.Mul(verifier.state.a, verifier.c)
	if err != nil {
		return nil, errs.WrapFailed(err, "cannot perform homomorphic multiplication")
	}
	bEnc, _, err := verifier.pk.Encrypt(verifier.state.b)
	if err != nil {
		return nil, errs.WrapFailed(err, "cannot encrypt value")
	}
	cPrime, err := verifier.pk.Add(acEnc, bEnc)

	cBisMessage := append(verifier.state.a.Bytes()[:], verifier.state.b.Bytes()...)
	cBisCommitment, cBisWitness, err := commitments.Commit(hashFunc, cBisMessage)
	if err != nil {
		return nil, errs.WrapFailed(err, "cannot commit to a and b")
	}
	verifier.state.cBisWitness = cBisWitness

	aScalar, err := verifier.state.curve.NewScalar().SetBigInt(verifier.state.a)
	if err != nil {
		return nil, errs.WrapFailed(err, "cannot set scalar")
	}
	bScalar, err := verifier.state.curve.NewScalar().SetBigInt(verifier.state.b)
	if err != nil {
		return nil, errs.WrapFailed(err, "cannot set scalar")
	}
	verifier.state.bigQPrime = verifier.bigQ.Mul(aScalar).Add(verifier.state.curve.ScalarBaseMult(bScalar))

	rangeVerifierOutput, err := verifier.rangeVerifier.Round1()
	if err != nil {
		return nil, err
	}

	verifier.round += 2
	return &VerifierRound1Output{
		rangeVerifierOutput: rangeVerifierOutput,
		cPrime:              cPrime,
		cBisCommitment:      cBisCommitment,
	}, nil
}

func (prover *Prover) Round2(input *VerifierRound1Output) (output *ProverRound2Output, err error) {
	if prover.round != 2 {
		return nil, errs.NewInvalidRound("%d != 2", prover.round)
	}

	prover.state.cBisCommitment = input.cBisCommitment
	prover.state.alpha, err = prover.sk.Decrypt(input.cPrime)
	if err != nil {
		return nil, errs.WrapFailed(err, "cannot decrypt cipher text")
	}
	alphaScalar, err := prover.state.curve.NewScalar().SetBigInt(prover.state.alpha)
	if err != nil {
		return nil, errs.WrapFailed(err, "cannot set scalar")
	}
	prover.state.bigQHat = prover.state.curve.ScalarBaseMult(alphaScalar)
	bigQHatMessage := prover.state.bigQHat.ToAffineCompressed()
	bigQHatCommitment, bigQHatWitness, err := commitments.Commit(hashFunc, bigQHatMessage)
	if err != nil {
		return nil, errs.WrapFailed(err, "cannot commit to Q hat")
	}
	prover.state.bigQHatWitness = bigQHatWitness

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
	rangeVerifierOutput, err := verifier.rangeVerifier.Round3(input.rangeProverOutput)
	if err != nil {
		return nil, err
	}

	verifier.round += 2
	return &VerifierRound3Output{
		rangeVerifierOutput: rangeVerifierOutput,
		a:                   verifier.state.a,
		b:                   verifier.state.b,
		cBisWitness:         verifier.state.cBisWitness,
	}, nil
}

func (prover *Prover) Round4(input *VerifierRound3Output) (output *ProverRound4Output, err error) {
	if prover.round != 4 {
		return nil, errs.NewInvalidRound("%d != 4", prover.round)
	}

	cBisMessage := append(input.a.Bytes()[:], input.b.Bytes()...)
	if err := commitments.Open(hashFunc, cBisMessage, prover.state.cBisCommitment, input.cBisWitness); err != nil {
		return nil, errs.WrapFailed(err, "cannot decommit a and b")
	}

	alphaCheck := new(big.Int).Add(new(big.Int).Mul(input.a, prover.x.BigInt()), input.b)
	if prover.state.alpha.Cmp(alphaCheck) != 0 {
		return nil, errs.NewIdentifiableAbort("verifier is misbehaving")
	}

	rangeProverOutput, err := prover.rangeProver.Round4(input.rangeVerifierOutput)
	if err != nil {
		return nil, err
	}

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
