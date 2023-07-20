package paillierdlog

import (
	crand "crypto/rand"
	"crypto/sha256"
	"github.com/copperexchange/crypto-primitives-go/pkg/commitments"
	"github.com/copperexchange/crypto-primitives-go/pkg/core/curves"
	"github.com/copperexchange/crypto-primitives-go/pkg/core/errs"
	"github.com/copperexchange/crypto-primitives-go/pkg/paillier"
	"math/big"
)

var (
	hashFunc = sha256.New
)

type VerifierRound1Output struct {
	cPrime         paillier.CipherText
	cBisCommitment commitments.Commitment
}

type ProverRound2Output struct {
	cHat commitments.Commitment
}

type VerifierRound3Output struct {
	a           *big.Int
	b           *big.Int
	cBisWitness commitments.Witness
}

type ProverRound4Output struct {
	bigQHat        curves.Point
	bigQHatWitness commitments.Witness
}

func (verifier *Verifier) Round1() (output *VerifierRound1Output, err error) {
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

	return &VerifierRound1Output{
		cPrime:         cPrime,
		cBisCommitment: cBisCommitment,
	}, nil
}

func (prover *Prover) Round2(input *VerifierRound1Output) (output *ProverRound2Output, err error) {
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

	return &ProverRound2Output{
		cHat: bigQHatCommitment,
	}, nil
}

func (verifier *Verifier) Round3(input *ProverRound2Output) (output *VerifierRound3Output) {
	verifier.state.cHat = input.cHat

	return &VerifierRound3Output{
		a:           verifier.state.a,
		b:           verifier.state.b,
		cBisWitness: verifier.state.cBisWitness,
	}
}

func (prover *Prover) Round4(input *VerifierRound3Output) (output *ProverRound4Output, err error) {
	cBisMessage := append(input.a.Bytes()[:], input.b.Bytes()...)
	if err := commitments.Open(hashFunc, cBisMessage, prover.state.cBisCommitment, input.cBisWitness); err != nil {
		return nil, errs.WrapFailed(err, "cannot decommit a and b")
	}

	alphaCheck := new(big.Int).Add(new(big.Int).Mul(input.a, prover.x.BigInt()), input.b)
	if prover.state.alpha.Cmp(alphaCheck) != 0 {
		return nil, errs.NewIdentifiableAbort("verifier is misbehaving")
	}

	return &ProverRound4Output{
		bigQHat:        prover.state.bigQHat,
		bigQHatWitness: prover.state.bigQHatWitness,
	}, nil
}

func (verifier *Verifier) Round5(input *ProverRound4Output) (err error) {
	bigQHatMessage := input.bigQHat.ToAffineCompressed()
	if err := commitments.Open(hashFunc, bigQHatMessage, verifier.state.cHat, input.bigQHatWitness); err != nil {
		return errs.WrapFailed(err, "cannot decommit Q hat")
	}

	if !input.bigQHat.Equal(verifier.state.bigQPrime) {
		return errs.NewVerificationFailed("cannot verify")
	}

	return nil
}
