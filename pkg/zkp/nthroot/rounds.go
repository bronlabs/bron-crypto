package nthroot

import (
	crand "crypto/rand"
	"github.com/copperexchange/crypto-primitives-go/pkg/core/errs"
	"math/big"
)

type ProverRound1Output struct {
	A *big.Int
}

type VerifierRound2Output struct {
	E *big.Int
}

type ProverRound3Output struct {
	Z *big.Int
}

func (prover *Prover) Round1() (output *ProverRound1Output, err error) {
	if prover.round != 1 {
		return nil, errs.NewInvalidRound("%d != 1", prover.round)
	}

	// P chooses r at random mod N^2...
	prover.state.r, err = crand.Int(prover.prng, prover.state.bigNSquared)
	if err != nil {
		return nil, errs.WrapFailed(err, "cannot generate random number")
	}

	// ...calculates a = r^N mod N^2 and sends to V
	a := new(big.Int).Exp(prover.state.r, prover.bigN, prover.state.bigNSquared)

	prover.round += 2
	return &ProverRound1Output{
		A: a,
	}, nil
}

func (verifier *Verifier) Round2(input *ProverRound1Output) (output *VerifierRound2Output, err error) {
	if verifier.round != 2 {
		return nil, errs.NewInvalidRound("%d != 2", verifier.round)
	}

	verifier.state.a = input.A

	// k = bit length of N
	k := verifier.bigN.BitLen()

	// V chooses e, a random k bit number, and sends e to P (i.e 0 <= e < (1 << k))
	e, err := crand.Int(verifier.prng, new(big.Int).Lsh(big.NewInt(1), uint(k)))
	if err != nil {
		return nil, errs.WrapFailed(err, "cannot generate random number")
	}
	// make sure e has MSB set
	verifier.state.e = new(big.Int).SetBit(e, k-1, 1)

	verifier.round += 2
	return &VerifierRound2Output{
		E: verifier.state.e,
	}, nil
}

func (prover *Prover) Round3(input *VerifierRound2Output) (output *ProverRound3Output, err error) {
	if prover.round != 3 {
		return nil, errs.NewInvalidRound("%d != 3", prover.round)
	}

	// P sends z = rv^e mod N^2 to V
	z := new(big.Int).Mod(new(big.Int).Mul(new(big.Int).Exp(prover.y, input.E, prover.state.bigNSquared), prover.state.r), prover.state.bigNSquared)

	prover.round += 2
	return &ProverRound3Output{
		Z: z,
	}, nil
}

func (verifier *Verifier) Round4(input *ProverRound3Output) (err error) {
	if verifier.round != 4 {
		return errs.NewInvalidRound("%d != 4", verifier.round)
	}

	// calc z^N mod N^2
	zToN := new(big.Int).Exp(input.Z, verifier.bigN, verifier.state.bigNSquared)
	// calc au^e mod N^2
	uToE := new(big.Int).Exp(verifier.x, verifier.state.e, verifier.state.bigNSquared)
	aTimesUtoE := new(big.Int).Mod(new(big.Int).Mul(verifier.state.a, uToE), verifier.state.bigNSquared)

	// V checks that z^N = au^e mod N^2, and accepts if and only if this is the case
	if zToN.Cmp(aTimesUtoE) != 0 {
		return errs.NewVerificationFailed("verification failed")
	}

	verifier.round += 2
	return nil
}
