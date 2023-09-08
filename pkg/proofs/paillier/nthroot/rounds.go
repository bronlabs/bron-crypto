package nthroot

import (
	crand "crypto/rand"

	"github.com/cronokirby/saferith"

	"github.com/copperexchange/krypton/pkg/base"
	"github.com/copperexchange/krypton/pkg/base/errs"
	"github.com/copperexchange/krypton/pkg/base/types"
)

type Round1Output struct {
	A *saferith.Nat

	_ types.Incomparable
}

type Round2Output struct {
	E *saferith.Nat

	_ types.Incomparable
}

type Round3Output struct {
	Z *saferith.Nat

	_ types.Incomparable
}

func (prover *Prover) Round1() (output *Round1Output, err error) {
	if prover.round != 1 {
		return nil, errs.NewInvalidRound("%d != 1", prover.round)
	}

	// P chooses r at random mod N^2...
	rInt, err := crand.Int(prover.prng, prover.state.bigNSquared.Big())
	if err != nil {
		return nil, errs.WrapFailed(err, "cannot generate random number")
	}
	prover.state.r = new(saferith.Nat).SetBig(rInt, prover.state.bigNSquared.BitLen())

	// ...calculates a = r^N mod N^2 and sends to V
	a := new(saferith.Nat).Exp(prover.state.r, prover.bigN, prover.state.bigNSquared)

	prover.round += 2
	return &Round1Output{
		A: a,
	}, nil
}

func (verifier *Verifier) Round2(input *Round1Output) (output *Round2Output, err error) {
	if verifier.round != 2 {
		return nil, errs.NewInvalidRound("%d != 2", verifier.round)
	}

	verifier.state.a = input.A

	// k = bit length of N
	k := verifier.bigN.AnnouncedLen()

	// V chooses e, a random k bit number, and sends e to P (i.e 0 <= e < (1 << k))
	e, err := base.RandomNat(verifier.prng, new(saferith.Nat).SetUint64(0), new(saferith.Nat).Lsh(new(saferith.Nat).SetUint64(1), uint(k), -1))
	if err != nil {
		return nil, errs.WrapFailed(err, "cannot generate random number")
	}
	// make sure e has MSB set (no
	e, err = base.NatSetBit(e, k-1)
	if err != nil {
		return nil, errs.WrapFailed(err, "cannot set MSB")
	}
	verifier.state.e = e

	verifier.round += 2
	return &Round2Output{
		E: verifier.state.e,
	}, nil
}

func (prover *Prover) Round3(input *Round2Output) (output *Round3Output, err error) {
	if prover.round != 3 {
		return nil, errs.NewInvalidRound("%d != 3", prover.round)
	}

	// P sends z = rv^e mod N^2 to V
	z := new(saferith.Nat).ModMul(new(saferith.Nat).Exp(prover.y, input.E, prover.state.bigNSquared), prover.state.r, prover.state.bigNSquared)

	prover.round += 2
	return &Round3Output{
		Z: z,
	}, nil
}

func (verifier *Verifier) Round4(input *Round3Output) (err error) {
	if verifier.round != 4 {
		return errs.NewInvalidRound("%d != 4", verifier.round)
	}

	// calc z^N mod N^2
	zToN := new(saferith.Nat).Exp(input.Z, verifier.bigN, verifier.state.bigNSquared)
	// calc au^e mod N^2
	uToE := new(saferith.Nat).Exp(verifier.x, verifier.state.e, verifier.state.bigNSquared)
	aTimesUtoE := new(saferith.Nat).ModMul(verifier.state.a, uToE, verifier.state.bigNSquared)

	// V checks that z^N = au^e mod N^2, and accepts if and only if this is the case
	if zToN.Eq(aTimesUtoE) == 0 {
		return errs.NewVerificationFailed("verification failed")
	}

	verifier.round += 2
	return nil
}
