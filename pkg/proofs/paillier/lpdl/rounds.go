package lpdl

import (
	"github.com/cronokirby/saferith"

	"github.com/copperexchange/krypton-primitives/pkg/base/errs"
	saferithUtils "github.com/copperexchange/krypton-primitives/pkg/base/utils/saferith"
	"github.com/copperexchange/krypton-primitives/pkg/commitments"
	"github.com/copperexchange/krypton-primitives/pkg/encryptions/paillier"
)

func (verifier *Verifier) Round1() (r1out *Round1Output, err error) {
	// Validation
	if verifier.round != 1 {
		return nil, errs.NewRound("%d != 1", verifier.round)
	}

	// 1. choose random a, b
	verifier.state.a, err = saferithUtils.NatRandomRangeH(verifier.prng, verifier.state.q.Nat())
	if err != nil {
		return nil, errs.WrapFailed(err, "cannot generate random integer")
	}
	verifier.state.b, err = saferithUtils.NatRandomRangeH(verifier.prng, verifier.state.q2.Nat())
	if err != nil {
		return nil, errs.WrapFailed(err, "cannot generate random integer")
	}

	// 1.i. compute a (*) c (+) Enc(b, r) for random r
	acEnc, err := verifier.pk.MulPlaintext(verifier.c, verifier.state.a)
	if err != nil {
		return nil, errs.WrapFailed(err, "cannot perform homomorphic multiplication")
	}
	bEnc, _, err := verifier.pk.Encrypt(verifier.state.b, verifier.prng)
	if err != nil {
		return nil, errs.WrapFailed(err, "cannot encrypt value")
	}
	cPrime, err := verifier.pk.Add(acEnc, bEnc)
	if err != nil {
		return nil, errs.WrapFailed(err, "cannot perform homomorphic addition")
	}

	// 1.ii. compute c'' = commit(a, b)
	cDoublePrimeCommitment, cDoublePrimeWitness, err := commitments.Commit(
		verifier.sessionId,
		verifier.prng,
		verifier.state.a.Bytes(),
		verifier.state.b.Bytes(),
	)
	if err != nil {
		return nil, errs.WrapFailed(err, "cannot commit to a and b")
	}
	verifier.state.cDoublePrimeWitness = cDoublePrimeWitness

	// 1.iii. compute Q' = aQ + bQ
	aScalar := verifier.state.curve.ScalarField().Element().SetNat(verifier.state.a)
	bScalar := verifier.state.curve.ScalarField().Element().SetNat(verifier.state.b)
	verifier.state.bigQPrime = verifier.bigQ.ScalarMul(aScalar).Add(verifier.state.curve.ScalarBaseMult(bScalar))

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

func (prover *Prover) Round2(r1out *Round1Output) (r2out *Round2Output, err error) {
	// Validation; RangeVerifierOutput deferred to `rangeProver.Round2`, CPrime deferred to `decryptor.Decrypt`
	if prover.round != 2 {
		return nil, errs.NewRound("%d != 2", prover.round)
	}
	if err := r1out.Validate(); err != nil {
		return nil, errs.WrapValidation(err, "invalid round 2 input")
	}

	prover.state.cDoublePrimeCommitment = r1out.CDoublePrimeCommitment

	// 2.i. decrypt c' to obtain alpha, compute Q^ = alpha * G
	decrytor, err := paillier.NewDecryptor(prover.sk)
	if err != nil {
		return nil, errs.WrapFailed(err, "cannot create decryptor")
	}
	prover.state.alpha, err = decrytor.Decrypt(r1out.CPrime)
	if err != nil {
		return nil, errs.WrapFailed(err, "cannot decrypt cipher text")
	}
	alphaScalar := prover.state.curve.ScalarField().Element().SetNat(prover.state.alpha)
	prover.state.bigQHat = prover.state.curve.ScalarBaseMult(alphaScalar)

	// 2.ii. compute c^ = commit(Q^) and send to V
	bigQHatCommitment, bigQHatWitness, err := commitments.Commit(prover.sessionId, prover.prng, prover.state.bigQHat.ToAffineCompressed())
	if err != nil {
		return nil, errs.WrapFailed(err, "cannot commit to Q hat")
	}
	prover.state.bigQHatWitness = bigQHatWitness

	// 4.i. In parallel to the above, run L_P protocol
	rangeProverOutput, err := prover.rangeProver.Round2(r1out.RangeVerifierOutput)
	if err != nil {
		return nil, errs.WrapFailed(err, "range prover round 2")
	}

	prover.round += 2
	return &Round2Output{
		RangeProverOutput: rangeProverOutput,
		CHat:              bigQHatCommitment,
	}, nil
}

func (verifier *Verifier) Round3(r2out *Round2Output) (r3out *Round3Output, err error) {
	// Validation; RangeProverOutput deferred to `rangeVerifier.Round3`
	if verifier.round != 3 {
		return nil, errs.NewRound("%d != 3", verifier.round)
	}
	if err := r2out.Validate(); err != nil {
		return nil, errs.WrapValidation(err, "invalid round 3 input")
	}

	verifier.state.cHat = r2out.CHat

	// 4.i. In parallel to the above, run L_P protocol
	rangeVerifierOutput, err := verifier.rangeVerifier.Round3(r2out.RangeProverOutput)
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

func (prover *Prover) Round4(r3out *Round3Output) (r4out *Round4Output, err error) {
	// Validation; RangeVerifierOutput deferred to `rangeProver.Round4`
	if prover.round != 4 {
		return nil, errs.NewRound("%d != 4", prover.round)
	}
	if err := r3out.Validate(); err != nil {
		return nil, errs.WrapValidation(err, "invalid round 4 input")
	}

	if err := commitments.Open(prover.sessionId, prover.state.cDoublePrimeCommitment, r3out.CDoublePrimeWitness, r3out.A.Bytes(), r3out.B.Bytes()); err != nil {
		return nil, errs.WrapFailed(err, "cannot decommit a and b")
	}

	// 4. check that alpha == ax + b (over integers), if not aborts
	ax := new(saferith.Nat).Mul(r3out.A, prover.x.Nat(), -1)
	axPlusB := new(saferith.Nat).Add(ax, r3out.B, prover.state.q2.BitLen()+1)
	if prover.state.alpha.Eq(axPlusB) == 0 {
		return nil, errs.NewIdentifiableAbort("verifier", "verifier is misbehaving")
	}

	rangeProverOutput, err := prover.rangeProver.Round4(r3out.RangeVerifierOutput)
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
	// Validation; RangeProverOutput deferred to `rangeVerifier.Round5`
	if verifier.round != 5 {
		return errs.NewRound("%d != 5", verifier.round)
	}
	if err := input.Validate(); err != nil {
		return errs.WrapValidation(err, "invalid round 5 input")
	}

	if err := commitments.Open(verifier.sessionId, verifier.state.cHat, input.BigQHatWitness, input.BigQHat.ToAffineCompressed()); err != nil {
		return errs.WrapFailed(err, "cannot decommit Q hat")
	}

	// 5. accepts if and only if it accepts the range proof and Q^ == Q'
	if !input.BigQHat.Equal(verifier.state.bigQPrime) {
		return errs.NewVerification("cannot verify")
	}
	err = verifier.rangeVerifier.Round5(input.RangeProverOutput)
	if err != nil {
		return errs.WrapFailed(err, "range verifier round 5")
	}

	verifier.round += 2
	return nil
}
