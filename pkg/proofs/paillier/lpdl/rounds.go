package lpdl

import (
	"slices"

	"github.com/bronlabs/bron-crypto/pkg/base/errs"
	"github.com/bronlabs/bron-crypto/pkg/base/nt/num"
)

func (verifier *Verifier[P, B, S]) Round1() (r1out *Round1Output, err error) {
	// Validation
	if verifier.round != 1 {
		return nil, errs.NewRound("%d != 1", verifier.round)
	}

	// 1. choose random a, b (both from Z/qZ since they're used as curve scalars)
	verifier.state.a, err = verifier.state.zModQ.Random(verifier.prng)
	if err != nil {
		return nil, errs.WrapFailed(err, "cannot generate random integer")
	}
	verifier.state.b, err = verifier.state.zModQ.Random(verifier.prng)
	if err != nil {
		return nil, errs.WrapFailed(err, "cannot generate random integer")
	}

	bAsPlaintext, err := verifier.pk.PlaintextSpace().FromNat(verifier.state.b.Value())
	if err != nil {
		return nil, errs.WrapFailed(err, "cannot create plaintext from nat")
	}

	// 1.i. compute a (*) c (+) Enc(b, r) for random r
	// acEnc, err := verifier.pk.CipherTextMul(verifier.c, new(saferith.Int).SetNat(verifier.state.a))
	acEnc := verifier.c.ScalarExp(verifier.state.a.Nat())
	bEnc, _, err := verifier.paillierEncrypter.Encrypt(bAsPlaintext, verifier.pk, verifier.prng)
	if err != nil {
		return nil, errs.WrapFailed(err, "cannot encrypt value")
	}
	cPrime := acEnc.Mul(bEnc)

	// 1.ii. compute c'' = commit(a, b)
	cDoublePrimeCommitment, cDoublePrimeWitness, err := verifier.commitmentScheme.Committer().Commit(slices.Concat(verifier.state.a.Bytes(), verifier.state.b.Bytes()), verifier.prng)
	if err != nil {
		return nil, errs.WrapFailed(err, "cannot commit to a and b")
	}
	verifier.state.cDoublePrimeWitness = cDoublePrimeWitness

	// 1.iii. compute Q' = aQ + bQ
	// TODO: add SetNatCT to ScalarField etc.
	aScalar, err := verifier.state.curve.ScalarField().FromBytesBE(verifier.state.a.Bytes())
	if err != nil {
		return nil, errs.WrapFailed(err, "cannot convert a to scalar")
	}
	bScalar, err := verifier.state.curve.ScalarField().FromBytesBE(verifier.state.b.Bytes())
	if err != nil {
		return nil, errs.WrapFailed(err, "cannot convert b to scalar")
	}
	verifier.state.bigQPrime = verifier.bigQ.ScalarMul(aScalar).Add(verifier.state.curve.ScalarBaseMul(bScalar))

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

func (prover *Prover[P, B, S]) Round2(r1out *Round1Output) (r2out *Round2Output, err error) {
	// Validation; RangeVerifierOutput deferred to `rangeProver.Round2`, CPrime deferred to `decryptor.Decrypt`
	if prover.round != 2 {
		return nil, errs.NewRound("%d != 2", prover.round)
	}
	if err := r1out.Validate(); err != nil {
		return nil, errs.WrapValidation(err, "invalid round 2 input")
	}

	prover.state.cDoublePrimeCommitment = r1out.CDoublePrimeCommitment

	// 2.i. decrypt c' to obtain alpha, compute Q^ = alpha * G
	prover.state.alpha, err = prover.paillierDecrypter.Decrypt(r1out.CPrime)
	if err != nil {
		return nil, errs.WrapFailed(err, "cannot decrypt cipher text")
	}

	alphaScalar, err := prover.state.curve.ScalarField().FromBytesBE(prover.state.alpha.Normalise().BytesBE())
	if err != nil {
		return nil, errs.WrapFailed(err, "cannot convert alpha to scalar")
	}
	prover.state.bigQHat = prover.state.curve.ScalarBaseMul(alphaScalar)

	// 2.ii. compute c^ = commit(Q^) and send to V

	bigQHatCommitment, bigQHatWitness, err := prover.commitmentScheme.Committer().Commit(prover.state.bigQHat.ToCompressed(), prover.prng)
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

func (verifier *Verifier[P, B, S]) Round3(r2out *Round2Output) (r3out *Round3Output, err error) {
	// Validation; RangeProverOutput deferred to `rangeVerifier.Round3`
	if verifier.round != 3 {
		return nil, errs.NewRound("%d != 3", verifier.round)
	}
	if err := r2out.Validate(); err != nil {
		return nil, errs.WrapValidation(err, "invalid round 3 input")
	}

	verifier.state.cHat = r2out.CHat

	// 4.i. In parallel to the above, run L_P protocol
	rangeVerifierMessage, rangeVerifierWitness, err := verifier.rangeVerifier.Round3(r2out.RangeProverOutput)
	if err != nil {
		return nil, errs.WrapFailed(err, "range verifier round 3")
	}

	// 3. decommit c'' revealing a, b
	verifier.round += 2
	return &Round3Output{
		RangeVerifierMessage: rangeVerifierMessage,
		RangeVerifierWitness: rangeVerifierWitness,
		A:                    verifier.state.a,
		B:                    verifier.state.b,
		CDoublePrimeWitness:  verifier.state.cDoublePrimeWitness,
	}, nil
}

func (prover *Prover[P, B, S]) Round4(r4In *Round3Output) (r4out *Round4Output[P, B, S], err error) {
	// Validation; RangeVerifierOutput deferred to `rangeProver.Round4`
	if prover.round != 4 {
		return nil, errs.NewRound("%d != 4", prover.round)
	}
	if err := r4In.Validate(); err != nil {
		return nil, errs.WrapValidation(err, "invalid round 4 input")
	}

	if err := prover.commitmentScheme.Verifier().Verify(prover.state.cDoublePrimeCommitment, slices.Concat(r4In.A.Bytes(), r4In.B.Bytes()), r4In.CDoublePrimeWitness); err != nil {
		return nil, errs.WrapFailed(err, "cannot open R commitment")
	}

	// 4. check that alpha == ax + b (over integers), if not aborts
	x, err := num.Z().FromCardinal(prover.x.Cardinal())
	if err != nil {
		return nil, errs.WrapFailed(err, "cannot convert x to nat")
	}
	if !prover.state.alpha.Value().Equal(r4In.A.Lift().Mul(x).Add(r4In.B.Lift())) {
		return nil, errs.NewIdentifiableAbort("verifier", "verifier is misbehaving")
	}

	rangeProverOutput, err := prover.rangeProver.Round4(r4In.RangeVerifierMessage, r4In.RangeVerifierWitness)
	if err != nil {
		return nil, errs.WrapFailed(err, "range prover round 4")
	}

	// 4. decommit c^ revealing Q^
	prover.round += 2
	return &Round4Output[P, B, S]{
		RangeProverOutput: rangeProverOutput,
		BigQHat:           prover.state.bigQHat,
		BigQHatWitness:    prover.state.bigQHatWitness,
	}, nil
}

func (verifier *Verifier[P, B, S]) Round5(input *Round4Output[P, B, S]) (err error) {
	// Validation; RangeProverOutput deferred to `rangeVerifier.Round5`
	if verifier.round != 5 {
		return errs.NewRound("%d != 5", verifier.round)
	}
	if err := input.Validate(); err != nil {
		return errs.WrapValidation(err, "invalid round 5 input")
	}

	if err := verifier.commitmentScheme.Verifier().Verify(verifier.state.cHat, input.BigQHat.ToCompressed(), input.BigQHatWitness); err != nil {
		return errs.WrapFailed(err, "cannot decommit Q hat")
	}

	// 5. accepts if and only if it accepts the range proof and Q^ == Q'
	if !input.BigQHat.Equal(verifier.state.bigQPrime) {
		return errs.NewVerification("cannot verify")
	}
	err = verifier.rangeVerifier.Verify(input.RangeProverOutput)
	if err != nil {
		return errs.WrapFailed(err, "range verifier round 5")
	}

	verifier.round += 2
	return nil
}
