package lp

import (
	"github.com/cronokirby/saferith"

	"github.com/bronlabs/krypton-primitives/pkg/base/errs"
	"github.com/bronlabs/krypton-primitives/pkg/base/modular"
	"github.com/bronlabs/krypton-primitives/pkg/proofs/sigma"
)

func (verifier *Verifier) Round1() (output *Round1Output, err error) {
	if verifier.Round != 1 {
		return nil, errs.NewRound("%d != 1", verifier.Round)
	}

	rootTranscript := verifier.Transcript.Clone()

	// V picks x = y^N mod N^2 which is the Paillier encryption of zero (N being the Paillier public-key)
	zeros := make([]*saferith.Int, verifier.k)
	for i := range zeros {
		zeros[i] = new(saferith.Int).SetUint64(0).Resize(0)
	}
	verifier.state.x, verifier.state.y, err = verifier.paillierPublicKey.EncryptMany(zeros, verifier.Prng)
	if err != nil {
		return nil, errs.WrapFailed(err, "encryption failed")
	}

	xs := make([]*saferith.Nat, verifier.k)
	for i, x := range verifier.state.x {
		xs[i] = &x.C
	}
	verifier.state.rootsProver, err = sigma.NewProver(verifier.SessionId, rootTranscript.Clone(), verifier.nthRootsProtocol, xs, verifier.state.y)
	if err != nil {
		return nil, errs.WrapFailed(err, "cannot create sigma protocol prover")
	}

	nthRootProverRound1Output, err := verifier.state.rootsProver.Round1()
	if err != nil {
		return nil, errs.WrapFailed(err, "cannot run round 1 of Nth root prover")
	}

	verifier.Round += 2
	return &Round1Output{
		NthRootsProverOutput: nthRootProverRound1Output,
		X:                    verifier.state.x,
	}, nil
}

func (prover *Prover) Round2(input *Round1Output) (output *Round2Output, err error) {
	if prover.Round != 2 {
		return nil, errs.NewRound("%d != 2", prover.Round)
	}
	if err := input.Validate(prover.k); err != nil {
		return nil, errs.WrapValidation(err, "invalid round 2 input")
	}

	prover.state.x = input.X
	xs := make([]*saferith.Nat, prover.k)
	for i, x := range input.X {
		xs[i] = &x.C
	}

	rootTranscript := prover.Transcript.Clone()
	prover.state.rootsVerifier, err = sigma.NewVerifier(prover.SessionId, rootTranscript.Clone(), prover.nthRootsProtocol, xs, prover.Prng)
	if err != nil {
		return nil, errs.WrapFailed(err, "cannot create Nth root verifier")
	}

	nthRootVerifierRound2Output, err := prover.state.rootsVerifier.Round2(input.NthRootsProverOutput)
	if err != nil {
		return nil, errs.WrapFailed(err, "cannot run round 2 of Nth root verifier")
	}

	prover.Round += 2
	return &Round2Output{
		NthRootsVerifierOutput: nthRootVerifierRound2Output,
	}, nil
}

func (verifier *Verifier) Round3(input *Round2Output) (output *Round3Output, err error) {
	if verifier.Round != 3 {
		return nil, errs.NewRound("%d != 3", verifier.Round)
	}
	if err := input.Validate(verifier.k); err != nil {
		return nil, errs.WrapValidation(err, "invalid round 3 input")
	}

	nthRootProverRound3Output, err := verifier.state.rootsProver.Round3(input.NthRootsVerifierOutput)
	if err != nil {
		return nil, errs.WrapFailed(err, "cannot run round 3 of Nth root prover")
	}

	verifier.Round += 2
	return &Round3Output{
		NthRootsProverOutput: nthRootProverRound3Output,
	}, nil
}

func (prover *Prover) Round4(input *Round3Output) (output *Round4Output, err error) {
	if prover.Round != 4 {
		return nil, errs.NewRound("%d != 4", prover.Round)
	}
	if err := input.Validate(prover.k); err != nil {
		return nil, errs.WrapValidation(err, "invalid round 4 input")
	}

	// round 4 of proving the knowledge of y
	if err := prover.state.rootsVerifier.Verify(input.NthRootsProverOutput); err != nil {
		return nil, errs.WrapVerification(err, "cannot verify knowledge of Nth root from Verifier")
	}

	// V proved the knowledge of Nth root x
	bases := make([]*saferith.Nat, prover.k)
	for i, c := range prover.state.x {
		bases[i] = &c.C
	}

	nMod, err := modular.NewFastModulusFromPrimeFactors(prover.paillierSecretKey.P.Nat(), prover.paillierSecretKey.Q.Nat())
	if err != nil {
		return nil, errs.WrapFailed(err, "cannot get NN residue params")
	}

	// P calculates a y', the Nth root of x
	// see: Yehuda Lindell's answer (https://crypto.stackexchange.com/a/46745) for reference
	m := new(saferith.Nat).ModInverse(prover.paillierSecretKey.N.Nat(), prover.paillierSecretKey.Phi())
	yPrime, err := nMod.MultiBaseExp(bases, m)
	if err != nil {
		return nil, errs.WrapFailed(err, "cannot compute exp")
	}

	// P returns a y'
	prover.Round += 2
	return &Round4Output{
		YPrime: yPrime,
	}, nil
}

func (verifier *Verifier) Round5(input *Round4Output) (err error) {
	// Validation
	if verifier.Round != 5 {
		return errs.NewRound("%d != 5", verifier.Round)
	}
	if err := input.Validate(verifier.k); err != nil {
		return errs.WrapValidation(err, "invalid round 5 input")
	}

	for i := 0; i < verifier.k; i++ {
		if input.YPrime[i].Eq(verifier.state.y[i]) == 0 {
			// V rejects if y != y'
			return errs.NewVerification("failed to verify Paillier public key")
		}
	}

	// V accepts if every y_i == y'_i
	verifier.Round += 2
	return nil
}
