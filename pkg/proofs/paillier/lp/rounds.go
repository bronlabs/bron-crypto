package lp

import (
	"github.com/cronokirby/saferith"

	"github.com/copperexchange/krypton-primitives/pkg/base/errs"
	"github.com/copperexchange/krypton-primitives/pkg/encryptions/paillier"
	"github.com/copperexchange/krypton-primitives/pkg/proofs/paillier/nthroot"
	"github.com/copperexchange/krypton-primitives/pkg/proofs/sigma"
)

func (verifier *Verifier) Round1() (r1out *Round1Output, err error) {
	// Validation
	if verifier.Round != 1 {
		return nil, errs.NewRound("%d != 1", verifier.Round)
	}

	verifier.state.y = make([]*saferith.Nat, verifier.k)
	verifier.state.x = make([]*paillier.CipherText, verifier.k)

	zero := new(saferith.Nat).SetUint64(0)
	nthRootProverRound1Outputs := make([]nthroot.Commitment, verifier.k)
	verifier.state.rootProvers = make([]*sigma.Prover[nthroot.Statement, nthroot.Witness, nthroot.Commitment, nthroot.State, nthroot.Response], verifier.k)
	rootTranscript := verifier.Transcript.Clone()
	for i := 0; i < verifier.k; i++ {
		// V picks x = y^N mod N^2 which is the Paillier encryption of zero (N being the Paillier public-key)
		verifier.state.x[i], verifier.state.y[i], err = verifier.paillierPublicKey.Encrypt(zero, verifier.Prng)
		if err != nil {
			return nil, errs.WrapFailed(err, "encryption failed")
		}

		// V proves the knowledge of y, the Nth root of x,
		verifier.state.rootProvers[i], err = sigma.NewProver(verifier.SessionId, rootTranscript.Clone(), verifier.nthRootProtocol, verifier.state.x[i].C, verifier.state.y[i])
		if err != nil {
			return nil, errs.WrapFailed(err, "cannot create Nth root prover")
		}
		nthRootProverRound1Outputs[i], err = verifier.state.rootProvers[i].Round1()
		if err != nil {
			return nil, errs.WrapFailed(err, "cannot run round 1 of Nth root prover")
		}
	}

	verifier.Round += 2
	return &Round1Output{
		NthRootProverOutputs: nthRootProverRound1Outputs,
		X:                    verifier.state.x,
	}, nil
}

func (prover *Prover) Round2(r1out *Round1Output) (r2out *Round2Output, err error) {
	// Validation
	if prover.Round != 2 {
		return nil, errs.NewRound("%d != 2", prover.Round)
	}
	if err := r1out.Validate(prover.k); err != nil {
		return nil, errs.WrapValidation(err, "invalid round 2 input")
	}

	prover.state.x = r1out.X

	nthRootVerifierRound2Outputs := make([]sigma.ChallengeBytes, prover.k)
	prover.state.rootVerifiers = make([]*sigma.Verifier[nthroot.Statement, nthroot.Witness, nthroot.Commitment, nthroot.State, nthroot.Response], prover.k)
	rootTranscript := prover.Transcript.Clone()
	for i := 0; i < prover.k; i++ {
		// round 2 of proving the knowledge of y
		prover.state.rootVerifiers[i], err = sigma.NewVerifier(prover.SessionId, rootTranscript.Clone(), prover.nthRootProtocol, r1out.X[i].C, prover.Prng)
		if err != nil {
			return nil, errs.WrapFailed(err, "cannot create Nth root verifier")
		}
		nthRootVerifierRound2Outputs[i], err = prover.state.rootVerifiers[i].Round2(r1out.NthRootProverOutputs[i])
		if err != nil {
			return nil, errs.WrapFailed(err, "cannot run round 2 of Nth root verifier")
		}
	}

	prover.Round += 2
	return &Round2Output{
		NthRootVerifierOutputs: nthRootVerifierRound2Outputs,
	}, nil
}

func (verifier *Verifier) Round3(r2out *Round2Output) (r3out *Round3Output, err error) {
	// Validation
	if verifier.Round != 3 {
		return nil, errs.NewRound("%d != 3", verifier.Round)
	}
	if err := r2out.Validate(verifier.k); err != nil {
		return nil, errs.WrapValidation(err, "invalid round 3 input")
	}
	nthRootProverRound3Outputs := make([]nthroot.Response, verifier.k)
	for i := 0; i < verifier.k; i++ {
		// round 3 of proving the knowledge of y
		nthRootProverRound3Outputs[i], err = verifier.state.rootProvers[i].Round3(r2out.NthRootVerifierOutputs[i])
		if err != nil {
			return nil, errs.WrapFailed(err, "cannot run round 3 of Nth root prover")
		}
	}

	verifier.Round += 2
	return &Round3Output{
		NthRootProverOutputs: nthRootProverRound3Outputs,
	}, nil
}

func (prover *Prover) Round4(r3out *Round3Output) (r4out *Round4Output, err error) {
	// Validation
	if prover.Round != 4 {
		return nil, errs.NewRound("%d != 4", prover.Round)
	}
	if err := r3out.Validate(prover.k); err != nil {
		return nil, errs.WrapValidation(err, "invalid round 4 input")
	}

	for i := 0; i < prover.k; i++ {
		// round 4 of proving the knowledge of y
		if err := prover.state.rootVerifiers[i].Verify(r3out.NthRootProverOutputs[i]); err != nil {
			return nil, errs.WrapVerification(err, "cannot verify knowledge of Nth root from Verifier")
		}
	}

	// V proved the knowledge of Nth root x
	yPrime := make([]*saferith.Nat, prover.k)
	for i := 0; i < prover.k; i++ {
		// P calculates a y', the Nth root of x
		// see: Yehuda Lindell's answer (https://crypto.stackexchange.com/a/46745) for reference
		m := new(saferith.Nat).ModInverse(prover.paillierSecretKey.N, saferith.ModulusFromNat(prover.paillierSecretKey.Phi))
		yPrime[i] = new(saferith.Nat).Exp(prover.state.x[i].C, m, prover.paillierSecretKey.GetNModulus())
	}

	// P returns a y'
	prover.Round += 2
	return &Round4Output{
		YPrime: yPrime,
	}, nil
}

func (verifier *Verifier) Round5(r4out *Round4Output) (err error) {
	// Validation
	if verifier.Round != 5 {
		return errs.NewRound("%d != 5", verifier.Round)
	}
	if err := r4out.Validate(verifier.k); err != nil {
		return errs.WrapValidation(err, "invalid round 5 input")
	}

	for i := 0; i < verifier.k; i++ {
		if r4out.YPrime[i].Eq(verifier.state.y[i]) == 0 {
			// V rejects if y != y'
			return errs.NewVerification("failed to verify Paillier public key")
		}
	}

	// V accepts if every y_i == y'_i
	verifier.Round += 2
	return nil
}
