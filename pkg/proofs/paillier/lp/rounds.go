package lp

import (
	"github.com/cronokirby/saferith"

	ds "github.com/copperexchange/krypton-primitives/pkg/base/datastructures"
	"github.com/copperexchange/krypton-primitives/pkg/base/errs"
	"github.com/copperexchange/krypton-primitives/pkg/encryptions/paillier"
	"github.com/copperexchange/krypton-primitives/pkg/proofs/paillier/nthroot"
	"github.com/copperexchange/krypton-primitives/pkg/proofs/sigma"
)

type Round1Output struct {
	NthRootProverOutputs []nthroot.Commitment
	X                    []*paillier.CipherText

	_ ds.Incomparable
}

type Round2Output struct {
	NthRootVerifierOutputs []sigma.ChallengeBytes

	_ ds.Incomparable
}

type Round3Output struct {
	NthRootProverOutputs []nthroot.Response

	_ ds.Incomparable
}

type Round4Output struct {
	YPrime []*saferith.Nat

	_ ds.Incomparable
}

func (verifier *Verifier) Round1() (output *Round1Output, err error) {
	if verifier.round != 1 {
		return nil, errs.NewRound("%d != 1", verifier.round)
	}

	verifier.state.y = make([]*saferith.Nat, verifier.k)
	verifier.state.x = make([]*paillier.CipherText, verifier.k)

	zero := new(saferith.Nat).SetUint64(0)
	nthRootProverRound1Outputs := make([]nthroot.Commitment, verifier.k)
	verifier.state.rootProvers = make([]*sigma.Prover[nthroot.Statement, nthroot.Witness, nthroot.Commitment, nthroot.State, nthroot.Response], verifier.k)
	rootTranscript := verifier.transcript.Clone()
	for i := 0; i < verifier.k; i++ {
		// V picks x = y^N mod N^2 which is the Paillier encryption of zero (N being the Paillier public-key)
		verifier.state.x[i], verifier.state.y[i], err = verifier.paillierPublicKey.Encrypt(zero, verifier.prng)
		if err != nil {
			return nil, errs.WrapFailed(err, "encryption failed")
		}

		// V proves the knowledge of y, the Nth root of x,
		verifier.state.rootProvers[i], err = sigma.NewProver(verifier.sessionId, rootTranscript.Clone(), verifier.nthRootProtocol, verifier.state.x[i].C, verifier.state.y[i])
		if err != nil {
			return nil, errs.WrapFailed(err, "cannot create Nth root prover")
		}
		nthRootProverRound1Outputs[i], err = verifier.state.rootProvers[i].Round1()
		if err != nil {
			return nil, errs.WrapFailed(err, "cannot run round 1 of Nth root prover")
		}
	}

	verifier.round += 2
	return &Round1Output{
		NthRootProverOutputs: nthRootProverRound1Outputs,
		X:                    verifier.state.x,
	}, nil
}

func (prover *Prover) Round2(input *Round1Output) (output *Round2Output, err error) {
	if prover.round != 2 {
		return nil, errs.NewRound("%d != 2", prover.round)
	}

	prover.state.x = input.X

	nthRootVerifierRound2Outputs := make([]sigma.ChallengeBytes, prover.k)
	prover.state.rootVerifiers = make([]*sigma.Verifier[nthroot.Statement, nthroot.Witness, nthroot.Commitment, nthroot.State, nthroot.Response], prover.k)
	rootTranscript := prover.transcript.Clone()
	for i := 0; i < prover.k; i++ {
		// round 2 of proving the knowledge of y
		prover.state.rootVerifiers[i], err = sigma.NewVerifier(prover.sessionId, rootTranscript.Clone(), prover.nthRootProtocol, input.X[i].C, prover.prng)
		if err != nil {
			return nil, errs.WrapFailed(err, "cannot create Nth root verifier")
		}
		nthRootVerifierRound2Outputs[i], err = prover.state.rootVerifiers[i].Round2(input.NthRootProverOutputs[i])
		if err != nil {
			return nil, errs.WrapFailed(err, "cannot run round 2 of Nth root verifier")
		}
	}

	prover.round += 2
	return &Round2Output{
		NthRootVerifierOutputs: nthRootVerifierRound2Outputs,
	}, nil
}

func (verifier *Verifier) Round3(input *Round2Output) (output *Round3Output, err error) {
	if verifier.round != 3 {
		return nil, errs.NewRound("%d != 3", verifier.round)
	}

	nthRootProverRound3Outputs := make([]nthroot.Response, verifier.k)
	for i := 0; i < verifier.k; i++ {
		// round 3 of proving the knowledge of y
		nthRootProverRound3Outputs[i], err = verifier.state.rootProvers[i].Round3(input.NthRootVerifierOutputs[i])
		if err != nil {
			return nil, errs.WrapFailed(err, "cannot run round 3 of Nth root prover")
		}
	}

	verifier.round += 2
	return &Round3Output{
		NthRootProverOutputs: nthRootProverRound3Outputs,
	}, nil
}

func (prover *Prover) Round4(input *Round3Output) (output *Round4Output, err error) {
	if prover.round != 4 {
		return nil, errs.NewRound("%d != 4", prover.round)
	}

	for i := 0; i < prover.k; i++ {
		// round 4 of proving the knowledge of y
		if err := prover.state.rootVerifiers[i].Verify(input.NthRootProverOutputs[i]); err != nil {
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
	prover.round += 2
	return &Round4Output{
		YPrime: yPrime,
	}, nil
}

func (verifier *Verifier) Round5(input *Round4Output) (err error) {
	if verifier.round != 5 {
		return errs.NewRound("%d != 5", verifier.round)
	}

	for i := 0; i < verifier.k; i++ {
		if input.YPrime[i].Eq(verifier.state.y[i]) == 0 {
			// V rejects if y != y'
			return errs.NewVerification("failed to verify Paillier public key")
		}
	}

	// V accepts if every y_i == y'_i
	verifier.round += 2
	return nil
}
