package lp

import (
	"github.com/cronokirby/saferith"

	ds "github.com/copperexchange/krypton-primitives/pkg/base/datastructures"
	"github.com/copperexchange/krypton-primitives/pkg/base/errs"
	"github.com/copperexchange/krypton-primitives/pkg/encryptions/paillier"
	"github.com/copperexchange/krypton-primitives/pkg/proofs/paillier/nthroots"
	"github.com/copperexchange/krypton-primitives/pkg/proofs/sigma"
)

type Round1Output struct {
	NthRootProverOutput nthroots.Commitment
	X                   []*paillier.CipherText

	_ ds.Incomparable
}

type Round2Output struct {
	NthRootVerifierOutput sigma.ChallengeBytes

	_ ds.Incomparable
}

type Round3Output struct {
	NthRootProverOutputs nthroots.Response

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

	rootTranscript := verifier.transcript.Clone()

	// V picks x = y^N mod N^2 which is the Paillier encryption of zero (N being the Paillier public-key)
	zeros := make([]*saferith.Nat, verifier.k)
	for i := range zeros {
		zeros[i] = new(saferith.Nat).SetUint64(0).Resize(1)
	}
	verifier.state.x, verifier.state.y, err = verifier.paillierPublicKey.EncryptMany(zeros, verifier.prng)
	if err != nil {
		return nil, errs.WrapFailed(err, "encryption failed")
	}

	xs := make([]*saferith.Nat, verifier.k)
	for i, x := range verifier.state.x {
		xs[i] = x.C
	}
	verifier.state.nthRootProver, err = sigma.NewProver(verifier.sessionId, rootTranscript.Clone(), verifier.nthRootProtocol, xs, verifier.state.y)
	nthRootProverRound1Output, err := verifier.state.nthRootProver.Round1()
	if err != nil {
		return nil, errs.WrapFailed(err, "cannot run round 1 of Nth root prover")
	}

	verifier.round += 2
	return &Round1Output{
		NthRootProverOutput: nthRootProverRound1Output,
		X:                   verifier.state.x,
	}, nil
}

func (prover *Prover) Round2(input *Round1Output) (output *Round2Output, err error) {
	if prover.round != 2 {
		return nil, errs.NewRound("%d != 2", prover.round)
	}

	prover.state.x = input.X
	xs := make([]*saferith.Nat, prover.k)
	for i, x := range input.X {
		xs[i] = x.C
	}

	rootTranscript := prover.transcript.Clone()
	prover.state.rootVerifier, err = sigma.NewVerifier(prover.sessionId, rootTranscript.Clone(), prover.nthRootProtocol, xs, prover.prng)
	if err != nil {
		return nil, errs.WrapFailed(err, "cannot create Nth root verifier")
	}

	nthRootVerifierRound2Output, err := prover.state.rootVerifier.Round2(input.NthRootProverOutput)
	if err != nil {
		return nil, errs.WrapFailed(err, "cannot run round 2 of Nth root verifier")
	}

	prover.round += 2
	return &Round2Output{
		NthRootVerifierOutput: nthRootVerifierRound2Output,
	}, nil
}

func (verifier *Verifier) Round3(input *Round2Output) (output *Round3Output, err error) {
	if verifier.round != 3 {
		return nil, errs.NewRound("%d != 3", verifier.round)
	}

	nthRootProverRound3Outputs, err := verifier.state.nthRootProver.Round3(input.NthRootVerifierOutput)
	if err != nil {
		return nil, errs.WrapFailed(err, "cannot run round 3 of Nth root prover")
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

	// round 4 of proving the knowledge of y
	if err := prover.state.rootVerifier.Verify(input.NthRootProverOutputs); err != nil {
		return nil, errs.WrapVerification(err, "cannot verify knowledge of Nth root from Verifier")
	}

	// V proved the knowledge of Nth root x
	bases := make([]*saferith.Nat, prover.k)
	for i, c := range prover.state.x {
		bases[i] = c.C
	}

	// P calculates a y', the Nth root of x
	// see: Yehuda Lindell's answer (https://crypto.stackexchange.com/a/46745) for reference
	m := new(saferith.Nat).ModInverse(prover.paillierSecretKey.N, saferith.ModulusFromNat(prover.paillierSecretKey.Phi))
	yPrime := prover.paillierSecretKey.GetNModulus().MultiBaseExp(bases, m)

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
