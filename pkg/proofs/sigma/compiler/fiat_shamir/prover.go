package fiat_shamir

import (
	"github.com/copperexchange/krypton-primitives/pkg/base/errs"
	"github.com/copperexchange/krypton-primitives/pkg/proofs/sigma"
	"github.com/copperexchange/krypton-primitives/pkg/proofs/sigma/compiler"
	"github.com/copperexchange/krypton-primitives/pkg/transcripts"
)

var _ compiler.NIProver[sigma.Statement, sigma.Witness] = (*prover[
	sigma.Statement, sigma.Witness, sigma.Commitment, sigma.CommitmentState, sigma.Challenge, sigma.Response,
])(nil)

type prover[X sigma.Statement, W sigma.Witness, A sigma.Commitment, S sigma.CommitmentState, E sigma.Challenge, Z sigma.Response] struct {
	transcript    transcripts.Transcript
	sigmaProtocol sigma.Protocol[X, W, A, S, E, Z]
}

func (p prover[X, W, A, S, E, Z]) Prove(statement X, witness W) (compiler.NIZKPoKProof, error) {
	p.transcript.AppendMessages(statementLabel, p.sigmaProtocol.SerializeStatement(statement))

	a, s, err := p.sigmaProtocol.GenerateCommitment(statement, witness)
	if err != nil {
		return nil, errs.WrapFailed(err, "cannot generate commitment")
	}
	p.transcript.AppendMessages(commitmentLabel, p.sigmaProtocol.SerializeCommitment(a))

	challenge, err := p.transcript.ExtractBytes(challengeLabel, 32)
	if err != nil {
		return nil, errs.WrapFailed(err, "cannot extract bytes from transcript")
	}
	e, err := p.sigmaProtocol.GenerateChallenge(challenge)
	if err != nil {
		return nil, errs.WrapFailed(err, "cannot generate challenge")
	}

	z, err := p.sigmaProtocol.GenerateResponse(statement, witness, s, e)
	if err != nil {
		return nil, errs.WrapFailed(err, "cannot generate response")
	}

	proof := &Proof[A, Z]{
		A: a,
		Z: z,
	}
	return proof, nil
}
