package fiatShamir

import (
	"github.com/copperexchange/krypton-primitives/pkg/base/errs"
	"github.com/copperexchange/krypton-primitives/pkg/proofs/sigma"
	"github.com/copperexchange/krypton-primitives/pkg/proofs/sigma/compiler"
	"github.com/copperexchange/krypton-primitives/pkg/transcripts"
)

var _ compiler.NIProver[sigma.Statement, sigma.Witness] = (*prover[
	sigma.Statement, sigma.Witness, sigma.Commitment, sigma.State, sigma.Response,
])(nil)

type prover[X sigma.Statement, W sigma.Witness, A sigma.Commitment, S sigma.State, Z sigma.Response] struct {
	transcript    transcripts.Transcript
	sigmaProtocol sigma.Protocol[X, W, A, S, Z]
}

func (p prover[X, W, A, S, Z]) Prove(statement X, witness W) (compiler.NIZKPoKProof, error) {
	p.transcript.AppendMessages(statementLabel, p.sigmaProtocol.SerializeStatement(statement))

	a, s, err := p.sigmaProtocol.ComputeProverCommitment(statement, witness)
	if err != nil {
		return nil, errs.WrapFailed(err, "cannot generate commitment")
	}
	p.transcript.AppendMessages(commitmentLabel, p.sigmaProtocol.SerializeCommitment(a))

	e, err := p.transcript.ExtractBytes(challengeLabel, uint(p.sigmaProtocol.GetChallengeBytesLength()))
	if err != nil {
		return nil, errs.WrapFailed(err, "cannot extract bytes from transcript")
	}

	z, err := p.sigmaProtocol.ComputeProverResponse(statement, witness, a, s, e)
	if err != nil {
		return nil, errs.WrapFailed(err, "cannot generate response")
	}

	proof := &Proof[A, Z]{
		A: a,
		Z: z,
	}
	return proof, nil
}
