package fiatshamir

import (
	"github.com/bronlabs/bron-crypto/pkg/base/errs"
	"github.com/bronlabs/bron-crypto/pkg/proofs/sigma"
	"github.com/bronlabs/bron-crypto/pkg/proofs/sigma/compiler"
	"github.com/bronlabs/bron-crypto/pkg/transcripts"
	"github.com/fxamacker/cbor/v2"
)

type prover[X sigma.Statement, W sigma.Witness, A sigma.Commitment, S sigma.State, Z sigma.Response] struct {
	transcript    transcripts.Transcript
	sigmaProtocol sigma.Protocol[X, W, A, S, Z]
}

func (p prover[X, W, A, S, Z]) Prove(statement X, witness W) (compiler.NIZKPoKProof, error) {
	p.transcript.AppendBytes(statementLabel, statement.Bytes())

	a, s, err := p.sigmaProtocol.ComputeProverCommitment(statement, witness)
	if err != nil {
		return nil, errs.WrapFailed(err, "cannot generate commitment")
	}
	p.transcript.AppendBytes(commitmentLabel, a.Bytes())

	e, err := p.transcript.ExtractBytes(challengeLabel, uint(p.sigmaProtocol.GetChallengeBytesLength()))
	if err != nil {
		return nil, errs.WrapFailed(err, "cannot extract bytes from transcript")
	}

	z, err := p.sigmaProtocol.ComputeProverResponse(statement, witness, a, s, e)
	if err != nil {
		return nil, errs.WrapFailed(err, "cannot generate response")
	}

	proof := &Proof[A, Z]{
		a: a,
		z: z,
	}
	proofBytes, err := cbor.Marshal(proof)
	if err != nil {
		return nil, errs.WrapSerialisation(err, "cannot serialize proof")
	}
	return proofBytes, nil
}
