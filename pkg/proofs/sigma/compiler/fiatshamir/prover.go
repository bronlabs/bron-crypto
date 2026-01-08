package fiatshamir

import (
	"github.com/bronlabs/bron-crypto/pkg/base/errs2"
	"github.com/bronlabs/bron-crypto/pkg/base/serde"
	"github.com/bronlabs/bron-crypto/pkg/proofs/sigma"
	compiler "github.com/bronlabs/bron-crypto/pkg/proofs/sigma/compiler/internal"
	"github.com/bronlabs/bron-crypto/pkg/transcripts"
)

// prover implements the NIProver interface for Fiat-Shamir proofs.
type prover[X sigma.Statement, W sigma.Witness, A sigma.Commitment, S sigma.State, Z sigma.Response] struct {
	transcript    transcripts.Transcript
	sigmaProtocol sigma.Protocol[X, W, A, S, Z]
}

// Prove generates a non-interactive proof for the given statement and witness.
// It computes the sigma protocol commitment, derives the challenge from the transcript
// hash, computes the response, and returns the serialized proof.
func (p prover[X, W, A, S, Z]) Prove(statement X, witness W) (compiler.NIZKPoKProof, error) {
	p.transcript.AppendBytes(statementLabel, statement.Bytes())

	a, s, err := p.sigmaProtocol.ComputeProverCommitment(statement, witness)
	if err != nil {
		return nil, errs2.Wrap(err).WithMessage("cannot generate commitment")
	}
	p.transcript.AppendBytes(commitmentLabel, a.Bytes())

	e, err := p.transcript.ExtractBytes(challengeLabel, uint(p.sigmaProtocol.GetChallengeBytesLength()))
	if err != nil {
		return nil, errs2.Wrap(err).WithMessage("cannot extract bytes from transcript")
	}

	z, err := p.sigmaProtocol.ComputeProverResponse(statement, witness, a, s, e)
	if err != nil {
		return nil, errs2.Wrap(err).WithMessage("cannot generate response")
	}

	proof := &Proof[A, Z]{
		a: a,
		z: z,
	}

	proofBytes, err := serde.MarshalCBOR(proof)
	if err != nil {
		return nil, errs2.Wrap(err).WithMessage("cannot serialise proof")
	}
	return proofBytes, nil
}
