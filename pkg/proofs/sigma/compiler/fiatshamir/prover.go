package fiatshamir

import (
	"github.com/bronlabs/errs-go/errs"

	"github.com/bronlabs/bron-crypto/pkg/base/serde"
	"github.com/bronlabs/bron-crypto/pkg/mpc/session"
	"github.com/bronlabs/bron-crypto/pkg/proofs/sigma"
	compiler "github.com/bronlabs/bron-crypto/pkg/proofs/sigma/compiler/internal"
)

// prover implements the NIProver interface for Fiat-Shamir proofs.
type prover[X sigma.Statement, W sigma.Witness, A sigma.Commitment, S sigma.State, Z sigma.Response] struct {
	ctx           *session.Context
	sigmaProtocol sigma.Protocol[X, W, A, S, Z]
}

// Prove generates a non-interactive proof for the given statement and witness.
// It computes the sigma protocol commitment, derives the challenge from the transcript
// hash, computes the response, and returns the serialised proof.
func (p prover[X, W, A, S, Z]) Prove(statement X, witness W) (compiler.NIZKPoKProof, error) {
	p.ctx.Transcript().AppendBytes(statementLabel, statement.Bytes())

	a, s, err := p.sigmaProtocol.ComputeProverCommitment(statement, witness)
	if err != nil {
		return nil, errs.Wrap(err).WithMessage("cannot generate commitment")
	}
	p.ctx.Transcript().AppendBytes(commitmentLabel, a.Bytes())

	e, err := p.ctx.Transcript().ExtractBytes(challengeLabel, uint(p.sigmaProtocol.GetChallengeBytesLength()))
	if err != nil {
		return nil, errs.Wrap(err).WithMessage("cannot extract bytes from transcript")
	}

	z, err := p.sigmaProtocol.ComputeProverResponse(statement, witness, a, s, e)
	if err != nil {
		return nil, errs.Wrap(err).WithMessage("cannot generate response")
	}

	proof := &Proof[A, Z]{
		a: a,
		z: z,
	}

	proofBytes, err := serde.MarshalCBOR(proof)
	if err != nil {
		return nil, errs.Wrap(err).WithMessage("cannot serialise proof")
	}
	return proofBytes, nil
}
