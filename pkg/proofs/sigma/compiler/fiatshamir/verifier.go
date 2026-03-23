package fiatshamir

import (
	"github.com/bronlabs/errs-go/errs"

	"github.com/bronlabs/bron-crypto/pkg/base/serde"
	"github.com/bronlabs/bron-crypto/pkg/mpc/session"
	"github.com/bronlabs/bron-crypto/pkg/proofs/sigma"
	compiler "github.com/bronlabs/bron-crypto/pkg/proofs/sigma/compiler/internal"
)

// verifier implements the NIVerifier interface for Fiat-Shamir proofs.
type verifier[X sigma.Statement, W sigma.Witness, A sigma.Commitment, S sigma.State, Z sigma.Response] struct {
	ctx           *session.Context
	sigmaProtocol sigma.Protocol[X, W, A, S, Z]
}

// Verify checks that a Fiat-Shamir proof is valid for the given statement.
// It deserializes the proof, recomputes the challenge from the transcript,
// and verifies the sigma protocol relation.
func (v verifier[X, W, A, S, Z]) Verify(statement X, proofBytes compiler.NIZKPoKProof) error {
	if len(proofBytes) == 0 {
		return ErrNil.WithMessage("proof")
	}

	fsProof, err := serde.UnmarshalCBOR[*Proof[A, Z]](proofBytes)
	if err != nil {
		return errs.Wrap(err).WithMessage("cannot deserialize proof")
	}
	v.ctx.Transcript().AppendBytes(statementLabel, statement.Bytes())

	a := fsProof.a
	v.ctx.Transcript().AppendBytes(commitmentLabel, a.Bytes())

	e, err := v.ctx.Transcript().ExtractBytes(challengeLabel, uint(v.sigmaProtocol.GetChallengeBytesLength()))
	if err != nil {
		return errs.Wrap(err).WithMessage("cannot extract bytes from transcript")
	}

	z := fsProof.z
	if err := v.sigmaProtocol.Verify(statement, a, e, z); err != nil {
		return errs.Wrap(err).WithMessage("verification failed")
	}

	return nil
}
