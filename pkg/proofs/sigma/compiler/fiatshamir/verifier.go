package fiatshamir

import (
	"github.com/bronlabs/errs-go/errs"

	"github.com/bronlabs/bron-crypto/pkg/base/serde"
	"github.com/bronlabs/bron-crypto/pkg/mpc/session"
	"github.com/bronlabs/bron-crypto/pkg/proofs"
	"github.com/bronlabs/bron-crypto/pkg/proofs/sigma"
	"github.com/bronlabs/bron-crypto/pkg/proofs/sigma/compiler/fiatshamir/zkmodule"
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
		return proofs.ErrInvalidArgument.WithMessage("proof is nil")
	}
	fsProof, err := serde.UnmarshalCBOR[*Proof[A, Z]](proofBytes)
	if err != nil {
		return errs.Wrap(err).WithMessage("cannot deserialize proof")
	}

	if err := zkmodule.Verify(v.ctx, v.sigmaProtocol, statement, fsProof); err != nil {
		return errs.Wrap(err).WithMessage("verification failed")
	}
	return nil
}
