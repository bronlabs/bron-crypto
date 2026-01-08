package fiatshamir

import (
	"github.com/bronlabs/bron-crypto/pkg/base/errs2"
	"github.com/bronlabs/bron-crypto/pkg/base/serde"
	"github.com/bronlabs/bron-crypto/pkg/proofs/sigma"
	compiler "github.com/bronlabs/bron-crypto/pkg/proofs/sigma/compiler/internal"
	"github.com/bronlabs/bron-crypto/pkg/transcripts"
)

// verifier implements the NIVerifier interface for Fiat-Shamir proofs.
type verifier[X sigma.Statement, W sigma.Witness, A sigma.Commitment, S sigma.State, Z sigma.Response] struct {
	transcript    transcripts.Transcript
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
		return errs2.Wrap(err).WithMessage("cannot deserialize proof")
	}
	v.transcript.AppendBytes(statementLabel, statement.Bytes())

	a := fsProof.a
	v.transcript.AppendBytes(commitmentLabel, a.Bytes())

	e, err := v.transcript.ExtractBytes(challengeLabel, uint(v.sigmaProtocol.GetChallengeBytesLength()))
	if err != nil {
		return errs2.Wrap(err).WithMessage("cannot extract bytes from transcript")
	}

	z := fsProof.z
	if err := v.sigmaProtocol.Verify(statement, a, e, z); err != nil {
		return errs2.Wrap(err).WithMessage("verification failed")
	}

	return nil
}
