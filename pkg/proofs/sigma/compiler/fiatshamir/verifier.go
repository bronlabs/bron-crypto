package fiatshamir

import (
	"github.com/bronlabs/bron-crypto/pkg/base/errs"
	"github.com/bronlabs/bron-crypto/pkg/proofs/sigma"
	"github.com/bronlabs/bron-crypto/pkg/proofs/sigma/compiler"
	"github.com/bronlabs/bron-crypto/pkg/transcripts"
)

var _ compiler.NIVerifier[sigma.Statement] = (*verifier[
	sigma.Statement, sigma.Witness, sigma.Commitment, sigma.State, sigma.Response,
])(nil)

type verifier[X sigma.Statement, W sigma.Witness, A sigma.Commitment, S sigma.State, Z sigma.Response] struct {
	transcript    transcripts.Transcript
	sigmaProtocol sigma.Protocol[X, W, A, S, Z]
}

func (v verifier[X, W, A, S, Z]) Verify(statement X, proof compiler.NIZKPoKProof) error {
	if proof == nil {
		return errs.NewIsNil("proof")
	}
	fsProof, ok := proof.(*Proof[A, Z])
	if !ok {
		return errs.NewType("input proof")
	}

	v.transcript.AppendBytes(statementLabel, v.sigmaProtocol.SerializeStatement(statement))

	a := fsProof.A
	v.transcript.AppendBytes(commitmentLabel, v.sigmaProtocol.SerializeCommitment(a))

	e, err := v.transcript.ExtractBytes(challengeLabel, uint(v.sigmaProtocol.GetChallengeBytesLength()))
	if err != nil {
		return errs.WrapFailed(err, "cannot extract bytes from transcript")
	}

	z := fsProof.Z
	if err := v.sigmaProtocol.Verify(statement, a, e, z); err != nil {
		return errs.WrapVerification(err, "verification failed")
	}

	return nil
}
