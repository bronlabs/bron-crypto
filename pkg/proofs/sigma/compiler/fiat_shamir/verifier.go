package fiat_shamir

import (
	"github.com/copperexchange/krypton-primitives/pkg/base/errs"
	"github.com/copperexchange/krypton-primitives/pkg/proofs/sigma"
	"github.com/copperexchange/krypton-primitives/pkg/proofs/sigma/compiler"
	"github.com/copperexchange/krypton-primitives/pkg/transcripts"
)

var _ compiler.NIVerifier[sigma.Statement] = (*verifier[
	sigma.Statement, sigma.Witness, sigma.Commitment, sigma.CommitmentState, sigma.Challenge, sigma.Response,
])(nil)

type verifier[X sigma.Statement, W sigma.Witness, A sigma.Commitment, S sigma.CommitmentState, E sigma.Challenge, Z sigma.Response] struct {
	transcript    transcripts.Transcript
	sigmaProtocol sigma.Protocol[X, W, A, S, E, Z]
}

func (v verifier[X, W, A, S, E, Z]) Verify(statement X, proof compiler.NIZKPoKProof) error {
	if proof == nil {
		return errs.NewIsNil("proof")
	}
	fsProof, ok := proof.(*Proof[A, Z])
	if !ok {
		return errs.NewInvalidType("input proof")
	}

	v.transcript.AppendMessages(statementLabel, v.sigmaProtocol.SerializeStatement(statement))

	a := fsProof.A
	v.transcript.AppendMessages(commitmentLabel, v.sigmaProtocol.SerializeCommitment(a))

	challenge, err := v.transcript.ExtractBytes(challengeLabel, 32)
	if err != nil {
		return errs.WrapFailed(err, "cannot extract bytes from transcript")
	}
	e, err := v.sigmaProtocol.GenerateChallenge(challenge)
	if err != nil {
		return errs.WrapFailed(err, "cannot generate challenge")
	}

	z := fsProof.Z
	err = v.sigmaProtocol.Verify(statement, a, e, z)
	if err != nil {
		return errs.WrapVerificationFailed(err, "verification failed")
	}

	return nil
}
