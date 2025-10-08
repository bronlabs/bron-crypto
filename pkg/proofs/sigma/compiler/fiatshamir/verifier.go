package fiatshamir

import (
	"github.com/bronlabs/bron-crypto/pkg/base/errs"
	"github.com/bronlabs/bron-crypto/pkg/base/serde"
	"github.com/bronlabs/bron-crypto/pkg/proofs/sigma"
	"github.com/bronlabs/bron-crypto/pkg/proofs/sigma/compiler"
	"github.com/bronlabs/bron-crypto/pkg/transcripts"
)

type verifier[X sigma.Statement, W sigma.Witness, A sigma.Commitment, S sigma.State, Z sigma.Response] struct {
	transcript    transcripts.Transcript
	sigmaProtocol sigma.Protocol[X, W, A, S, Z]
}

func (v verifier[X, W, A, S, Z]) Verify(statement X, proofBytes compiler.NIZKPoKProof) error {
	if len(proofBytes) == 0 {
		return errs.NewIsNil("proof")
	}

	fsProof, err := serde.UnmarshalCBOR[*Proof[A, Z]](proofBytes)
	if err != nil {
		return errs.WrapSerialisation(err, "cannot deserialize proof")
	}
	v.transcript.AppendBytes(statementLabel, statement.Bytes())

	a := fsProof.a
	v.transcript.AppendBytes(commitmentLabel, a.Bytes())

	e, err := v.transcript.ExtractBytes(challengeLabel, uint(v.sigmaProtocol.GetChallengeBytesLength()))
	if err != nil {
		return errs.WrapFailed(err, "cannot extract bytes from transcript")
	}

	z := fsProof.z
	if err := v.sigmaProtocol.Verify(statement, a, e, z); err != nil {
		return errs.WrapVerification(err, "verification failed")
	}

	return nil
}
