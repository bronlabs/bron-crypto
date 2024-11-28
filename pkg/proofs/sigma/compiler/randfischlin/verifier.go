package randfischlin

import (
	"github.com/copperexchange/krypton-primitives/pkg/base/bitstring"
	"github.com/copperexchange/krypton-primitives/pkg/base/errs"
	"github.com/copperexchange/krypton-primitives/pkg/base/utils/safecast"
	"github.com/copperexchange/krypton-primitives/pkg/proofs/sigma"
	"github.com/copperexchange/krypton-primitives/pkg/proofs/sigma/compiler"
	"github.com/copperexchange/krypton-primitives/pkg/transcripts"
)

var _ compiler.NIVerifier[sigma.Statement] = (*verifier[
	sigma.Statement, sigma.Witness, sigma.Commitment, sigma.State, sigma.Response,
])(nil)

type verifier[X sigma.Statement, W sigma.Witness, A sigma.Commitment, S sigma.State, Z sigma.Response] struct {
	sessionId     []byte
	transcript    transcripts.Transcript
	sigmaProtocol sigma.Protocol[X, W, A, S, Z]
}

func (v verifier[X, W, A, S, Z]) Verify(statement X, proof compiler.NIZKPoKProof) (err error) {
	if proof == nil {
		return errs.NewIsNil("proof")
	}
	rfProof, ok := proof.(*Proof[A, Z])
	if !ok {
		return errs.NewType("input proof")
	}

	if len(rfProof.A) != R || len(rfProof.E) != R || len(rfProof.Z) != R {
		return errs.NewArgument("invalid length")
	}

	v.transcript.AppendMessages(statementLabel, v.sigmaProtocol.SerializeStatement(statement))
	crs, err := v.transcript.Bind(v.sessionId, transcriptLabel)
	if err != nil {
		return errs.WrapHashing(err, "couldn't bind to transcript")
	}

	commitmentSerialized := make([]byte, 0)
	for i := 0; i < R; i++ {
		commitmentSerialized = append(commitmentSerialized, v.sigmaProtocol.SerializeCommitment(rfProof.A[i])...)
	}
	v.transcript.AppendMessages(commitmentLabel, commitmentSerialized)
	v.transcript.AppendMessages(challengeLabel, rfProof.E...)

	// step 1. parse (a_i, e_i, z_i) for i in [r] and set a = (a_i) for every i in [r]
	a := make([]byte, 0)
	for i := 0; i < R; i++ {
		a = append(a, v.sigmaProtocol.SerializeCommitment(rfProof.A[i])...)
	}

	// step 2. for each i in [r] verify that hash(a, i, e_i, z_i) == 0 and SigmaV(x, (a_i, e_i, z_i)) is true, abort if not
	for i := 0; i < R; i++ {
		digest, err := hash(crs, a, bitstring.ToBytes32LE(safecast.ToInt32(i)), rfProof.E[i], v.sigmaProtocol.SerializeResponse(rfProof.Z[i]))
		if err != nil {
			return errs.WrapHashing(err, "cannot hash")
		}
		if !isAllZeros(digest) {
			return errs.NewVerification("invalid challenge")
		}
		err = v.sigmaProtocol.Verify(statement, rfProof.A[i], rfProof.E[i], rfProof.Z[i])
		if err != nil {
			return errs.WrapVerification(err, "verification failed")
		}
	}

	// step 3. accept
	return nil
}
