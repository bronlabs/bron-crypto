package fischlin

import (
	"encoding/binary"

	"github.com/bronlabs/krypton-primitives/pkg/base"
	"github.com/bronlabs/krypton-primitives/pkg/base/errs"
	"github.com/bronlabs/krypton-primitives/pkg/base/utils"
	"github.com/bronlabs/krypton-primitives/pkg/hashing"
	"github.com/bronlabs/krypton-primitives/pkg/proofs/sigma"
	"github.com/bronlabs/krypton-primitives/pkg/proofs/sigma/compiler"
	"github.com/bronlabs/krypton-primitives/pkg/transcripts"
)

var _ compiler.NIVerifier[sigma.Statement] = (*verifier[
	sigma.Statement, sigma.Witness, sigma.Commitment, sigma.State, sigma.Response,
])(nil)

type verifier[X sigma.Statement, W sigma.Witness, A sigma.Commitment, S sigma.State, Z sigma.Response] struct {
	sessionId     []byte
	transcript    transcripts.Transcript
	sigmaProtocol sigma.Protocol[X, W, A, S, Z]
}

func (v *verifier[X, W, A, S, Z]) Verify(statement X, proof compiler.NIZKPoKProof) error {
	if proof == nil {
		return errs.NewIsNil("proof")
	}

	// 1. Parse π as (m, e, z)
	fischlinProof, ok := proof.(*Proof[A, Z])
	if !ok {
		return errs.NewType("input proof")
	}

	// 2. If m, e, and z do not each have ρ elements, then output reject
	if uint64(len(fischlinProof.A)) != fischlinProof.Rho || uint64(len(fischlinProof.E)) != fischlinProof.Rho || uint64(len(fischlinProof.Z)) != fischlinProof.Rho {
		return errs.NewArgument("invalid length")
	}
	if fischlinProof.Rho < 2 || fischlinProof.B < 2 {
		return errs.NewArgument("invalid length")
	}

	b := fischlinProof.B - uint64(utils.CeilLog2(int(v.sigmaProtocol.SpecialSoundness())-1))
	if (fischlinProof.Rho * b) < base.ComputationalSecurity {
		return errs.NewVerification("verification failed")
	}

	v.transcript.AppendMessages(rhoLabel, binary.LittleEndian.AppendUint64(nil, fischlinProof.Rho))
	v.transcript.AppendMessages(statementLabel, v.sigmaProtocol.SerializeStatement(statement))

	commitmentSerialized := make([][]byte, 0)
	for i := uint64(0); i < fischlinProof.Rho; i++ {
		commitmentSerialized = append(commitmentSerialized, v.sigmaProtocol.SerializeCommitment(fischlinProof.A[i]))
	}
	v.transcript.AppendMessages(commitmentLabel, commitmentSerialized...)
	v.transcript.AppendMessages(challengeLabel, fischlinProof.E...)

	a := make([]byte, 0)
	for i := uint64(0); i < fischlinProof.Rho; i++ {
		a = append(a, v.sigmaProtocol.SerializeCommitment(fischlinProof.A[i])...)
	}

	// 3. common-h ← H(x, m, sid)
	commonH, err := hashing.Hash(base.RandomOracleHashFunction, v.sigmaProtocol.SerializeStatement(statement), a, v.sessionId)
	if err != nil {
		return errs.WrapHashing(err, "cannot serialise statement")
	}

	// 4. For i ∈ {1, ..., ρ}
	for i := uint64(0); i < fischlinProof.Rho; i++ {
		digest, err := v.hash(fischlinProof.B, commonH, i, fischlinProof.E[i], fischlinProof.Z[i])
		if err != nil {
			return errs.WrapHashing(err, "cannot compute digest")
		}

		// 4.b) Halt and output reject if Hb(common-h, i, e_i, z_i) != 0
		if !isAllZeros(digest) {
			return errs.NewVerification("invalid challenge")
		}

		// 4.a) Halt and output reject if VerifyProof(x, m_i, e_i, z_i) == 0
		eBytes := make([]byte, v.sigmaProtocol.GetChallengeBytesLength())
		copy(eBytes[len(eBytes)-len(fischlinProof.E[i]):], fischlinProof.E[i])
		err = v.sigmaProtocol.Verify(statement, fischlinProof.A[i], eBytes, fischlinProof.Z[i])
		if err != nil {
			return errs.WrapVerification(err, "verification failed")
		}
	}

	responseSerialized := make([][]byte, 0)
	for i := uint64(0); i < fischlinProof.Rho; i++ {
		responseSerialized = append(responseSerialized, v.sigmaProtocol.SerializeResponse(fischlinProof.Z[i]))
	}
	v.transcript.AppendMessages(responseLabel, responseSerialized...)

	// 5. Output accept
	return nil
}

func (v *verifier[X, W, A, S, Z]) hash(b uint64, commonH []byte, i uint64, challenge sigma.ChallengeBytes, response Z) ([]byte, error) {
	bBytes := b/8 + 1
	bMask := byte((1 << (b % 8)) - 1)
	h, err := hashing.Hash(base.RandomOracleHashFunction, commonH, binary.LittleEndian.AppendUint64(make([]byte, 8), i), challenge, v.sigmaProtocol.SerializeResponse(response))
	if err != nil {
		return nil, errs.WrapRandomSample(err, "cannot hash challenge")
	}
	h[bBytes-1] &= bMask
	return h[:bBytes], nil
}
