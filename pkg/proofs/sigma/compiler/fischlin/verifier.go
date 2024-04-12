package fischlin

import (
	"encoding/binary"

	"github.com/copperexchange/krypton-primitives/pkg/base"
	"github.com/copperexchange/krypton-primitives/pkg/base/bitstring"
	"github.com/copperexchange/krypton-primitives/pkg/base/errs"
	"github.com/copperexchange/krypton-primitives/pkg/base/utils"
	"github.com/copperexchange/krypton-primitives/pkg/hashing"
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

func (v *verifier[X, W, A, S, Z]) Verify(statement X, proof compiler.NIZKPoKProof) error {
	if proof == nil {
		return errs.NewIsNil("proof")
	}
	fischlinProof, ok := proof.(*Proof[A, Z])
	if !ok {
		return errs.NewType("input proof")
	}

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

	v.transcript.AppendMessages(rhoLabel, bitstring.ToBytesLE(int(fischlinProof.Rho)))
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

	commonH, err := hashing.Hash(base.RandomOracleHashFunction, v.sigmaProtocol.SerializeStatement(statement), a, v.sessionId)
	if err != nil {
		return errs.WrapHashing(err, "cannot serialise statement")
	}

	for i := uint64(0); i < fischlinProof.Rho; i++ {
		digest, err := v.hash(fischlinProof.B, commonH, i, fischlinProof.E[i], fischlinProof.Z[i])
		if err != nil {
			return errs.WrapHashing(err, "cannot compute digest")
		}

		if !isAllZeros(digest) {
			return errs.NewVerification("invalid challenge")
		}

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
