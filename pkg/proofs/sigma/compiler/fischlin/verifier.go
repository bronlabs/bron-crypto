package fischlin

import (
	"encoding/binary"

	"github.com/bronlabs/bron-crypto/pkg/base"
	"github.com/bronlabs/bron-crypto/pkg/base/errs"
	"github.com/bronlabs/bron-crypto/pkg/base/serde"
	"github.com/bronlabs/bron-crypto/pkg/base/utils"
	"github.com/bronlabs/bron-crypto/pkg/hashing"
	"github.com/bronlabs/bron-crypto/pkg/network"
	"github.com/bronlabs/bron-crypto/pkg/proofs/sigma"
	"github.com/bronlabs/bron-crypto/pkg/proofs/sigma/compiler"
	"github.com/bronlabs/bron-crypto/pkg/transcripts"
)

var _ compiler.NIVerifier[sigma.Statement] = (*verifier[
	sigma.Statement, sigma.Witness, sigma.Commitment, sigma.State, sigma.Response,
])(nil)

type verifier[X sigma.Statement, W sigma.Witness, A sigma.Commitment, S sigma.State, Z sigma.Response] struct {
	sessionId     network.SID
	transcript    transcripts.Transcript
	sigmaProtocol sigma.Protocol[X, W, A, S, Z]
}

func (v *verifier[X, W, A, S, Z]) Verify(statement X, proofBytes compiler.NIZKPoKProof) error {
	if proofBytes == nil {
		return errs.NewIsNil("proof")
	}

	fischlinProof, err := serde.UnmarshalCBOR[*Proof[A, Z]](proofBytes)
	if err != nil {
		return errs.WrapSerialisation(err, "cannot deserialize proof")
	}

	// 2. If m, e, and z do not each have ρ elements, then output 'reject'
	if uint64(len(fischlinProof.A)) != fischlinProof.Rho || uint64(len(fischlinProof.E)) != fischlinProof.Rho || uint64(len(fischlinProof.Z)) != fischlinProof.Rho {
		return errs.NewArgument("invalid length")
	}
	if fischlinProof.Rho < 2 || fischlinProof.B < 2 {
		return errs.NewArgument("invalid length")
	}

	b := fischlinProof.B - uint64(utils.CeilLog2(int(v.sigmaProtocol.SpecialSoundness())-1))
	if (fischlinProof.Rho * b) < base.ComputationalSecurityBits {
		return errs.NewVerification("verification failed")
	}

	v.transcript.AppendBytes(rhoLabel, binary.LittleEndian.AppendUint64(nil, fischlinProof.Rho))
	v.transcript.AppendBytes(statementLabel, statement.Bytes())

	commitmentSerialized := make([][]byte, 0)
	for i := uint64(0); i < fischlinProof.Rho; i++ {
		commitmentSerialized = append(commitmentSerialized, fischlinProof.A[i].Bytes())
	}
	v.transcript.AppendBytes(commitmentLabel, commitmentSerialized...)
	v.transcript.AppendBytes(challengeLabel, fischlinProof.E...)

	a := make([]byte, 0)
	for i := uint64(0); i < fischlinProof.Rho; i++ {
		a = append(a, fischlinProof.A[i].Bytes()...)
	}

	// 3. common-h ← H(x, m, sid)
	commonH, err := hashing.Hash(randomOracle, statement.Bytes(), a, v.sessionId[:])
	if err != nil {
		return errs.WrapHashing(err, "cannot serialise statement")
	}

	// 4. For i ∈ {1, ..., ρ}
	for i := uint64(0); i < fischlinProof.Rho; i++ {
		digest, err := v.hash(fischlinProof.B, commonH, i, fischlinProof.E[i], fischlinProof.Z[i])
		if err != nil {
			return errs.WrapHashing(err, "cannot compute digest")
		}

		// 4.b. Halt and output 'reject' if Hb(common-h, i, e_i, z_i) != 0
		if !isAllZeros(digest) {
			return errs.NewVerification("invalid challenge")
		}

		// 4.a. Halt and output 'reject' if VerifyProof(x, m_i, e_i, z_i) == 0
		eBytes := make([]byte, v.sigmaProtocol.GetChallengeBytesLength())
		copy(eBytes[len(eBytes)-len(fischlinProof.E[i]):], fischlinProof.E[i])
		err = v.sigmaProtocol.Verify(statement, fischlinProof.A[i], eBytes, fischlinProof.Z[i])
		if err != nil {
			return errs.WrapVerification(err, "verification failed")
		}
	}

	responseSerialized := make([][]byte, 0)
	for i := uint64(0); i < fischlinProof.Rho; i++ {
		responseSerialized = append(responseSerialized, fischlinProof.Z[i].Bytes())
	}
	v.transcript.AppendBytes(responseLabel, responseSerialized...)

	// 5. Output 'accept'
	return nil
}

func (v *verifier[X, W, A, S, Z]) hash(b uint64, commonH []byte, i uint64, challenge sigma.ChallengeBytes, response Z) ([]byte, error) {
	bBytes := b/8 + 1
	bMask := byte((1 << (b % 8)) - 1)
	h, err := hashing.Hash(randomOracle, commonH, binary.LittleEndian.AppendUint64(make([]byte, 8), i), challenge, response.Bytes())
	if err != nil {
		return nil, errs.WrapRandomSample(err, "cannot hash challenge")
	}
	h[bBytes-1] &= bMask
	return h[:bBytes], nil
}
