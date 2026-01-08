package fischlin

import (
	"encoding/binary"

	"github.com/bronlabs/bron-crypto/pkg/base"
	"github.com/bronlabs/bron-crypto/pkg/base/errs2"
	"github.com/bronlabs/bron-crypto/pkg/base/serde"
	"github.com/bronlabs/bron-crypto/pkg/base/utils/mathutils"
	"github.com/bronlabs/bron-crypto/pkg/hashing"
	"github.com/bronlabs/bron-crypto/pkg/network"
	"github.com/bronlabs/bron-crypto/pkg/proofs/sigma"
	compiler "github.com/bronlabs/bron-crypto/pkg/proofs/sigma/compiler/internal"
	"github.com/bronlabs/bron-crypto/pkg/transcripts"
)

var _ compiler.NIVerifier[sigma.Statement] = (*verifier[
	sigma.Statement, sigma.Witness, sigma.Commitment, sigma.State, sigma.Response,
])(nil)

// verifier implements the NIVerifier interface for Fischlin proofs.
type verifier[X sigma.Statement, W sigma.Witness, A sigma.Commitment, S sigma.State, Z sigma.Response] struct {
	sessionId     network.SID
	transcript    transcripts.Transcript
	sigmaProtocol sigma.Protocol[X, W, A, S, Z]
}

// Verify checks that a Fischlin proof is valid for the given statement.
// It verifies that all rho challenge/response pairs hash to zero and that
// each sigma protocol transcript is valid.
func (v *verifier[X, W, A, S, Z]) Verify(statement X, proofBytes compiler.NIZKPoKProof) error {
	if proofBytes == nil {
		return ErrNil.WithMessage("proof")
	}

	fischlinProof, err := serde.UnmarshalCBOR[*Proof[A, Z]](proofBytes)
	if err != nil {
		return errs2.Wrap(err).WithMessage("cannot deserialize proof")
	}

	// 2. If m, e, and z do not each have ρ elements, then output 'reject'
	if uint64(len(fischlinProof.A)) != fischlinProof.Rho || uint64(len(fischlinProof.E)) != fischlinProof.Rho || uint64(len(fischlinProof.Z)) != fischlinProof.Rho {
		return ErrInvalid.WithMessage("invalid length")
	}
	if fischlinProof.Rho < 2 || fischlinProof.B < 2 {
		return ErrInvalid.WithMessage("invalid length")
	}

	b := fischlinProof.B - uint64(mathutils.CeilLog2(int(v.sigmaProtocol.SpecialSoundness())-1))
	if (fischlinProof.Rho * b) < base.ComputationalSecurityBits {
		return ErrVerification.WithMessage("insufficient soundness")
	}

	v.transcript.AppendBytes(rhoLabel, binary.LittleEndian.AppendUint64(nil, fischlinProof.Rho))
	v.transcript.AppendBytes(statementLabel, statement.Bytes())
	commonHKey, err := v.transcript.ExtractBytes(commonHLabel, 32)
	if err != nil {
		return errs2.Wrap(err).WithMessage("cannot extract h")
	}

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
	commonH, err := hashing.Hash(randomOracle, commonHKey, statement.Bytes(), a, v.sessionId[:])
	if err != nil {
		return errs2.Wrap(err).WithMessage("cannot serialise statement")
	}

	// 4. For i ∈ {1, ..., ρ}
	for i := uint64(0); i < fischlinProof.Rho; i++ {
		digest, err := hash(fischlinProof.B, commonH, i, fischlinProof.E[i], fischlinProof.Z[i].Bytes())
		if err != nil {
			return errs2.Wrap(err).WithMessage("cannot compute digest")
		}

		// 4.b. Halt and output 'reject' if Hb(common-h, i, e_i, z_i) != 0
		if !isAllZeros(digest) {
			return ErrVerification.WithMessage("invalid challenge")
		}

		// 4.a. Halt and output 'reject' if VerifyProof(x, m_i, e_i, z_i) == 0
		eBytes := make([]byte, v.sigmaProtocol.GetChallengeBytesLength())
		if (len(eBytes) - len(fischlinProof.E[i])) < 0 {
			return ErrVerification.WithMessage("invalid challenge")
		}

		copy(eBytes[len(eBytes)-len(fischlinProof.E[i]):], fischlinProof.E[i])
		err = v.sigmaProtocol.Verify(statement, fischlinProof.A[i], eBytes, fischlinProof.Z[i])
		if err != nil {
			return errs2.Wrap(err).WithMessage("verification failed")
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
