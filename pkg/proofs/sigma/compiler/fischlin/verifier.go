package fischlin

import (
	"encoding/binary"

	"github.com/bronlabs/errs-go/errs"

	"github.com/bronlabs/bron-crypto/pkg/base/serde"
	"github.com/bronlabs/bron-crypto/pkg/hashing"
	"github.com/bronlabs/bron-crypto/pkg/mpc/session"
	"github.com/bronlabs/bron-crypto/pkg/proofs/sigma"
	compiler "github.com/bronlabs/bron-crypto/pkg/proofs/sigma/compiler/internal"
)

var _ compiler.NIVerifier[sigma.Statement] = (*verifier[
	sigma.Statement, sigma.Witness, sigma.Commitment, sigma.State, sigma.Response,
])(nil)

// verifier implements the NIVerifier interface for Fischlin proofs.
type verifier[X sigma.Statement, W sigma.Witness, A sigma.Commitment, S sigma.State, Z sigma.Response] struct {
	ctx           *session.Context
	sigmaProtocol sigma.Protocol[X, W, A, S, Z]
	rho           uint64
	b             uint64
	t             uint64
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
		return errs.Wrap(err).WithMessage("cannot deserialize proof")
	}

	// 2. If m, e, and z do not each have ρ elements, then output 'reject'
	if uint64(len(fischlinProof.A)) != v.rho || uint64(len(fischlinProof.E)) != v.rho || uint64(len(fischlinProof.Z)) != v.rho {
		return ErrInvalid.WithMessage("invalid length")
	}

	v.ctx.Transcript().AppendBytes(rhoLabel, binary.LittleEndian.AppendUint64(nil, v.rho))
	v.ctx.Transcript().AppendBytes(statementLabel, statement.Bytes())
	commonHKey, err := v.ctx.Transcript().ExtractBytes(commonHLabel, 32)
	if err != nil {
		return errs.Wrap(err).WithMessage("cannot extract h")
	}

	commitmentSerialized := make([][]byte, 0)
	for i := range v.rho {
		commitmentSerialized = append(commitmentSerialized, fischlinProof.A[i].Bytes())
	}
	v.ctx.Transcript().AppendBytes(commitmentLabel, commitmentSerialized...)
	v.ctx.Transcript().AppendBytes(challengeLabel, fischlinProof.E...)

	a := make([]byte, 0)
	for i := range v.rho {
		a = append(a, fischlinProof.A[i].Bytes()...)
	}

	// 3. common-h ← H(x, m, sid)
	sessionID := v.ctx.SessionID()
	commonH, err := hashing.Hash(randomOracle, commonHKey, statement.Bytes(), a, sessionID[:])
	if err != nil {
		return errs.Wrap(err).WithMessage("cannot serialise statement")
	}

	// 4. For i ∈ {1, ..., ρ}
	eByteLen := (v.t + 7) / 8
	for i := range v.rho {
		if len(fischlinProof.E[i]) != int(eByteLen) {
			return ErrVerification.WithMessage("invalid proof")
		}
		digest, err := hash(v.b, commonH, i, fischlinProof.E[i], fischlinProof.Z[i].Bytes())
		if err != nil {
			return errs.Wrap(err).WithMessage("cannot compute digest")
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
			return errs.Wrap(err).WithMessage("verification failed")
		}
	}

	responseSerialized := make([][]byte, 0)
	for i := range v.rho {
		responseSerialized = append(responseSerialized, fischlinProof.Z[i].Bytes())
	}
	v.ctx.Transcript().AppendBytes(responseLabel, responseSerialized...)

	// 5. Output 'accept'
	return nil
}
