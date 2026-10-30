package randfischlin

import (
	"encoding/binary"
	"encoding/hex"
	"fmt"

	"github.com/bronlabs/errs-go/errs"

	"github.com/bronlabs/bron-crypto/pkg/base/serde"
	"github.com/bronlabs/bron-crypto/pkg/mpc/session"
	"github.com/bronlabs/bron-crypto/pkg/proofs"
	"github.com/bronlabs/bron-crypto/pkg/proofs/sigma"
	compiler "github.com/bronlabs/bron-crypto/pkg/proofs/sigma/compiler/internal"
)

// Verifier implements the NIVerifier interface for randomised Fischlin proofs.
type Verifier[X sigma.Statement, W sigma.Witness, A sigma.Commitment, S sigma.State, Z sigma.Response] struct {
	params

	ctx           *session.Context
	sigmaProtocol sigma.Protocol[X, W, A, S, Z]
}

// Verify checks that a randomised Fischlin proof is valid for the given statement.
// It verifies that the proof has exactly r repetitions, that every challenge has
// the canonical length, that all r challenge/response pairs hash to zero and that
// each sigma protocol transcript is valid.
func (v *Verifier[X, W, A, S, Z]) Verify(statement X, proofBytes compiler.NIZKPoKProof) error {
	if len(proofBytes) == 0 {
		return proofs.ErrInvalidArgument.WithMessage("proof is nil")
	}

	rfProof, err := serde.UnmarshalCBOR[*Proof[A, Z]](proofBytes)
	if err != nil {
		return errs.Join(proofs.ErrInvalidArgument, errs.Wrap(err)).WithMessage("input proof")
	}
	if rfProof == nil {
		return proofs.ErrInvalidArgument.WithMessage("proof is nil")
	}

	if len(rfProof.A) != v.r || len(rfProof.E) != v.r || len(rfProof.Z) != v.r {
		return proofs.ErrInvalidArgument.WithMessage("invalid length")
	}

	sessionID := v.ctx.SessionID()
	v.ctx.Transcript().AppendDomainSeparator(fmt.Sprintf("%s-%s", transcriptLabel, hex.EncodeToString(sessionID[:])))
	v.ctx.Transcript().AppendBytes(statementLabel, statement.Bytes())
	crs, err := v.ctx.Transcript().ExtractBytes(crsLabel, 32)
	if err != nil {
		return errs.Wrap(err).WithMessage("cannot extract crs")
	}

	commitmentSerialized := make([]byte, 0)
	for i := range v.r {
		commitmentSerialized = append(commitmentSerialized, rfProof.A[i].Bytes()...)
	}
	v.ctx.Transcript().AppendBytes(commitmentLabel, commitmentSerialized)
	v.ctx.Transcript().AppendBytes(challengeLabel, rfProof.E...)

	// step 1. parse (a_i, e_i, z_i) for i in [r] and set a = (a_i) for every i in [r]
	a := make([]byte, 0)
	for i := range v.r {
		a = append(a, rfProof.A[i].Bytes()...)
	}

	// step 2. for each i in [r] verify that hash(a, i, e_i, z_i) == 0 and SigmaV(x, (a_i, e_i, z_i)) is true, abort if not
	for i := range v.r {
		// The row hash is computed over the raw bytes of e_i, so only the canonical
		// fixed-length encoding may be accepted. A sigma protocol may map differently
		// encoded byte strings (e.g. the same value with leading zero bytes) to the same
		// challenge; if such encodings were accepted, a prover could re-encode a single
		// accepting transcript to obtain unboundedly many random oracle queries per row
		// and pass the hash-to-zero check without ever answering two distinct challenges,
		// which breaks straight-line extraction.
		if len(rfProof.E[i]) != v.sigmaProtocol.GetChallengeBytesLength() {
			return proofs.ErrInvalidArgument.WithMessage("invalid challenge length")
		}
		digest, err := v.hash(crs, a, binary.LittleEndian.AppendUint64(nil, uint64(i)), rfProof.E[i], rfProof.Z[i].Bytes(), statement.Bytes())
		if err != nil {
			return errs.Wrap(err).WithMessage("cannot hash")
		}
		if !isAllZeros(digest) {
			return proofs.ErrVerificationFailed.WithMessage("invalid challenge")
		}
		err = v.sigmaProtocol.Verify(statement, rfProof.A[i], rfProof.E[i], rfProof.Z[i])
		if err != nil {
			return errs.Wrap(err).WithMessage("verification failed")
		}
	}

	// step 3. accept
	return nil
}
