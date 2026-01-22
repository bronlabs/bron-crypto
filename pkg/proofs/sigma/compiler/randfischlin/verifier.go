package randfischlin

import (
	"encoding/binary"
	"encoding/hex"
	"fmt"

	"github.com/bronlabs/bron-crypto/pkg/base/serde"
	"github.com/bronlabs/bron-crypto/pkg/network"
	"github.com/bronlabs/bron-crypto/pkg/proofs/sigma"
	compiler "github.com/bronlabs/bron-crypto/pkg/proofs/sigma/compiler/internal"
	"github.com/bronlabs/bron-crypto/pkg/transcripts"
	"github.com/bronlabs/errs-go/errs"
)

var _ compiler.NIVerifier[sigma.Statement] = (*verifier[
	sigma.Statement, sigma.Witness, sigma.Commitment, sigma.State, sigma.Response,
])(nil)

// verifier implements the NIVerifier interface for randomised Fischlin proofs.
type verifier[X sigma.Statement, W sigma.Witness, A sigma.Commitment, S sigma.State, Z sigma.Response] struct {
	sessionID     network.SID
	transcript    transcripts.Transcript
	sigmaProtocol sigma.Protocol[X, W, A, S, Z]
}

// Verify checks that a randomised Fischlin proof is valid for the given statement.
// It verifies that all R challenge/response pairs hash to zero and that each
// sigma protocol transcript is valid.
func (v verifier[X, W, A, S, Z]) Verify(statement X, proofBytes compiler.NIZKPoKProof) (err error) {
	if proofBytes == nil {
		return ErrNil.WithMessage("proof")
	}

	rfProof, err := serde.UnmarshalCBOR[*Proof[A, Z]](proofBytes)
	if err != nil {
		return errs.Wrap(err).WithMessage("input proof")
	}

	if len(rfProof.A) != R || len(rfProof.E) != R || len(rfProof.Z) != R {
		return ErrInvalid.WithMessage("invalid length")
	}

	v.transcript.AppendDomainSeparator(fmt.Sprintf("%s-%s", transcriptLabel, hex.EncodeToString(v.sessionID[:])))
	crs, err := v.transcript.ExtractBytes(crsLabel, 32)
	if err != nil {
		return errs.Wrap(err).WithMessage("cannot extract crs")
	}
	v.transcript.AppendBytes(statementLabel, statement.Bytes())

	commitmentSerialized := make([]byte, 0)
	for i := range R {
		commitmentSerialized = append(commitmentSerialized, rfProof.A[i].Bytes()...)
	}
	v.transcript.AppendBytes(commitmentLabel, commitmentSerialized)
	v.transcript.AppendBytes(challengeLabel, rfProof.E...)

	// step 1. parse (a_i, e_i, z_i) for i in [r] and set a = (a_i) for every i in [r]
	a := make([]byte, 0)
	for i := range R {
		a = append(a, rfProof.A[i].Bytes()...)
	}

	// step 2. for each i in [r] verify that hash(a, i, e_i, z_i) == 0 and SigmaV(x, (a_i, e_i, z_i)) is true, abort if not
	for i := range R {
		digest, err := hash(crs, a, binary.LittleEndian.AppendUint64(nil, uint64(i)), rfProof.E[i], rfProof.Z[i].Bytes())
		if err != nil {
			return errs.Wrap(err).WithMessage("cannot hash")
		}
		if !isAllZeros(digest) {
			return ErrVerification.WithMessage("invalid challenge")
		}
		err = v.sigmaProtocol.Verify(statement, rfProof.A[i], rfProof.E[i], rfProof.Z[i])
		if err != nil {
			return errs.Wrap(err).WithMessage("verification failed")
		}
	}

	// step 3. accept
	return nil
}
