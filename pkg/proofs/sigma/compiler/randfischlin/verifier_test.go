//nolint:testpackage // Need unexported labels etc for testing.
package randfischlin

import (
	"encoding/binary"
	"encoding/hex"
	"fmt"
	"io"
	"testing"

	"github.com/stretchr/testify/require"

	"github.com/bronlabs/bron-crypto/pkg/base/curves/k256"
	"github.com/bronlabs/bron-crypto/pkg/base/datastructures/hashset"
	"github.com/bronlabs/bron-crypto/pkg/base/prng/pcg"
	"github.com/bronlabs/bron-crypto/pkg/base/serde"
	session_testutils "github.com/bronlabs/bron-crypto/pkg/mpc/session/testutils"
	"github.com/bronlabs/bron-crypto/pkg/mpc/sharing"
	"github.com/bronlabs/bron-crypto/pkg/proofs"
	"github.com/bronlabs/bron-crypto/pkg/proofs/dlog/schnorr"
)

// TestVerifier_RejectsNonCanonicalChallengeEncoding is a regression test for a
// forgery that needs no witness: the forger builds one simulated transcript per
// row and then re-encodes the challenge with leading zero bytes (a different
// random oracle query that the sigma protocol parses to the same scalar) until
// the row hashes to zero. The verifier must reject any challenge whose length
// is not the sigma protocol's canonical challenge length.
func TestVerifier_RejectsNonCanonicalChallengeEncoding(t *testing.T) {
	t.Parallel()

	curve := k256.NewCurve()
	prng := pcg.NewRandomised()

	schnorrProtocol, err := schnorr.NewProtocol(curve.Generator(), prng)
	require.NoError(t, err)
	nizk, err := NewCompiler(schnorrProtocol, prng)
	require.NoError(t, err)

	const proverId, verifierId = 1, 2
	quorum := hashset.NewComparable[sharing.ID](proverId, verifierId).Freeze()
	ctxs := session_testutils.MakeRandomContexts(t, quorum, prng)

	// The forger plays the prover role, so it shares the prover's transcript setup.
	_, err = nizk.NewProver(ctxs[proverId])
	require.NoError(t, err)
	verifier, err := nizk.NewVerifier(ctxs[verifierId])
	require.NoError(t, err)

	// A statement whose discrete log is unknown to everyone.
	x, err := curve.Random(prng)
	require.NoError(t, err)
	statement := schnorr.NewStatement(x)

	// Replicate the honest prover's transcript steps to obtain the crs.
	ctx := ctxs[proverId]
	sessionID := ctx.SessionID()
	ctx.Transcript().AppendDomainSeparator(fmt.Sprintf("%s-%s", transcriptLabel, hex.EncodeToString(sessionID[:])))
	ctx.Transcript().AppendBytes(statementLabel, statement.Bytes())
	crs, err := ctx.Transcript().ExtractBytes(crsLabel, 32)
	require.NoError(t, err)

	type A = *schnorr.Commitment[*k256.Point, *k256.Scalar]
	type Z = *schnorr.Response[*k256.Scalar]
	eLen := schnorrProtocol.GetChallengeBytesLength()
	aI := make([]A, nizk.r)
	zI := make([]Z, nizk.r)
	eI := make([][]byte, nizk.r)
	a := make([]byte, 0)
	for i := range nizk.r {
		eI[i] = make([]byte, eLen)
		_, err = io.ReadFull(prng, eI[i][:nizk.tBytes])
		require.NoError(t, err)
		// One accepting transcript per row, obtained from the simulator.
		aI[i], zI[i], err = schnorrProtocol.RunSimulator(statement, eI[i])
		require.NoError(t, err)
		a = append(a, aI[i].Bytes()...)
	}

	for i := range nizk.r {
		e := eI[i]
		for {
			digest, err := nizk.hash(crs, a, binary.LittleEndian.AppendUint64(nil, uint64(i)), e, zI[i].Bytes(), statement.Bytes())
			require.NoError(t, err)
			if isAllZeros(digest) {
				eI[i] = e
				break
			}
			// Same challenge value, different random oracle query.
			e = append([]byte{0x00}, e...)
		}
	}

	proofBytes, err := serde.MarshalCBOR(&Proof[A, Z]{A: aI, E: eI, Z: zI})
	require.NoError(t, err)

	err = verifier.Verify(statement, proofBytes)
	require.ErrorIs(t, err, proofs.ErrInvalidArgument)
}
