package randfischlin_test

import (
	"bytes"
	"testing"

	"github.com/stretchr/testify/require"

	"github.com/bronlabs/bron-crypto/pkg/base/curves/k256"
	"github.com/bronlabs/bron-crypto/pkg/base/datastructures/hashset"
	"github.com/bronlabs/bron-crypto/pkg/base/prng/pcg"
	session_testutils "github.com/bronlabs/bron-crypto/pkg/mpc/session/testutils"
	"github.com/bronlabs/bron-crypto/pkg/mpc/sharing"
	"github.com/bronlabs/bron-crypto/pkg/proofs/dlog/batch_schnorr"
	"github.com/bronlabs/bron-crypto/pkg/proofs/dlog/schnorr"
	"github.com/bronlabs/bron-crypto/pkg/proofs/sigma/compiler/randfischlin"
	"github.com/bronlabs/bron-crypto/pkg/proofs/sigma/compose/sigor"
)

// TestRandFischlin_OrSchnorr compiles an OR of two Schnorr instances, the
// composition the randomised transform exists for: the response carries a
// prover-chosen challenge split, so the protocol has no unique responses but is
// strongly 2-special sound.
func TestRandFischlin_OrSchnorr(t *testing.T) {
	t.Parallel()

	prng := pcg.NewRandomised()
	curve := k256.NewCurve()

	schnorrProtocol, err := schnorr.NewProtocol(curve.Generator(), prng)
	require.NoError(t, err)
	orProtocol, err := sigor.Compose(schnorrProtocol, 2, prng)
	require.NoError(t, err)
	require.Equal(t, uint(2), orProtocol.SpecialSoundness())

	nizk, err := randfischlin.NewCompiler(orProtocol, prng)
	require.NoError(t, err)

	w, err := curve.ScalarField().Random(prng)
	require.NoError(t, err)
	unknown, err := curve.Random(prng)
	require.NoError(t, err)
	statement, err := sigor.ComposeStatements(schnorr.NewStatement(curve.ScalarBaseMul(w)), schnorr.NewStatement(unknown))
	require.NoError(t, err)
	witness := sigor.NewWitness(schnorr.NewWitness(w))

	const proverId, verifierId = 1, 2
	quorum := hashset.NewComparable[sharing.ID](proverId, verifierId).Freeze()
	ctxs := session_testutils.MakeRandomContexts(t, quorum, prng)

	prover, err := nizk.NewProver(ctxs[proverId])
	require.NoError(t, err)
	proof, err := prover.Prove(statement, witness)
	require.NoError(t, err)

	verifier, err := nizk.NewVerifier(ctxs[verifierId])
	require.NoError(t, err)
	require.NoError(t, verifier.Verify(statement, proof))

	proverBytes, err := ctxs[proverId].Transcript().ExtractBytes("final", 32)
	require.NoError(t, err)
	verifierBytes, err := ctxs[verifierId].Transcript().ExtractBytes("final", 32)
	require.NoError(t, err)
	require.True(t, bytes.Equal(proverBytes, verifierBytes))

	// Without a witness for either branch no proof can be produced.
	noWitness, err := curve.ScalarField().Random(prng)
	require.NoError(t, err)
	failingProver, err := nizk.NewProver(ctxs[proverId].Clone())
	require.NoError(t, err)
	_, err = failingProver.Prove(statement, sigor.NewWitness(schnorr.NewWitness(noWitness)))
	require.Error(t, err)
}

// TestRandFischlin_OrBatchSchnorr compiles an OR of two batch Schnorr instances
// with k = 2: each branch is 3-special sound, so the composition is
// (3-1)^2 + 1 = 5-special sound and the compiler must enlarge the hash output
// accordingly.
func TestRandFischlin_OrBatchSchnorr(t *testing.T) {
	t.Parallel()

	const k = 2
	prng := pcg.NewRandomised()
	curve := k256.NewCurve()

	batchProtocol, err := batch_schnorr.NewProtocol(k, curve, prng)
	require.NoError(t, err)
	orProtocol, err := sigor.Compose(batchProtocol, 2, prng)
	require.NoError(t, err)
	require.Equal(t, uint(5), orProtocol.SpecialSoundness())

	nizk, err := randfischlin.NewCompiler(orProtocol, prng)
	require.NoError(t, err)

	ws := make([]*k256.Scalar, k)
	xs := make([]*k256.Point, k)
	unknown := make([]*k256.Point, k)
	for i := range k {
		ws[i], err = curve.ScalarField().Random(prng)
		require.NoError(t, err)
		xs[i] = curve.ScalarBaseMul(ws[i])
		unknown[i], err = curve.Random(prng)
		require.NoError(t, err)
	}
	statement, err := sigor.ComposeStatements(
		batch_schnorr.NewStatement(curve.Generator(), xs...),
		batch_schnorr.NewStatement(curve.Generator(), unknown...),
	)
	require.NoError(t, err)
	witness := sigor.NewWitness(batch_schnorr.NewWitness(ws...))

	const proverId, verifierId = 1, 2
	quorum := hashset.NewComparable[sharing.ID](proverId, verifierId).Freeze()
	ctxs := session_testutils.MakeRandomContexts(t, quorum, prng)

	prover, err := nizk.NewProver(ctxs[proverId])
	require.NoError(t, err)
	proof, err := prover.Prove(statement, witness)
	require.NoError(t, err)

	verifier, err := nizk.NewVerifier(ctxs[verifierId])
	require.NoError(t, err)
	require.NoError(t, verifier.Verify(statement, proof))

	proverBytes, err := ctxs[proverId].Transcript().ExtractBytes("final", 32)
	require.NoError(t, err)
	verifierBytes, err := ctxs[verifierId].Transcript().ExtractBytes("final", 32)
	require.NoError(t, err)
	require.True(t, bytes.Equal(proverBytes, verifierBytes))
}
