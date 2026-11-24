package signing_mrr21

import (
	"crypto/sha256"
	"maps"
	"slices"
	"testing"

	"github.com/stretchr/testify/require"

	"github.com/bronlabs/bron-crypto/pkg/base"
	"github.com/bronlabs/bron-crypto/pkg/base/curves/k256"
	"github.com/bronlabs/bron-crypto/pkg/base/datastructures/hashmap"
	"github.com/bronlabs/bron-crypto/pkg/base/datastructures/hashset"
	"github.com/bronlabs/bron-crypto/pkg/base/prng/pcg"
	"github.com/bronlabs/bron-crypto/pkg/mpc/dkg/trusteddealer"
	session_testutils "github.com/bronlabs/bron-crypto/pkg/mpc/session/testutils"
	"github.com/bronlabs/bron-crypto/pkg/mpc/sharing"
	"github.com/bronlabs/bron-crypto/pkg/mpc/sharing/accessstructures/threshold"
	"github.com/bronlabs/bron-crypto/pkg/mpc/signatures/ecdsa/dkls23/keygen"
	"github.com/bronlabs/bron-crypto/pkg/network"
	ntu "github.com/bronlabs/bron-crypto/pkg/network/testutils"
	"github.com/bronlabs/bron-crypto/pkg/signatures/ecdsa"
)

type (
	testPoint     = *k256.Point
	testBaseField = *k256.BaseFieldElement
	testScalar    = *k256.Scalar
	testCosigner  = Cosigner[testPoint, testBaseField, testScalar]
)

// TestForgedMultiplicationInputIsCaught checks the binding the rVOLE itself
// does not provide: its consistency check only ties ã to some input a', so a
// cosigner can run it on an input other than the (r_i, sk_i) it committed to
// through R_i and pk_i. Protocol 3.6 binds the two with the Γ^u and Γ^v checks
// of the next round. Here party 1 runs its rVOLE as Alice on (r_1 + 1, sk_1)
// and opens the honest R_1; party 2 must abort and name party 1.
func TestForgedMultiplicationInputIsCaught(t *testing.T) {
	t.Parallel()
	suite, err := ecdsa.NewSuite(k256.NewCurve(), sha256.New)
	require.NoError(t, err)
	prng := pcg.NewRandomised()
	const cheater, honest = sharing.ID(1), sharing.ID(2)
	accessStructure, err := threshold.NewThresholdAccessStructure(2, hashset.NewComparable(cheater, honest).Freeze())
	require.NoError(t, err)
	baseShards, err := trusteddealer.Deal(suite.Curve(), accessStructure, prng)
	require.NoError(t, err)
	ctxs := session_testutils.MakeRandomContexts(t, hashset.NewComparable(cheater, honest).Freeze(), prng)
	cosigners := make(map[sharing.ID]*testCosigner)
	for id, baseShard := range baseShards.Iter() {
		shard, err := keygen.NewShard(baseShard)
		require.NoError(t, err)
		cosigners[id], err = NewCosigner(ctxs[id], suite, shard, pcg.NewRandomised())
		require.NoError(t, err)
	}
	participants := slices.Collect(maps.Values(cosigners))

	r1bOut := make(map[sharing.ID]*Round1Broadcast[testPoint, testBaseField, testScalar])
	r1uOut := make(map[sharing.ID]network.OutgoingUnicasts[*Round1P2P[testPoint, testBaseField, testScalar], *testCosigner])
	for id, c := range cosigners {
		r1bOut[id], r1uOut[id], err = c.Round1()
		require.NoError(t, err)
	}
	r2bIn, r2uIn := ntu.MapO2I(t, participants, r1bOut, r1uOut)

	r2bOut := make(map[sharing.ID]*Round2Broadcast[testPoint, testBaseField, testScalar])
	r2uOut := make(map[sharing.ID]network.OutgoingUnicasts[*Round2P2P[testPoint, testBaseField, testScalar], *testCosigner])
	r2bOut[honest], r2uOut[honest], err = cosigners[honest].Round2(r2bIn[honest], r2uIn[honest])
	require.NoError(t, err)
	r2bOut[cheater], r2uOut[cheater] = forgedRound2(t, cosigners[cheater], r2bIn[cheater], r2uIn[cheater])

	r3bIn, r3uIn := ntu.MapO2I(t, participants, r2bOut, r2uOut)
	_, err = cosigners[honest].Round3(r3bIn[honest], r3uIn[honest], []byte("forged input"))
	require.ErrorIs(t, err, base.ErrAbort)
	require.Equal(t, []sharing.ID{cheater}, base.GetMaliciousIdentities[sharing.ID](err))
}

// forgedRound2 is Round2 with Alice's rVOLE input (r_i + 1, sk_i) in place of
// (r_i, sk_i); everything else, including the opening of the honest R_i, is
// as in the protocol, so the rVOLE's own check passes.
func forgedRound2(t *testing.T, c *testCosigner, r1b network.RoundMessages[*Round1Broadcast[testPoint, testBaseField, testScalar], *testCosigner], r1u network.RoundMessages[*Round1P2P[testPoint, testBaseField, testScalar], *testCosigner]) (*Round2Broadcast[testPoint, testBaseField, testScalar], network.OutgoingUnicasts[*Round2P2P[testPoint, testBaseField, testScalar], *testCosigner]) {
	t.Helper()
	require.NoError(t, network.ValidateIncomingMessages(c, c.core.Ctx().OtherPartiesOrdered(), r1b))
	require.NoError(t, network.ValidateIncomingMessages(c, c.core.Ctx().OtherPartiesOrdered(), r1u))
	for id := range c.core.Ctx().OtherPartiesOrdered() {
		bIn, _ := r1b.Get(id)
		uIn, _ := r1u.Get(id)
		c.core.ReceiveCommitment(id, bIn.BigRCommitment)
		chi, err := c.bob[id].Round2(uIn.MulAliceR1)
		require.NoError(t, err)
		c.core.ReceiveChi(id, chi)
	}
	a, err := c.core.AliceInput()
	require.NoError(t, err)
	forged := []testScalar{a[0].Add(c.core.Suite().ScalarField().One()), a[1]}

	unicasts := hashmap.NewComparable[sharing.ID, *Round2P2P[testPoint, testBaseField, testScalar]]()
	for id := range c.core.Ctx().OtherPartiesOrdered() {
		uIn, _ := r1u.Get(id)
		mulR2, cShare, err := c.alice[id].Round2(uIn.MulBobR1, forged)
		require.NoError(t, err)
		check, err := c.core.CheckValues(id, cShare)
		require.NoError(t, err)
		unicasts.Put(id, &Round2P2P[testPoint, testBaseField, testScalar]{MulR2: mulR2, GammaU: check.GammaU, GammaV: check.GammaV, Psi: check.Psi})
	}
	opening, err := c.core.Opening()
	require.NoError(t, err)
	c.round++
	return &Round2Broadcast[testPoint, testBaseField, testScalar]{BigR: opening.BigR, BigRWitness: opening.BigRWitness, Pk: opening.Pk}, unicasts.Freeze()
}
