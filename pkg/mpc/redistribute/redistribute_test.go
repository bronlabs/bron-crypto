package redistribute_test

import (
	"maps"
	"slices"
	"testing"

	"github.com/stretchr/testify/require"

	"github.com/bronlabs/bron-crypto/pkg/base/algebra"
	"github.com/bronlabs/bron-crypto/pkg/base/curves/k256"
	"github.com/bronlabs/bron-crypto/pkg/base/curves/p256"
	"github.com/bronlabs/bron-crypto/pkg/base/datastructures/hashset"
	"github.com/bronlabs/bron-crypto/pkg/base/mat"
	"github.com/bronlabs/bron-crypto/pkg/base/prng/pcg"
	"github.com/bronlabs/bron-crypto/pkg/base/utils/sliceutils"
	"github.com/bronlabs/bron-crypto/pkg/mpc"
	redistribute "github.com/bronlabs/bron-crypto/pkg/mpc/redistribute"
	"github.com/bronlabs/bron-crypto/pkg/mpc/redistribute/testutils"
	session_testutils "github.com/bronlabs/bron-crypto/pkg/mpc/session/testutils"
	"github.com/bronlabs/bron-crypto/pkg/mpc/sharing"
	"github.com/bronlabs/bron-crypto/pkg/mpc/sharing/accessstructures/hierarchical"
	"github.com/bronlabs/bron-crypto/pkg/mpc/sharing/accessstructures/threshold"
	"github.com/bronlabs/bron-crypto/pkg/mpc/sharing/scheme/kw"
	"github.com/bronlabs/bron-crypto/pkg/mpc/sharing/vss/feldman"
	"github.com/bronlabs/bron-crypto/pkg/network"
	ntu "github.com/bronlabs/bron-crypto/pkg/network/testutils"
)

func Test_HappyPathRedistribute(t *testing.T) {
	t.Parallel()

	testHappyPathAddTTP(t, k256.NewCurve())
	testHappyPathDisjoint(t, p256.NewCurve())
}

func TestRound2RejectsInvalidSubShareVerificationVectorDimensions(t *testing.T) {
	t.Parallel()

	group := k256.NewCurve()
	prng := pcg.NewRandomised()
	field := algebra.StructureMustBeAs[algebra.PrimeField[*k256.Scalar]](group.ScalarStructure())
	secretValue, err := field.Random(prng)
	require.NoError(t, err)

	oldShareholders := hashset.NewComparable[sharing.ID](1, 2, 3).Freeze()
	oldAS, err := threshold.NewThresholdAccessStructure(2, oldShareholders)
	require.NoError(t, err)
	oldShards := testutils.Deal(t, oldAS, group, secretValue)

	newShareholders := hashset.NewComparable[sharing.ID](4, 5, 6, 7).Freeze()
	newAS, err := threshold.NewThresholdAccessStructure(3, newShareholders)
	require.NoError(t, err)

	quorum := oldShareholders.Union(newShareholders)
	ctxs := session_testutils.MakeRandomContexts(t, quorum, prng)
	participants := make(map[sharing.ID]*redistribute.Participant[*k256.Point, *k256.Scalar])
	for id := range quorum.Iter() {
		p, err := redistribute.NewParticipant(ctxs[id], 1, oldShareholders, oldShards[id], newAS, pcg.NewRandomised())
		require.NoError(t, err)
		participants[id] = p
	}

	r1bo := make(map[sharing.ID]*redistribute.Round1Broadcast[*k256.Point, *k256.Scalar])
	r1uo := make(map[sharing.ID]network.RoundMessages[*redistribute.Round1P2P[*k256.Point, *k256.Scalar], *redistribute.Participant[*k256.Point, *k256.Scalar]])
	for id, p := range participants {
		r1bo[id], r1uo[id], err = p.Round1()
		require.NoError(t, err)
	}

	r2bi, r2ui := ntu.MapO2I(t, slices.Collect(maps.Values(participants)), r1bo, r1uo)
	r2bo := make(map[sharing.ID]*redistribute.Round2Broadcast[*k256.Point, *k256.Scalar])
	for id, p := range participants {
		r2bo[id], _, err = p.Round2(r2bi[id], r2ui[id])
		require.NoError(t, err)
	}

	rows, _ := r2bo[1].NextVerificationVectorContribution.Value().Dimensions()
	wrongModule, err := mat.NewModuleValuedColumnVectorModule(uint(rows+1), group)
	require.NoError(t, err)
	wrongEntries := make([]*k256.Point, rows+1)
	for i := range wrongEntries {
		wrongEntries[i] = group.Generator()
	}
	wrongVVV, err := wrongModule.NewRowMajor(wrongEntries...)
	require.NoError(t, err)
	wrongVV, err := feldman.NewVerificationVector(wrongVVV, nil)
	require.NoError(t, err)

	corrupted := &redistribute.Round2Broadcast[*k256.Point, *k256.Scalar]{
		PrevMSP:                            r2bo[1].PrevMSP,
		PrevVerificationVector:             r2bo[1].PrevVerificationVector,
		ZeroVerificationVector:             r2bo[1].ZeroVerificationVector,
		NextVerificationVectorContribution: wrongVV,
	}

	err = corrupted.Validate(participants[4], 1)
	require.Error(t, err)
}

// This simulates adding a new TTP and converting the threshold access structure to a hierarchical one
func testHappyPathAddTTP[G algebra.PrimeGroupElement[G, S], S algebra.PrimeFieldElement[S]](tb testing.TB, group algebra.PrimeGroup[G, S]) {
	tb.Helper()

	const BRON sharing.ID = 1
	const CLIENT sharing.ID = 2
	const TTP1 sharing.ID = 3
	const TTP2 sharing.ID = 4

	prng := pcg.NewRandomised()
	field := algebra.StructureMustBeAs[algebra.PrimeField[S]](group.ScalarStructure())
	secretValue, err := field.Random(prng)
	require.NoError(tb, err)

	oldShareholders := hashset.NewComparable(BRON, CLIENT, TTP1).Freeze()
	oldAS, err := threshold.NewThresholdAccessStructure(2, oldShareholders)
	require.NoError(tb, err)
	require.NoError(tb, err)
	oldShards := testutils.Deal(tb, oldAS, group, secretValue)

	newShareholders := hashset.NewComparable(BRON, CLIENT, TTP1, TTP2).Freeze()
	newAS, err := hierarchical.NewHierarchicalConjunctiveThresholdAccessStructure(
		hierarchical.WithLevel(1, BRON, CLIENT),
		hierarchical.WithLevel(2, TTP1, TTP2),
	)
	require.NoError(tb, err)

	ctxs := session_testutils.MakeRandomContexts(tb, newShareholders, prng)
	participants := make(map[sharing.ID]*redistribute.Participant[G, S])
	for id := range newAS.Shareholders().Iter() {
		p, err := redistribute.NewParticipant(ctxs[id], BRON, oldShareholders, oldShards[id], newAS, pcg.NewRandomised())
		require.NoError(tb, err)
		participants[id] = p
	}

	r1bo := make(map[sharing.ID]*redistribute.Round1Broadcast[G, S])
	r1uo := make(map[sharing.ID]network.RoundMessages[*redistribute.Round1P2P[G, S], *redistribute.Participant[G, S]])
	for id, p := range participants {
		r1bo[id], r1uo[id], err = p.Round1()
		require.NoError(tb, err)
	}

	r2bi, r2ui := ntu.MapO2I(tb, slices.Collect(maps.Values(participants)), r1bo, r1uo)
	r2bo := make(map[sharing.ID]*redistribute.Round2Broadcast[G, S])
	r2uo := make(map[sharing.ID]network.RoundMessages[*redistribute.Round2P2P[G, S], *redistribute.Participant[G, S]])
	for id, p := range participants {
		r2bo[id], r2uo[id], err = p.Round2(r2bi[id], r2ui[id])
		require.NoError(tb, err)
	}

	r3bi, r3ui := ntu.MapO2I(tb, slices.Collect(maps.Values(participants)), r2bo, r2uo)
	newShards := make(map[sharing.ID]*mpc.BaseShard[G, S])
	for id, p := range participants {
		newShards[id], err = p.Round3(r3bi[id], r3ui[id])
		require.NoError(tb, err)
	}

	// new shares are valid
	scheme, err := feldman.NewScheme(group, newAS)
	require.NoError(tb, err)
	for _, shard := range newShards {
		err := scheme.Verify(shard.Share(), shard.VerificationVector())
		require.NoError(tb, err)
	}

	// new shares are refreshed but keep the same public key
	for id := range oldAS.Shareholders().Iter() {
		require.False(tb, oldShards[id].Share().Equal(newShards[id].Share()))
		require.False(tb, oldShards[id].VerificationVector().Equal(newShards[id].VerificationVector()))

		oldPk, _ := oldShards[id].VerificationVector().Value().Get(0, 0)
		newPk, _ := newShards[id].VerificationVector().Value().Get(0, 0)
		require.True(tb, oldPk.Equal(newPk))
	}

	// new shares reconstruct to the same value
	c := 0
	for ids := range sliceutils.KCoveringCombinations(newAS.Shareholders().List(), 1) {
		if scheme.MSP().Accepts(ids...) {
			shares := sliceutils.Map(ids, func(id sharing.ID) *kw.Share[S] { return newShards[id].Share() })
			newSecret, err := scheme.Reconstruct(shares...)
			require.NoError(tb, err)
			require.True(tb, newSecret.Value().Equal(secretValue))
			c++
		}
	}
	// c should be 10:
	//  (bron, client), (bron, ttp1), (bron, ttp2), (client, ttp1), (client, ttp2)
	//  (bron, client, ttp1), (bron, client, ttp2), (bron, ttp1, ttp2), (client, ttp1, ttp2)
	//  (bron, client, ttp1, ttp2)
	require.Equal(tb, 10, c)
}

// This simulates adding a new TTP and converting the threshold access structure to a hierarchical one
func testHappyPathDisjoint[G algebra.PrimeGroupElement[G, S], S algebra.PrimeFieldElement[S]](tb testing.TB, group algebra.PrimeGroup[G, S]) {
	tb.Helper()

	prng := pcg.NewRandomised()
	field := algebra.StructureMustBeAs[algebra.PrimeField[S]](group.ScalarStructure())
	secretValue, err := field.Random(prng)
	require.NoError(tb, err)

	oldShareholders := hashset.NewComparable[sharing.ID](1, 2, 3).Freeze()
	oldAS, err := threshold.NewThresholdAccessStructure(2, oldShareholders)
	require.NoError(tb, err)
	oldShards := testutils.Deal(tb, oldAS, group, secretValue)

	newShareholders := hashset.NewComparable[sharing.ID](4, 5, 6, 7).Freeze()
	newAS, err := threshold.NewThresholdAccessStructure(3, newShareholders)
	require.NoError(tb, err)

	quorum := oldShareholders.Union(newShareholders)
	ctxs := session_testutils.MakeRandomContexts(tb, quorum, prng)
	participants := make(map[sharing.ID]*redistribute.Participant[G, S])
	for id := range quorum.Iter() {
		p, err := redistribute.NewParticipant(ctxs[id], 1, oldShareholders, oldShards[id], newAS, pcg.NewRandomised())
		require.NoError(tb, err)
		participants[id] = p
	}

	r1bo := make(map[sharing.ID]*redistribute.Round1Broadcast[G, S])
	r1uo := make(map[sharing.ID]network.RoundMessages[*redistribute.Round1P2P[G, S], *redistribute.Participant[G, S]])
	for id, p := range participants {
		r1bo[id], r1uo[id], err = p.Round1()
		require.NoError(tb, err)
	}

	r2bi, r2ui := ntu.MapO2I(tb, slices.Collect(maps.Values(participants)), r1bo, r1uo)
	r2bo := make(map[sharing.ID]*redistribute.Round2Broadcast[G, S])
	r2uo := make(map[sharing.ID]network.RoundMessages[*redistribute.Round2P2P[G, S], *redistribute.Participant[G, S]])
	for id, p := range participants {
		r2bo[id], r2uo[id], err = p.Round2(r2bi[id], r2ui[id])
		require.NoError(tb, err)
	}

	r3bi, r3ui := ntu.MapO2I(tb, slices.Collect(maps.Values(participants)), r2bo, r2uo)
	newShards := make(map[sharing.ID]*mpc.BaseShard[G, S])
	for id, p := range participants {
		newShards[id], err = p.Round3(r3bi[id], r3ui[id])
		require.NoError(tb, err)
	}

	// new shares are valid
	scheme, err := feldman.NewScheme(group, newAS)
	require.NoError(tb, err)
	for id := range newAS.Shareholders().Iter() {
		shard, ok := newShards[id]
		require.True(tb, ok)
		err := scheme.Verify(shard.Share(), shard.VerificationVector())
		require.NoError(tb, err)
	}

	// new shares reconstruct to the same value
	for ids := range sliceutils.KCoveringCombinations(newAS.Shareholders().List(), 3) {
		if scheme.MSP().Accepts(ids...) {
			shares := sliceutils.Map(ids, func(id sharing.ID) *kw.Share[S] { return newShards[id].Share() })
			newSecret, err := scheme.Reconstruct(shares...)
			require.NoError(tb, err)
			require.True(tb, newSecret.Value().Equal(secretValue))
		}
	}
}
