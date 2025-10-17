package recovery_test

import (
	crand "crypto/rand"
	"testing"

	"github.com/bronlabs/bron-crypto/pkg/base/curves/k256"
	"github.com/bronlabs/bron-crypto/pkg/base/datastructures/hashset"
	"github.com/bronlabs/bron-crypto/pkg/network"
	"github.com/bronlabs/bron-crypto/pkg/network/testutils"
	"github.com/bronlabs/bron-crypto/pkg/threshold/recovery"
	"github.com/bronlabs/bron-crypto/pkg/threshold/sharing"
	"github.com/bronlabs/bron-crypto/pkg/threshold/sharing/feldman"
	"github.com/stretchr/testify/require"
)

func Test_HappyPath(t *testing.T) {
	t.Parallel()

	const THRESHOLD = 2
	const TOTAL = 4
	prng := crand.Reader
	shareholdersList := []sharing.ID{1, 2, 3, 4}
	shareholders := hashset.NewComparable(shareholdersList...).Freeze()
	group := k256.NewCurve()
	as, err := feldman.NewAccessStructure(THRESHOLD, hashset.NewComparable(shareholdersList...).Freeze())
	require.NoError(t, err)
	scheme, err := feldman.NewScheme(group.Generator(), THRESHOLD, shareholders)
	require.NoError(t, err)
	dealerOutput, _, err := scheme.DealRandom(prng)
	verificationVector := dealerOutput.VerificationMaterial()

	const MISLAYER_ID = 3
	quroumList := []sharing.ID{2, 3, 4}
	quorum := hashset.NewComparable[sharing.ID](quroumList...).Freeze()

	recoverers := make([]*recovery.Recoverer[*k256.Point, *k256.Scalar], 2)
	s2, ok := dealerOutput.Shares().Get(2)
	require.True(t, ok)
	recoverers[0], err = recovery.NewRecoverer(MISLAYER_ID, quorum, as, s2, verificationVector, prng)
	require.NoError(t, err)
	s4, ok := dealerOutput.Shares().Get(4)
	require.True(t, ok)
	recoverers[1], err = recovery.NewRecoverer(MISLAYER_ID, quorum, as, s4, verificationVector, prng)
	require.True(t, ok)

	mislayer, err := recovery.NewMislayer(MISLAYER_ID, quorum, as, group)
	require.NoError(t, err)
	participants := []testutils.TestParticipant{recoverers[0], recoverers[1], mislayer}

	r1bo := make(map[sharing.ID]*recovery.Round1Broadcast[*k256.Point, *k256.Scalar])
	r1uo := make(map[sharing.ID]network.RoundMessages[*recovery.Round1P2P[*k256.Point, *k256.Scalar]])
	for _, r := range recoverers {
		r1bo[r.SharingID()], r1uo[r.SharingID()], err = r.Round1()
		require.NoError(t, err)
	}
	r2bi, r2ui := testutils.MapO2I(t, participants, r1bo, r1uo)

	r2bo := make(map[sharing.ID]*recovery.Round2Broadcast[*k256.Point, *k256.Scalar])
	r2uo := make(map[sharing.ID]network.RoundMessages[*recovery.Round2P2P[*k256.Point, *k256.Scalar]])
	for _, r := range recoverers {
		r2bo[r.SharingID()], r2uo[r.SharingID()], err = r.Round2(r2bi[r.SharingID()], r2ui[r.SharingID()])
	}
	r3bi, r3ui := testutils.MapO2I(t, participants, r2bo, r2uo)

	s, v, err := mislayer.Round3(r3bi[MISLAYER_ID], r3ui[MISLAYER_ID])
	require.NoError(t, err)

	require.True(t, verificationVector.Equal(v))
	lostShare, ok := dealerOutput.Shares().Get(MISLAYER_ID)
	require.True(t, ok)
	require.True(t, s.Equal(lostShare))
}
