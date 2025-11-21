package recovery_test

import (
	crand "crypto/rand"
	"testing"

	"github.com/stretchr/testify/require"

	"github.com/bronlabs/bron-crypto/pkg/base/curves/k256"
	"github.com/bronlabs/bron-crypto/pkg/base/datastructures/hashset"
	"github.com/bronlabs/bron-crypto/pkg/network"
	"github.com/bronlabs/bron-crypto/pkg/network/testutils"
	"github.com/bronlabs/bron-crypto/pkg/threshold/recovery"
	"github.com/bronlabs/bron-crypto/pkg/threshold/sharing"
	"github.com/bronlabs/bron-crypto/pkg/threshold/sharing/feldman"
	"github.com/bronlabs/bron-crypto/pkg/threshold/tsig"
)

func Test_HappyPath(t *testing.T) {
	t.Parallel()

	const THRESHOLD = 2
	const TOTAL = 4
	prng := crand.Reader

	shareholdersList := [TOTAL]sharing.ID{}
	for i := 1; i <= TOTAL; i++ {
		shareholdersList[i-1] = sharing.ID(i)
	}
	shareholders := hashset.NewComparable(shareholdersList[:]...).Freeze()
	group := k256.NewCurve()
	as, err := feldman.NewAccessStructure(THRESHOLD, hashset.NewComparable(shareholdersList[:]...).Freeze())
	require.NoError(t, err)
	scheme, err := feldman.NewScheme(group.Generator(), THRESHOLD, shareholders)
	require.NoError(t, err)
	dealerOutput, _, err := scheme.DealRandom(prng)
	require.NoError(t, err)
	verificationVector := dealerOutput.VerificationMaterial()

	const MISLAYER_ID = 3
	quroumList := []sharing.ID{2, 3, 4}
	quorum := hashset.NewComparable(quroumList...).Freeze()

	recoverers := make([]*recovery.Recoverer[*k256.Point, *k256.Scalar], 2)
	s2, ok := dealerOutput.Shares().Get(2)
	require.True(t, ok)
	sh2, err := tsig.NewBaseShard(s2, verificationVector, as)
	require.NoError(t, err)
	recoverers[0], err = recovery.NewRecoverer(MISLAYER_ID, quorum, sh2, prng)
	require.NoError(t, err)
	s4, ok := dealerOutput.Shares().Get(4)
	require.True(t, ok)
	sh4, err := tsig.NewBaseShard(s4, verificationVector, as)
	require.NoError(t, err)
	recoverers[1], err = recovery.NewRecoverer(MISLAYER_ID, quorum, sh4, prng)
	require.NoError(t, err)

	mislayer, err := recovery.NewMislayer(MISLAYER_ID, quorum, as, group)
	require.NoError(t, err)
	participants := []ntu.TestParticipant{recoverers[0], recoverers[1], mislayer}

	r1bo := make(map[sharing.ID]*recovery.Round1Broadcast[*k256.Point, *k256.Scalar])
	r1uo := make(map[sharing.ID]network.RoundMessages[*recovery.Round1P2P[*k256.Point, *k256.Scalar]])
	for _, r := range recoverers {
		r1bo[r.SharingID()], r1uo[r.SharingID()], err = r.Round1()
		require.NoError(t, err)
	}
	r2bi, r2ui := ntu.MapO2I(t, participants, r1bo, r1uo)

	r2bo := make(map[sharing.ID]*recovery.Round2Broadcast[*k256.Point, *k256.Scalar])
	r2uo := make(map[sharing.ID]network.RoundMessages[*recovery.Round2P2P[*k256.Point, *k256.Scalar]])
	for _, r := range recoverers {
		r2bo[r.SharingID()], r2uo[r.SharingID()], err = r.Round2(r2bi[r.SharingID()], r2ui[r.SharingID()])
		require.NoError(t, err)
	}
	r3bi, r3ui := ntu.MapO2I(t, participants, r2bo, r2uo)

	s, v, err := mislayer.Round3(r3bi[MISLAYER_ID], r3ui[MISLAYER_ID])
	require.NoError(t, err)

	require.True(t, verificationVector.Equal(v))
	lostShare, ok := dealerOutput.Shares().Get(MISLAYER_ID)
	require.True(t, ok)
	require.True(t, s.Equal(lostShare))
}
