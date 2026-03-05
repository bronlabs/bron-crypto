package recovery_test

import (
	"testing"

	"github.com/stretchr/testify/require"

	"github.com/bronlabs/bron-crypto/pkg/base/curves/k256"
	"github.com/bronlabs/bron-crypto/pkg/base/datastructures/hashset"
	"github.com/bronlabs/bron-crypto/pkg/base/prng/pcg"
	session_testutils "github.com/bronlabs/bron-crypto/pkg/mpc/session/testutils"
	"github.com/bronlabs/bron-crypto/pkg/mpc/sharing"
	"github.com/bronlabs/bron-crypto/pkg/mpc/sharing/accessstructures"
	"github.com/bronlabs/bron-crypto/pkg/mpc/sharing/interactive/recovery"
	"github.com/bronlabs/bron-crypto/pkg/mpc/sharing/scheme/feldman"
	"github.com/bronlabs/bron-crypto/pkg/mpc/tsig"
	"github.com/bronlabs/bron-crypto/pkg/network"
	ntu "github.com/bronlabs/bron-crypto/pkg/network/testutils"
)

func Test_HappyPath(t *testing.T) {
	t.Parallel()

	const TOTAL = 4
	const THRESHOLD = 2

	prng := pcg.NewRandomised()
	group := k256.NewCurve()
	as, err := accessstructures.NewThresholdAccessStructure(THRESHOLD, sharing.NewOrdinalShareholderSet(TOTAL))
	require.NoError(t, err)
	scheme, err := feldman.NewScheme(group.Generator(), as)
	require.NoError(t, err)
	dealerOutput, _, err := scheme.DealRandom(prng)
	require.NoError(t, err)
	verificationVector := dealerOutput.VerificationMaterial()

	const MISLAYER_ID = 3
	quroumList := []sharing.ID{2, 3, 4}
	quorum := hashset.NewComparable(quroumList...).Freeze()
	ctxs := session_testutils.MakeRandomContexts(t, quorum, prng)

	recoverers := make([]*recovery.Recoverer[*k256.Point, *k256.Scalar], 2)
	s2, ok := dealerOutput.Shares().Get(2)
	require.True(t, ok)
	sh2, err := tsig.NewBaseShard(s2, verificationVector, as)
	require.NoError(t, err)
	recoverers[0], err = recovery.NewRecoverer(ctxs[2], MISLAYER_ID, sh2, prng)
	require.NoError(t, err)
	s4, ok := dealerOutput.Shares().Get(4)
	require.True(t, ok)
	sh4, err := tsig.NewBaseShard(s4, verificationVector, as)
	require.NoError(t, err)
	recoverers[1], err = recovery.NewRecoverer(ctxs[4], MISLAYER_ID, sh4, prng)
	require.NoError(t, err)

	mislayer, err := recovery.NewMislayer(ctxs[MISLAYER_ID], as, group)
	require.NoError(t, err)
	participants := []ntu.TestParticipant{recoverers[0], recoverers[1], mislayer}

	r1bo := make(map[sharing.ID]*recovery.Round1Broadcast[*k256.Point, *k256.Scalar])
	r1uo := make(map[sharing.ID]network.RoundMessages[*recovery.Round1P2P[*k256.Point, *k256.Scalar]])
	for _, r := range recoverers {
		r1bo[r.SharingID()], r1uo[r.SharingID()], err = r.Round1()
		require.NoError(t, err)
	}
	r2bi, r2ui := ntu.MapO2I(t, participants, r1bo, r1uo)

	r2uo := make(map[sharing.ID]network.RoundMessages[*recovery.Round2P2P[*k256.Point, *k256.Scalar]])
	for _, r := range recoverers {
		r2uo[r.SharingID()], err = r.Round2(r2bi[r.SharingID()], r2ui[r.SharingID()])
		require.NoError(t, err)
	}
	r3ui := ntu.MapUnicastO2I(t, participants, r2uo)

	o, err := mislayer.Round3(r3ui[MISLAYER_ID])
	require.NoError(t, err)

	require.True(t, verificationVector.Equal(o.Verification()))
	lostShare, ok := dealerOutput.Shares().Get(MISLAYER_ID)
	require.True(t, ok)
	require.True(t, o.Share().Equal(lostShare))
}
