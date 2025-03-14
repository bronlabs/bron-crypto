package recovery_test

import (
	crand "crypto/rand"
	"testing"

	"github.com/stretchr/testify/require"

	"github.com/bronlabs/bron-crypto/pkg/base/curves/k256"
	"github.com/bronlabs/bron-crypto/pkg/base/datastructures/hashset"
	"github.com/bronlabs/bron-crypto/pkg/base/types"
	"github.com/bronlabs/bron-crypto/pkg/base/types/testutils"
	"github.com/bronlabs/bron-crypto/pkg/network"
	gennaroTu "github.com/bronlabs/bron-crypto/pkg/threshold/dkg/gennaro/testutils"
	"github.com/bronlabs/bron-crypto/pkg/threshold/recovery"
)

func Test_HappyPath(t *testing.T) {
	t.Parallel()

	const n = 3
	const th = 2

	prng := crand.Reader
	curve := k256.NewCurve()
	sessionId := []byte("test-session-id")
	identities, err := testutils.MakeDeterministicTestIdentities(n)
	require.NoError(t, err)
	protocol, err := testutils.MakeThresholdProtocol(curve, identities, th)
	require.NoError(t, err)
	tapes := testutils.MakeTranscripts("testtest", identities)

	shares, publicShares, err := gennaroTu.DoGennaroDkg(t, sessionId, protocol, identities, tapes)
	require.NoError(t, err)

	// pretend bob lost his share
	aliceShare := shares[0]
	alicePublicShare := publicShares[0]
	charlieShare := shares[2]
	charliePublicShare := publicShares[2]

	recoverers := hashset.NewHashableHashSet[types.IdentityKey](identities[0], identities[2])
	alice, err := recovery.NewRecoverer(identities[0].(types.AuthKey), identities[1], recoverers, protocol, aliceShare, alicePublicShare, prng)
	require.NoError(t, err)
	bob, err := recovery.NewMislayer(identities[1].(types.AuthKey), recoverers, protocol, prng)
	require.NoError(t, err)
	charlie, err := recovery.NewRecoverer(identities[2].(types.AuthKey), identities[1], recoverers, protocol, charlieShare, charliePublicShare, prng)
	require.NoError(t, err)

	// r1
	r1bo := make([]*recovery.Round1Broadcast, 3)
	r1bo[0], err = alice.Round1()
	require.NoError(t, err)
	r1bo[2], err = charlie.Round1()
	require.NoError(t, err)

	// r2
	r2bi := testutils.MapBroadcastO2I(t, []types.ThresholdParticipant{alice, bob, charlie}, r1bo)
	r2uo := make([]network.RoundMessages[types.ThresholdProtocol, *recovery.Round2P2P], 3)
	r2uo[0], err = alice.Round2(r2bi[0])
	require.NoError(t, err)
	r2uo[2], err = charlie.Round2(r2bi[2])
	require.NoError(t, err)

	// r3
	r3ui := testutils.MapUnicastO2I(t, []types.ThresholdParticipant{alice, bob, charlie}, r2uo)
	r3bo := make([]*recovery.Round3Broadcast, 3)
	r3uo := make([]network.RoundMessages[types.ThresholdProtocol, *recovery.Round3P2P], 3)
	r3bo[0], r3uo[0], err = alice.Round3(r3ui[0])
	require.NoError(t, err)
	r3bo[2], r3uo[2], err = charlie.Round3(r3ui[2])
	require.NoError(t, err)

	// r4
	r4bi, r4ui := testutils.MapO2I(t, []types.ThresholdParticipant{alice, bob, charlie}, r3bo, r3uo)
	err = alice.Round4(r4bi[0])
	require.NoError(t, err)
	recoveredSks, recoveredPpk, err := bob.Round4(r4bi[1], r4ui[1])
	require.NoError(t, err)
	err = charlie.Round4(r4bi[2])
	require.NoError(t, err)

	bobShare := shares[1]
	bobPublicShare := publicShares[1]

	require.True(t, recoveredSks.Equal(bobShare))
	require.True(t, recoveredPpk.Equal(bobPublicShare))
}
