package dkg_test

import (
	crand "crypto/rand"
	"crypto/sha256"
	"fmt"
	"testing"

	"github.com/stretchr/testify/require"

	"github.com/copperexchange/krypton-primitives/pkg/base/curves/bls12381"
	"github.com/copperexchange/krypton-primitives/pkg/base/curves/k256"
	"github.com/copperexchange/krypton-primitives/pkg/base/errs"
	"github.com/copperexchange/krypton-primitives/pkg/base/protocols"
	"github.com/copperexchange/krypton-primitives/pkg/base/types"
	"github.com/copperexchange/krypton-primitives/pkg/base/types/integration"
	integration_testutils "github.com/copperexchange/krypton-primitives/pkg/base/types/integration/testutils"
	"github.com/copperexchange/krypton-primitives/pkg/signatures/bls"
	agreeonrandom_testutils "github.com/copperexchange/krypton-primitives/pkg/threshold/agreeonrandom/testutils"
	"github.com/copperexchange/krypton-primitives/pkg/threshold/tsignatures/tbls/boldyreva02/keygen/dkg"
	"github.com/copperexchange/krypton-primitives/pkg/threshold/tsignatures/tbls/boldyreva02/testutils"
)

func testHappyPath[K bls.KeySubGroup](t *testing.T, threshold, n int) {
	t.Helper()

	pointInK := new(K)
	curve := (*pointInK).Curve()

	cipherSuite := &integration.CipherSuite{
		Curve: curve,
		Hash:  sha256.New,
	}

	inG1 := curve.Name() == bls12381.NameG1
	inG1s := make([]bool, n)
	for i := 0; i < n; i++ {
		inG1s[i] = inG1
	}

	identities, err := integration_testutils.MakeTestIdentities(cipherSuite, n)
	require.NoError(t, err)
	cohortConfig, err := integration_testutils.MakeCohortProtocol(cipherSuite, protocols.BLS, identities, threshold, identities)
	require.NoError(t, err)

	uniqueSessionId, err := agreeonrandom_testutils.RunAgreeOnRandom(curve, identities, crand.Reader)
	require.NoError(t, err)

	participants, err := testutils.MakeDkgParticipants[K](uniqueSessionId, cohortConfig, identities, nil)
	require.NoError(t, err)

	r1OutsB, r1OutsU, err := testutils.DoDkgRound1(participants)
	require.NoError(t, err)
	for _, out := range r1OutsU {
		require.Len(t, out, cohortConfig.Participants.Len()-1)
	}

	r2InsB, r2InsU := integration_testutils.MapO2I(participants, r1OutsB, r1OutsU)
	r2Outs, err := testutils.DoDkgRound2(participants, r2InsB, r2InsU)
	require.NoError(t, err)

	r3Ins := integration_testutils.MapBroadcastO2I(participants, r2Outs)
	shards, err := testutils.DoDkgRound3(participants, r3Ins)
	require.NoError(t, err)
	for _, shard := range shards {
		err = shard.Validate(cohortConfig)
		require.NoError(t, err)
	}
}

func Test_HappyPath(t *testing.T) {
	t.Parallel()
	for _, inG1 := range []bool{true, false} {
		for _, thresholdConfig := range []struct {
			t int
			n int
		}{
			{t: 2, n: 2},
			{t: 2, n: 3},
			{t: 3, n: 3},
		} {
			boundedInG1 := inG1
			boundedThresholdConfig := thresholdConfig
			t.Run(fmt.Sprintf("Happy path with inG1=%t and t=%d and n=%d", boundedInG1, boundedThresholdConfig.t, boundedThresholdConfig.n), func(t *testing.T) {
				t.Parallel()
				if boundedInG1 {
					testHappyPath[bls.G1](t, boundedThresholdConfig.t, boundedThresholdConfig.n)
				} else {
					testHappyPath[bls.G2](t, boundedThresholdConfig.t, boundedThresholdConfig.n)
				}
			})
		}
	}
}

func Test_SubGroupMismatchShouldFail(t *testing.T) {

	threshold := 2
	n := 2

	sid := []byte("something")

	aliceSubGroup := bls12381.NewG1()
	bobSubGroup := bls12381.NewG2()

	idCipherSuite := &integration.CipherSuite{
		Curve: k256.New(),
		Hash:  sha256.New,
	}

	identities, err := integration_testutils.MakeTestIdentities(idCipherSuite, n)
	require.NoError(t, err)

	aliceId := identities[0]
	bobId := identities[1]

	aliceCipherSuite := &integration.CipherSuite{
		Curve: aliceSubGroup,
		Hash:  sha256.New,
	}

	cohortConfigAlice, err := integration_testutils.MakeCohortProtocol(aliceCipherSuite, protocols.BLS, identities, threshold, identities)
	require.NoError(t, err)
	cohortConfigAlice.CipherSuite.Curve = aliceSubGroup

	bobCipherSuite := &integration.CipherSuite{
		Curve: bobSubGroup,
		Hash:  sha256.New,
	}

	cohortConfigBob, err := integration_testutils.MakeCohortProtocol(bobCipherSuite, protocols.BLS, identities, threshold, identities)
	require.NoError(t, err)

	alice, err := dkg.NewParticipant[bls.G1](sid, aliceId.(integration.AuthKey), cohortConfigAlice, nil, crand.Reader)
	require.NoError(t, err)

	bob, err := dkg.NewParticipant[bls.G2](sid, bobId.(integration.AuthKey), cohortConfigBob, nil, crand.Reader)
	require.NoError(t, err)

	aliceR1Broadcast, aliceR1P2P, err := alice.Round1()
	require.NoError(t, err)

	bobR1Broadcast, bobR1P2P, err := bob.Round1()
	require.NoError(t, err)

	aliceR2InputBroadcast := map[types.IdentityHash]*dkg.Round1Broadcast{bobId.Hash(): bobR1Broadcast}
	aliceR2InputP2P := map[types.IdentityHash]*dkg.Round1P2P{bobId.Hash(): bobR1P2P[aliceId.Hash()]}

	bobR2InputBroadcast := map[types.IdentityHash]*dkg.Round1Broadcast{aliceId.Hash(): aliceR1Broadcast}
	bobR2InputP2P := map[types.IdentityHash]*dkg.Round1P2P{aliceId.Hash(): aliceR1P2P[bobId.Hash()]}

	_, err = alice.Round2(aliceR2InputBroadcast, aliceR2InputP2P)
	require.Error(t, err)
	require.True(t, errs.IsInvalidCurve(err))

	_, err = bob.Round2(bobR2InputBroadcast, bobR2InputP2P)
	require.Error(t, err)
	require.True(t, errs.IsInvalidCurve(err))
}
