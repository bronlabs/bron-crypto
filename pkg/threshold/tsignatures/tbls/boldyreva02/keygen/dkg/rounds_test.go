package dkg_test

import (
	crand "crypto/rand"
	"crypto/sha256"
	"fmt"
	"testing"

	"github.com/stretchr/testify/require"

	"github.com/copperexchange/krypton-primitives/pkg/base/curves/bls12381"
	"github.com/copperexchange/krypton-primitives/pkg/base/curves/k256"
	"github.com/copperexchange/krypton-primitives/pkg/base/datastructures/hashmap"
	"github.com/copperexchange/krypton-primitives/pkg/base/errs"
	"github.com/copperexchange/krypton-primitives/pkg/base/types"
	ttu "github.com/copperexchange/krypton-primitives/pkg/base/types/testutils"
	randomisedFischlin "github.com/copperexchange/krypton-primitives/pkg/proofs/sigma/compiler/randomised_fischlin"
	"github.com/copperexchange/krypton-primitives/pkg/signatures/bls"
	agreeonrandom_testutils "github.com/copperexchange/krypton-primitives/pkg/threshold/agreeonrandom/testutils"
	"github.com/copperexchange/krypton-primitives/pkg/threshold/tsignatures"
	"github.com/copperexchange/krypton-primitives/pkg/threshold/tsignatures/tbls/boldyreva02/keygen/dkg"
	"github.com/copperexchange/krypton-primitives/pkg/threshold/tsignatures/tbls/boldyreva02/testutils"
)

func testHappyPath[K bls.KeySubGroup](t *testing.T, threshold, n int) {
	t.Helper()

	curve := bls12381.GetSourceSubGroup[K]()
	h := sha256.New

	cipherSuite, err := ttu.MakeSignatureProtocol(curve, h)
	require.NoError(t, err)
	inG1 := curve.Name() == bls12381.NameG1
	inG1s := make([]bool, n)
	for i := 0; i < n; i++ {
		inG1s[i] = inG1
	}

	identities, err := ttu.MakeTestIdentities(cipherSuite, n)
	require.NoError(t, err)
	protocol, err := ttu.MakeThresholdSignatureProtocol(cipherSuite, identities, threshold, identities)
	require.NoError(t, err)

	uniqueSessionId, err := agreeonrandom_testutils.RunAgreeOnRandom(curve, identities, crand.Reader)
	require.NoError(t, err)

	participants, err := testutils.MakeDkgParticipants[K](uniqueSessionId, protocol, identities, nil)
	require.NoError(t, err)

	r1OutsB, r1OutsU, err := testutils.DoDkgRound1(participants)
	require.NoError(t, err)
	for _, out := range r1OutsU {
		require.Equal(t, out.Size(), protocol.Participants().Size()-1)
	}

	r2InsB, r2InsU := ttu.MapO2I(participants, r1OutsB, r1OutsU)
	r2Outs, err := testutils.DoDkgRound2(participants, r2InsB, r2InsU)
	require.NoError(t, err)

	r3Ins := ttu.MapBroadcastO2I(participants, r2Outs)
	shards, err := testutils.DoDkgRound3(participants, r3Ins)
	require.NoError(t, err)
	for _, shard := range shards {
		err = shard.Validate(protocol)
		require.NoError(t, err)
	}
	t.Run("Disaster recovery", func(t *testing.T) {
		shardMap := hashmap.NewHashableHashMap[types.IdentityKey, tsignatures.Shard]()
		for i := 0; i < threshold; i++ {
			shardMap.Put(identities[i], shards[i])
		}
		_, err := tsignatures.ConstructPrivateKey(protocol, shardMap)
		require.NoError(t, err)
	})
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
					testHappyPath[bls12381.G1](t, boundedThresholdConfig.t, boundedThresholdConfig.n)
				} else {
					testHappyPath[bls12381.G2](t, boundedThresholdConfig.t, boundedThresholdConfig.n)
				}
			})
		}
	}
}

func Test_SubGroupMismatchShouldFail(t *testing.T) {

	threshold := 2
	n := 2
	cn := randomisedFischlin.Name

	sid := []byte("something")

	aliceSubGroup := bls12381.NewG1()
	bobSubGroup := bls12381.NewG2()

	idCipherSuite, err := ttu.MakeSignatureProtocol(k256.NewCurve(), sha256.New)
	require.NoError(t, err)

	identities, err := ttu.MakeTestIdentities(idCipherSuite, n)
	require.NoError(t, err)

	aliceId := identities[0]
	bobId := identities[1]

	aliceCipherSuite, err := ttu.MakeSignatureProtocol(aliceSubGroup, sha256.New)
	require.NoError(t, err)

	cohortConfigAlice, err := ttu.MakeThresholdSignatureProtocol(aliceCipherSuite, identities, threshold, identities)
	require.NoError(t, err)

	bobCipherSuite, err := ttu.MakeSignatureProtocol(bobSubGroup, sha256.New)
	require.NoError(t, err)

	cohortConfigBob, err := ttu.MakeThresholdSignatureProtocol(bobCipherSuite, identities, threshold, identities)
	require.NoError(t, err)

	alice, err := dkg.NewParticipant[bls12381.G1](sid, aliceId.(types.AuthKey), cohortConfigAlice, cn, nil, crand.Reader)
	require.NoError(t, err)

	bob, err := dkg.NewParticipant[bls12381.G2](sid, bobId.(types.AuthKey), cohortConfigBob, cn, nil, crand.Reader)
	require.NoError(t, err)

	aliceR1Broadcast, aliceR1P2P, err := alice.Round1()
	require.NoError(t, err)

	bobR1Broadcast, bobR1P2P, err := bob.Round1()
	require.NoError(t, err)

	aliceR2InputBroadcast := types.NewRoundMessages[*dkg.Round1Broadcast]()
	aliceR2InputBroadcast.Put(bobId, bobR1Broadcast)

	aliceR2InputP2P := types.NewRoundMessages[*dkg.Round1P2P]()
	bobMessageToAlice, exists := bobR1P2P.Get(aliceId)
	require.True(t, exists)
	aliceR2InputP2P.Put(bobId, bobMessageToAlice)

	bobR2InputBroadcast := types.NewRoundMessages[*dkg.Round1Broadcast]()
	bobR2InputBroadcast.Put(aliceId, aliceR1Broadcast)

	bobR2InputP2P := types.NewRoundMessages[*dkg.Round1P2P]()
	aliceMessageTobob, exists := aliceR1P2P.Get(bobId)
	require.True(t, exists)
	bobR2InputP2P.Put(bobId, aliceMessageTobob)

	_, err = alice.Round2(aliceR2InputBroadcast, aliceR2InputP2P)
	require.Error(t, err)
	require.True(t, errs.IsCurve(err))

	_, err = bob.Round2(bobR2InputBroadcast, bobR2InputP2P)
	require.Error(t, err)
}
