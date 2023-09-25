package dkg_test

import (
	crand "crypto/rand"
	"crypto/sha256"
	"fmt"
	"github.com/copperexchange/krypton-primitives/pkg/base/types"
	"github.com/copperexchange/krypton-primitives/pkg/base/types/integration"
	testutils_integration "github.com/copperexchange/krypton-primitives/pkg/base/types/integration/testutils"
	"os"
	"strconv"
	"testing"

	"github.com/copperexchange/krypton-primitives/pkg/base/curves/bls12381"
	"github.com/copperexchange/krypton-primitives/pkg/base/curves/k256"
	"github.com/copperexchange/krypton-primitives/pkg/base/errs"
	"github.com/copperexchange/krypton-primitives/pkg/signatures/bls"
	"github.com/copperexchange/krypton-primitives/pkg/threshold/tsignatures/tbls/boldyreva02/keygen/dkg"
	"github.com/copperexchange/krypton-primitives/pkg/threshold/tsignatures/tbls/boldyreva02/testutils"

	"github.com/copperexchange/krypton-primitives/pkg/base/curves"
	"github.com/copperexchange/krypton-primitives/pkg/base/protocols"
	agreeonrandom_testutils "github.com/copperexchange/krypton-primitives/pkg/threshold/agreeonrandom/testutils"
	"github.com/stretchr/testify/require"
)

func TestRunProfile(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping profiling test in short mode")
	}
	if os.Getenv("PROFILE_T") == "" || os.Getenv("PROFILE_N") == "" {
		t.Skip("skipping profiling test missing parameter")
	}
	var curve curves.Curve
	th, _ := strconv.Atoi(os.Getenv("PROFILE_T"))
	n, _ := strconv.Atoi(os.Getenv("PROFILE_N"))
	if os.Getenv("IN_G1") == "true" {
		curve = bls12381.NewG1()
	} else {
		curve = bls12381.NewG2()
	}
	if curve.Name() == bls12381.G1Name {
		for i := 0; i < 1000; i++ {
			testHappyPath[bls.G1](t, th, n)
		}
	} else {
		for i := 0; i < 1000; i++ {
			testHappyPath[bls.G2](t, th, n)
		}
	}
}

func testHappyPath[K bls.KeySubGroup](t *testing.T, threshold, n int) {
	t.Helper()

	pointInK := new(K)
	curve := (*pointInK).Curve()

	cipherSuite := &integration.CipherSuite{
		Curve: curve,
		Hash:  sha256.New,
	}

	inG1 := curve.Name() == bls12381.G1Name
	inG1s := make([]bool, n)
	for i := 0; i < n; i++ {
		inG1s[i] = inG1
	}

	identities, err := testutils_integration.MakeIdentities(cipherSuite, n)
	require.NoError(t, err)
	cohortConfig, err := testutils_integration.MakeCohortProtocol(cipherSuite, protocols.BLS, identities, threshold, identities)
	require.NoError(t, err)

	uniqueSessionId, err := agreeonrandom_testutils.ProduceSharedRandomValue(curve, identities, crand.Reader)
	require.NoError(t, err)

	participants, err := testutils.MakeDkgParticipants[K](uniqueSessionId, cohortConfig, identities, nil)
	require.NoError(t, err)

	r1OutsB, r1OutsU, err := testutils.DoDkgRound1(participants)
	require.NoError(t, err)
	for _, out := range r1OutsU {
		require.Len(t, out, cohortConfig.Participants.Len()-1)
	}

	r2InsB, r2InsU := testutils.MapDkgRound1OutputsToRound2Inputs(participants, r1OutsB, r1OutsU)
	r2Outs, err := testutils.DoDkgRound2(participants, r2InsB, r2InsU)

	r3Ins := testutils.MapDkgRound2OutputsToRound3Inputs(participants, r2Outs)
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

	identities, err := testutils_integration.MakeIdentities(idCipherSuite, n)
	require.NoError(t, err)

	aliceId := identities[0]
	bobId := identities[1]

	aliceCipherSuite := &integration.CipherSuite{
		Curve: aliceSubGroup,
		Hash:  sha256.New,
	}

	cohortConfigAlice, err := testutils_integration.MakeCohortProtocol(aliceCipherSuite, protocols.BLS, identities, threshold, identities)
	require.NoError(t, err)
	cohortConfigAlice.CipherSuite.Curve = aliceSubGroup

	bobCipherSuite := &integration.CipherSuite{
		Curve: bobSubGroup,
		Hash:  sha256.New,
	}

	cohortConfigBob, err := testutils_integration.MakeCohortProtocol(bobCipherSuite, protocols.BLS, identities, threshold, identities)
	require.NoError(t, err)

	alice, err := dkg.NewParticipant[bls.G1](sid, aliceId, cohortConfigAlice, nil, crand.Reader)
	require.NoError(t, err)

	bob, err := dkg.NewParticipant[bls.G2](sid, bobId, cohortConfigBob, nil, crand.Reader)
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
