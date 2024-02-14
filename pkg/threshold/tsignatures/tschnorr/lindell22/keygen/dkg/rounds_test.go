package dkg_test

import (
	crand "crypto/rand"
	"crypto/sha512"
	"fmt"
	"hash"
	"reflect"
	"runtime"
	"strings"
	"testing"

	"github.com/stretchr/testify/require"
	"golang.org/x/crypto/sha3"

	"github.com/copperexchange/krypton-primitives/pkg/base/curves"
	"github.com/copperexchange/krypton-primitives/pkg/base/curves/edwards25519"
	"github.com/copperexchange/krypton-primitives/pkg/base/curves/k256"
	"github.com/copperexchange/krypton-primitives/pkg/base/datastructures/hashmap"
	"github.com/copperexchange/krypton-primitives/pkg/base/types"
	ttu "github.com/copperexchange/krypton-primitives/pkg/base/types/testutils"
	agreeonrandom_testutils "github.com/copperexchange/krypton-primitives/pkg/threshold/agreeonrandom/testutils"
	"github.com/copperexchange/krypton-primitives/pkg/threshold/tsignatures"
	"github.com/copperexchange/krypton-primitives/pkg/threshold/tsignatures/tschnorr/lindell22/testutils"
)

func testHappyPath(t *testing.T, curve curves.Curve, h func() hash.Hash, threshold int, n int) {
	t.Helper()

	cipherSuite, err := ttu.MakeSignatureProtocol(curve, h)
	require.NoError(t, err)

	identities, err := ttu.MakeTestIdentities(cipherSuite, n)
	require.NoError(t, err)
	protocol, err := ttu.MakeThresholdSignatureProtocol(cipherSuite, identities, threshold, identities)
	require.NoError(t, err)

	uniqueSessionId, err := agreeonrandom_testutils.RunAgreeOnRandom(curve, identities, crand.Reader)
	require.NoError(t, err)

	participants, err := testutils.MakeParticipants(uniqueSessionId, protocol, identities, nil)
	require.NoError(t, err)

	r1OutsB, r1OutsU, err := testutils.DoDkgRound1(participants)
	require.NoError(t, err)
	for _, out := range r1OutsU {
		require.Equal(t, out.Size(), int(protocol.TotalParties())-1)
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
	for _, curve := range []curves.Curve{k256.NewCurve(), edwards25519.NewCurve()} {
		for _, h := range []func() hash.Hash{sha3.New256, sha512.New} {
			for _, thresholdConfig := range []struct {
				t int
				n int
			}{
				{t: 2, n: 2},
				{t: 2, n: 3},
				{t: 3, n: 3},
			} {
				boundedCurve := curve
				boundedHash := h
				boundedHashName := runtime.FuncForPC(reflect.ValueOf(h).Pointer()).Name()
				boundedThresholdConfig := thresholdConfig
				t.Run(fmt.Sprintf("Happy path with curve=%s and hash=%s and t=%d and n=%d", boundedCurve.Name(), boundedHashName[strings.LastIndex(boundedHashName, "/")+1:], boundedThresholdConfig.t, boundedThresholdConfig.n), func(t *testing.T) {
					t.Parallel()
					testHappyPath(t, boundedCurve, boundedHash, boundedThresholdConfig.t, boundedThresholdConfig.n)
				})
			}
		}
	}
}
