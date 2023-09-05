package fuzz

import (
	crand "crypto/rand"
	"crypto/sha256"
	"fmt"
	"io"
	"math/rand"
	"testing"

	"github.com/stretchr/testify/require"

	agreeonrandom_test_utils "github.com/copperexchange/knox-primitives/pkg/agreeonrandom/test_utils"
	"github.com/copperexchange/knox-primitives/pkg/core/curves/bls12381"
	"github.com/copperexchange/knox-primitives/pkg/core/errs"
	"github.com/copperexchange/knox-primitives/pkg/core/integration"
	"github.com/copperexchange/knox-primitives/pkg/core/integration/helper_types"
	integration_test_utils "github.com/copperexchange/knox-primitives/pkg/core/integration/test_utils"
	test_utils_integration "github.com/copperexchange/knox-primitives/pkg/core/integration/test_utils"
	"github.com/copperexchange/knox-primitives/pkg/core/protocols"
	"github.com/copperexchange/knox-primitives/pkg/signatures/bls"
	"github.com/copperexchange/knox-primitives/pkg/signatures/threshold/tbls/boldyreva02"
	"github.com/copperexchange/knox-primitives/pkg/signatures/threshold/tbls/boldyreva02/signing/aggregation"
	"github.com/copperexchange/knox-primitives/pkg/signatures/threshold/tbls/boldyreva02/test_utils"
)

var schemes = []bls.RogueKeyPrevention{
	bls.Basic, bls.MessageAugmentation, bls.POP,
}

func Fuzz_Test(f *testing.F) {
	f.Add(uint(0), uint64(0), uint64(1), uint64(2), []byte("sid"), []byte("message"), int64(0))
	f.Fuzz(func(t *testing.T, schemeIndex uint, aliceSecret uint64, bobSecret uint64, charlieSecret uint64, sid []byte, message []byte, randomSeed int64) {
		roundtrip[bls.G1, bls.G2](t, schemeIndex, aliceSecret, bobSecret, charlieSecret, sid, message, randomSeed)
		roundtrip[bls.G2, bls.G1](t, schemeIndex, aliceSecret, bobSecret, charlieSecret, sid, message, randomSeed)
	})
}

func roundtrip[K bls.KeySubGroup, S bls.SignatureSubGroup](t *testing.T, schemeIndex uint, aliceSecret uint64, bobSecret uint64, charlieSecret uint64, sid []byte, message []byte, randomSeed int64) {
	t.Helper()
	scheme := schemes[schemeIndex%uint(len(schemes))]
	hashFunc := sha256.New

	pointInK := new(K)
	keysSubGroup := (*pointInK).Curve()

	cipherSuite := &integration.CipherSuite{
		Curve: keysSubGroup,
		Hash:  hashFunc,
	}

	aliceIdentity, _ := test_utils_integration.MakeIdentity(cipherSuite, keysSubGroup.Scalar().New(aliceSecret))
	bobIdentity, _ := test_utils_integration.MakeIdentity(cipherSuite, keysSubGroup.Scalar().New(bobSecret))
	charlieIdentity, _ := test_utils_integration.MakeIdentity(cipherSuite, keysSubGroup.Scalar().New(charlieSecret))
	identities := []integration.IdentityKey{aliceIdentity, bobIdentity, charlieIdentity}

	cohort, err := integration_test_utils.MakeCohortProtocol(cipherSuite, protocols.BLS, identities, 2, identities)
	if err != nil && !errs.IsKnownError(err) {
		require.NoError(t, err)
	}
	if err != nil {
		t.Skip(err.Error())
	}
	require.NoError(t, err)

	shards := keygen[K](t, identities, 2, 3, randomSeed)

	fmt.Println(shards[identities[0].Hash()])
	publicKeyShares := shards[identities[0].Hash()].PublicKeyShares
	publicKey := publicKeyShares.PublicKey

	participants, err := test_utils.MakeSigningParticipants[K, S](sid, cohort, identities, shards)
	require.NoError(t, err)

	partialSignatures, err := test_utils.ProducePartialSignature(participants, message)
	if err != nil && !errs.IsKnownError(err) {
		require.NoError(t, err)
	}
	if err != nil {
		t.Skip(err.Error())
	}
	require.NoError(t, err)

	aggregatorInput := test_utils.MapPartialSignatures(identities, partialSignatures)

	agg, err := aggregation.NewAggregator[K, S](shards[identities[0].Hash()].PublicKeyShares, cohort)
	require.NoError(t, err)

	signature, err := agg.Aggregate(aggregatorInput, message)
	require.NoError(t, err)

	err = bls.Verify(publicKey, signature, message, nil, scheme)
	require.Error(t, err)
}

func keygen[K bls.KeySubGroup](t *testing.T, identities []integration.IdentityKey, threshold, n int, randomSeed int64) map[helper_types.IdentityHash]*boldyreva02.Shard[K] {
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

	cohortConfig, err := test_utils_integration.MakeCohortProtocol(cipherSuite, protocols.BLS, identities, threshold, identities)
	require.NoError(t, err)

	uniqueSessionId, err := agreeonrandom_test_utils.ProduceSharedRandomValue(curve, identities, crand.Reader)
	require.NoError(t, err)

	randoms := make([]io.Reader, n)
	for i := 0; i < n; i++ {
		randoms[i] = rand.New(rand.NewSource(randomSeed + int64(i)))
	}
	participants, err := test_utils.MakeDkgParticipants[K](uniqueSessionId, cohortConfig, identities, randoms)
	require.NoError(t, err)

	r1OutsB, r1OutsU, err := test_utils.DoDkgRound1(participants)
	require.NoError(t, err)
	for _, out := range r1OutsU {
		require.Len(t, out, cohortConfig.Participants.Len()-1)
	}

	r2InsB, r2InsU := test_utils.MapDkgRound1OutputsToRound2Inputs(participants, r1OutsB, r1OutsU)
	r2Outs, err := test_utils.DoDkgRound2(participants, r2InsB, r2InsU)
	require.NoError(t, err)

	r3Ins := test_utils.MapDkgRound2OutputsToRound3Inputs(participants, r2Outs)
	shards, err := test_utils.DoDkgRound3(participants, r3Ins)
	shardMap := make(map[helper_types.IdentityHash]*boldyreva02.Shard[K])
	require.NoError(t, err)
	for i, shard := range shards {
		shardMap[identities[i].Hash()] = shard
		err = shard.Validate(cohortConfig)
		require.NoError(t, err)
	}
	return shardMap
}
