package fuzz

import (
	crand "crypto/rand"
	"crypto/sha256"
	"fmt"
	"io"
	"math/rand"
	"testing"

	"github.com/stretchr/testify/require"

	"github.com/copperexchange/krypton-primitives/pkg/base/curves/bls12381"
	"github.com/copperexchange/krypton-primitives/pkg/base/errs"
	"github.com/copperexchange/krypton-primitives/pkg/base/protocols"
	"github.com/copperexchange/krypton-primitives/pkg/base/types"
	"github.com/copperexchange/krypton-primitives/pkg/base/types/integration"
	testutils_integration "github.com/copperexchange/krypton-primitives/pkg/base/types/integration/testutils"
	"github.com/copperexchange/krypton-primitives/pkg/signatures/bls"
	agreeonrandom_testutils "github.com/copperexchange/krypton-primitives/pkg/threshold/agreeonrandom/testutils"
	"github.com/copperexchange/krypton-primitives/pkg/threshold/tsignatures/tbls/boldyreva02"
	"github.com/copperexchange/krypton-primitives/pkg/threshold/tsignatures/tbls/boldyreva02/signing/aggregation"
	"github.com/copperexchange/krypton-primitives/pkg/threshold/tsignatures/tbls/boldyreva02/testutils"
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

	aliceIdentity, _ := testutils_integration.MakeIdentity(cipherSuite, keysSubGroup.Scalar().New(aliceSecret))
	bobIdentity, _ := testutils_integration.MakeIdentity(cipherSuite, keysSubGroup.Scalar().New(bobSecret))
	charlieIdentity, _ := testutils_integration.MakeIdentity(cipherSuite, keysSubGroup.Scalar().New(charlieSecret))
	identities := []integration.IdentityKey{aliceIdentity, bobIdentity, charlieIdentity}

	cohort, err := testutils_integration.MakeCohortProtocol(cipherSuite, protocols.BLS, identities, 2, identities)
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

	participants, err := testutils.MakeSigningParticipants[K, S](sid, cohort, identities, shards)
	require.NoError(t, err)

	partialSignatures, err := testutils.ProducePartialSignature(participants, message)
	if err != nil && !errs.IsKnownError(err) {
		require.NoError(t, err)
	}
	if err != nil {
		t.Skip(err.Error())
	}
	require.NoError(t, err)

	aggregatorInput := testutils.MapPartialSignatures(identities, partialSignatures)

	agg, err := aggregation.NewAggregator[K, S](shards[identities[0].Hash()].PublicKeyShares, cohort)
	require.NoError(t, err)

	signature, err := agg.Aggregate(aggregatorInput, message)
	require.NoError(t, err)

	err = bls.Verify(publicKey, signature, message, nil, scheme)
	require.Error(t, err)
}

func keygen[K bls.KeySubGroup](t *testing.T, identities []integration.IdentityKey, threshold, n int, randomSeed int64) map[types.IdentityHash]*boldyreva02.Shard[K] {
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

	cohortConfig, err := testutils_integration.MakeCohortProtocol(cipherSuite, protocols.BLS, identities, threshold, identities)
	require.NoError(t, err)

	uniqueSessionId, err := agreeonrandom_testutils.ProduceSharedRandomValue(curve, identities, crand.Reader)
	require.NoError(t, err)

	randoms := make([]io.Reader, n)
	for i := 0; i < n; i++ {
		randoms[i] = rand.New(rand.NewSource(randomSeed + int64(i)))
	}
	participants, err := testutils.MakeDkgParticipants[K](uniqueSessionId, cohortConfig, identities, randoms)
	require.NoError(t, err)

	r1OutsB, r1OutsU, err := testutils.DoDkgRound1(participants)
	require.NoError(t, err)
	for _, out := range r1OutsU {
		require.Len(t, out, cohortConfig.Participants.Len()-1)
	}

	r2InsB, r2InsU := testutils.MapDkgRound1OutputsToRound2Inputs(participants, r1OutsB, r1OutsU)
	r2Outs, err := testutils.DoDkgRound2(participants, r2InsB, r2InsU)
	require.NoError(t, err)

	r3Ins := testutils.MapDkgRound2OutputsToRound3Inputs(participants, r2Outs)
	shards, err := testutils.DoDkgRound3(participants, r3Ins)
	shardMap := make(map[types.IdentityHash]*boldyreva02.Shard[K])
	require.NoError(t, err)
	for i, shard := range shards {
		shardMap[identities[i].Hash()] = shard
		err = shard.Validate(cohortConfig)
		require.NoError(t, err)
	}
	return shardMap
}
