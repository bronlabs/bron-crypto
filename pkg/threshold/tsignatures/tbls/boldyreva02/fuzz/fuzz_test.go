package fuzz

import (
	crand "crypto/rand"
	"crypto/sha256"
	"io"
	"math/rand"
	"testing"

	"github.com/stretchr/testify/require"

	"github.com/copperexchange/krypton-primitives/pkg/base/curves/bls12381"
	ds "github.com/copperexchange/krypton-primitives/pkg/base/datastructures"
	"github.com/copperexchange/krypton-primitives/pkg/base/datastructures/hashmap"
	"github.com/copperexchange/krypton-primitives/pkg/base/datastructures/hashset"
	"github.com/copperexchange/krypton-primitives/pkg/base/errs"
	"github.com/copperexchange/krypton-primitives/pkg/base/types"
	ttu "github.com/copperexchange/krypton-primitives/pkg/base/types/testutils"
	"github.com/copperexchange/krypton-primitives/pkg/signatures/bls"
	agreeonrandom_testutils "github.com/copperexchange/krypton-primitives/pkg/threshold/agreeonrandom/testutils"
	"github.com/copperexchange/krypton-primitives/pkg/threshold/tsignatures/tbls/boldyreva02"
	"github.com/copperexchange/krypton-primitives/pkg/threshold/tsignatures/tbls/boldyreva02/signing"
	"github.com/copperexchange/krypton-primitives/pkg/threshold/tsignatures/tbls/boldyreva02/testutils"
)

var schemes = []bls.RogueKeyPrevention{
	bls.Basic, bls.MessageAugmentation, bls.POP,
}

func Fuzz_Test(f *testing.F) {
	f.Add(uint(0), uint64(0), uint64(1), uint64(2), []byte("sid"), []byte("message"), int64(0))
	f.Fuzz(func(t *testing.T, schemeIndex uint, aliceSecret uint64, bobSecret uint64, charlieSecret uint64, sid []byte, message []byte, randomSeed int64) {
		roundtrip[bls12381.G1, bls12381.G2](t, schemeIndex, aliceSecret, bobSecret, charlieSecret, sid, message, randomSeed)
		roundtrip[bls12381.G2, bls12381.G1](t, schemeIndex, aliceSecret, bobSecret, charlieSecret, sid, message, randomSeed)
	})
}

func roundtrip[K bls.KeySubGroup, S bls.SignatureSubGroup](t *testing.T, schemeIndex uint, aliceSecret uint64, bobSecret uint64, charlieSecret uint64, sid []byte, message []byte, randomSeed int64) {
	t.Helper()
	scheme := schemes[schemeIndex%uint(len(schemes))]
	hashFunc := sha256.New

	if aliceSecret == 0 {
		aliceSecret++
	}
	if bobSecret == 0 {
		bobSecret++
	}
	if charlieSecret == 0 {
		charlieSecret++
	}

	if hashset.NewComparableHashSet(aliceSecret, bobSecret, charlieSecret).Size() != 3 {
		t.Skip()
	}

	keysSubGroup := bls12381.GetSourceSubGroup[K]()

	cipherSuite, err := ttu.MakeSignatureProtocol(keysSubGroup, hashFunc)
	require.NoError(t, err)

	aliceIdentity, _ := ttu.MakeTestIdentity(cipherSuite, keysSubGroup.ScalarField().New(aliceSecret))
	bobIdentity, _ := ttu.MakeTestIdentity(cipherSuite, keysSubGroup.ScalarField().New(bobSecret))
	charlieIdentity, _ := ttu.MakeTestIdentity(cipherSuite, keysSubGroup.ScalarField().New(charlieSecret))
	identities := []types.IdentityKey{aliceIdentity, bobIdentity, charlieIdentity}

	protocol, err := ttu.MakeThresholdSignatureProtocol(cipherSuite, identities, 2, identities)
	if err != nil && !errs.IsKnownError(err) {
		require.NoError(t, err)
	}
	if err != nil {
		t.Skip(err.Error())
	}
	require.NoError(t, err)

	shards := keygen[K](t, identities, 2, 3, randomSeed)
	shard, exists := shards.Get(identities[0])
	require.True(t, exists)

	publicKeyShares := shard.PublicKeyShares
	publicKey := publicKeyShares.PublicKey

	participants, err := testutils.MakeSigningParticipants[K, S](sid, protocol, identities, shards, scheme)
	require.NoError(t, err)

	partialSignatures, err := testutils.ProducePartialSignature(participants, message, bls.Basic)
	if err != nil && !errs.IsKnownError(err) {
		require.NoError(t, err)
	}
	if err != nil {
		t.Skip(err.Error())
	}
	require.NoError(t, err)

	sharingConfig := types.DeriveSharingConfig(protocol.Participants())
	aggregatorInput := testutils.MapPartialSignatures(identities, partialSignatures)

	signature, signaturePOP, err := signing.Aggregate(sharingConfig, publicKeyShares, aggregatorInput, message, scheme)
	require.NoError(t, err)

	err = bls.Verify(publicKey, signature, message, signaturePOP, scheme, nil)
	require.NoError(t, err)
}

func keygen[K bls.KeySubGroup](t *testing.T, identities []types.IdentityKey, threshold, n int, randomSeed int64) ds.HashMap[types.IdentityKey, *boldyreva02.Shard[K]] {
	t.Helper()

	curve := bls12381.GetSourceSubGroup[K]()
	require.Len(t, identities, n)

	cipherSuite, err := ttu.MakeSignatureProtocol(curve, sha256.New)
	require.NoError(t, err)

	inG1 := curve.Name() == bls12381.NameG1
	inG1s := make([]bool, n)
	for i := 0; i < n; i++ {
		inG1s[i] = inG1
	}

	protocol, err := ttu.MakeThresholdProtocol(cipherSuite.Curve(), identities, threshold)
	require.NoError(t, err)
	require.Equal(t, n, protocol.Participants().Size())

	uniqueSessionId, err := agreeonrandom_testutils.RunAgreeOnRandom(curve, identities, crand.Reader)
	require.NoError(t, err)

	randoms := make([]io.Reader, n)
	for i := 0; i < n; i++ {
		randoms[i] = rand.New(rand.NewSource(randomSeed + int64(i)))
	}
	participants, err := testutils.MakeDkgParticipants[K](uniqueSessionId, protocol, identities, randoms)
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
	shardMap := hashmap.NewHashableHashMap[types.IdentityKey, *boldyreva02.Shard[K]]()
	require.NoError(t, err)
	for i, shard := range shards {
		shardMap.Put(identities[i], shard)
		err = shard.Validate(protocol)
		require.NoError(t, err)
	}
	return shardMap
}
