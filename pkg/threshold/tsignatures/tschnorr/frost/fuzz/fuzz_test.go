package fuzz

import (
	crand "crypto/rand"
	"crypto/sha256"
	"crypto/sha512"
	"encoding/base64"
	"fmt"
	"hash"
	"io"
	"math"
	"math/rand"
	"testing"

	fuzz "github.com/google/gofuzz"
	"github.com/stretchr/testify/require"
	"golang.org/x/crypto/sha3"

	"github.com/copperexchange/krypton-primitives/pkg/base/curves"
	"github.com/copperexchange/krypton-primitives/pkg/base/curves/edwards25519"
	"github.com/copperexchange/krypton-primitives/pkg/base/curves/k256"
	"github.com/copperexchange/krypton-primitives/pkg/base/curves/p256"
	"github.com/copperexchange/krypton-primitives/pkg/base/datastructures/hashset"
	"github.com/copperexchange/krypton-primitives/pkg/base/errs"
	"github.com/copperexchange/krypton-primitives/pkg/base/types"
	ttu "github.com/copperexchange/krypton-primitives/pkg/base/types/testutils"
	schnorr "github.com/copperexchange/krypton-primitives/pkg/signatures/schnorr/vanilla"
	agreeonrandom_testutils "github.com/copperexchange/krypton-primitives/pkg/threshold/agreeonrandom/testutils"
	"github.com/copperexchange/krypton-primitives/pkg/threshold/dkg/pedersen"
	"github.com/copperexchange/krypton-primitives/pkg/threshold/sharing/shamir"
	"github.com/copperexchange/krypton-primitives/pkg/threshold/tsignatures"
	"github.com/copperexchange/krypton-primitives/pkg/threshold/tsignatures/tschnorr/frost"
	"github.com/copperexchange/krypton-primitives/pkg/threshold/tsignatures/tschnorr/frost/noninteractive_signing"
	"github.com/copperexchange/krypton-primitives/pkg/threshold/tsignatures/tschnorr/frost/testutils"
)

// testing with too many participants will slow down the fuzzer and it may cause the fuzzer to timeout or memory issue
var (
	maxParticipants          = 5
	maxNumberOfPreSignatures = 10
)

// we assume that input curves and hash functions are valid
var (
	allCurves = []curves.Curve{edwards25519.NewCurve(), k256.NewCurve(), p256.NewCurve()}
	allHashes = []func() hash.Hash{sha3.New256, sha512.New, sha256.New}
)

// Fuzz test for the FROST protocol (DKG + interactive signing)
// This test makes following assumptions:
// 1. input curves and hash functions are valid
// 2. n is between 2 and 10
// 3. threshold is between 2 and n
// 4. randomSeed is a valid int64
// Returns 1 if the fuzzer does not find a bug, 0 if inputs is not valid, panic if it finds a bug
func FuzzInteractiveSigning(f *testing.F) {
	f.Fuzz(func(t *testing.T, data []byte) {
		fz := fuzz.NewFromGoFuzz(data).NilChance(0.05) // 5% chance of generating nil inputs
		var curveIndex int
		var hashIndex int
		var n int
		var threshold int
		var randomSeed int64
		fz.Fuzz(&curveIndex)
		fz.Fuzz(&hashIndex)
		fz.Fuzz(&randomSeed)
		var message string
		fz.Fuzz(&message)
		if message == "" {
			message = string([]byte{1})
		}
		prng := rand.New(rand.NewSource(randomSeed))
		curveIndex = prng.Intn(len(allCurves))
		hashIndex = prng.Intn(len(allHashes))
		n = prng.Intn(maxParticipants-2) + 2                      // n is between 2 and 10
		threshold = prng.Intn(int(math.Max(float64(n-2), 1))) + 2 // threshold is between 2 and n
		fmt.Println("curveIndex: ", curveIndex, "hashIndex: ", hashIndex, "n: ", n, "threshold: ", threshold, "randomSeed: ", randomSeed, "message: ", message)
		curve := allCurves[curveIndex%len(allCurves)]
		h := allHashes[hashIndex%len(allHashes)]

		identities, cohortConfig, _, signingKeyShares, publicKeyShares := doDkg(t, curve, h, n, fz, threshold, randomSeed)
		doInteractiveSigning(t, signingKeyShares, publicKeyShares, threshold, identities, cohortConfig, message)
		fmt.Println("OK")
	})
}

func FuzzNonInteractiveSigning(f *testing.F) {
	f.Fuzz(func(t *testing.T, data []byte) {
		fz := fuzz.NewFromGoFuzz(data).NilChance(0.05) // 5% chance of generating nil inputs
		var curveIndex int
		var hashIndex int
		var n int
		var threshold int
		var tau int
		var randomSeed int64
		var firstUnusedPreSignatureIndex int
		fz.Fuzz(&firstUnusedPreSignatureIndex)
		fz.Fuzz(&curveIndex)
		fz.Fuzz(&hashIndex)
		fz.Fuzz(&n)
		fz.Fuzz(&threshold)
		fz.Fuzz(&randomSeed)
		var message string
		fz.Fuzz(&message)
		if message == "" {
			message = string([]byte{1})
		}
		prng := rand.New(rand.NewSource(randomSeed))
		curveIndex = prng.Intn(len(allCurves))
		hashIndex = prng.Intn(len(allHashes))
		n = prng.Intn(maxParticipants-2) + 2                      // n is between 2 and 10
		threshold = prng.Intn(int(math.Max(float64(n-2), 1))) + 2 // threshold is between 2 and n
		tau = prng.Intn(maxNumberOfPreSignatures) + 2
		firstUnusedPreSignatureIndex = firstUnusedPreSignatureIndex % tau
		if firstUnusedPreSignatureIndex < 0 {
			firstUnusedPreSignatureIndex = -firstUnusedPreSignatureIndex
		}

		fmt.Println("curveIndex: ", curveIndex, "hashIndex: ", hashIndex, "n: ", n, "threshold: ", threshold, "randomSeed: ", randomSeed, "firstUnusedPreSignatureIndex: ", firstUnusedPreSignatureIndex, "message: ", message, "tau: ", tau)
		curve := allCurves[curveIndex%len(allCurves)]
		h := allHashes[hashIndex%len(allHashes)]

		identities, cohortConfig, participants, signingKeyShares, publicKeyShares := doDkg(t, curve, h, n, fz, threshold, randomSeed)

		preSignatureBatch, privateNoncePairsOfAllParties := doGeneratePreSignatures(t, cohortConfig, identities, tau, prng, participants)
		doNonInteractiveSigning(t, signingKeyShares, publicKeyShares, cohortConfig, identities, preSignatureBatch, firstUnusedPreSignatureIndex, privateNoncePairsOfAllParties, prng, participants, message)
		fmt.Println("OK")
	})
}

func doInteractiveSigning(t *testing.T, signingKeyShares []*tsignatures.SigningKeyShare, publicKeyShares []*tsignatures.PartialPublicKeys, threshold int, identities []types.IdentityKey, protocol types.ThresholdSignatureProtocol, message string) {
	t.Helper()
	var shards []*frost.Shard
	for i := range signingKeyShares {
		shards = append(shards, &frost.Shard{
			SigningKeyShare: signingKeyShares[i],
			PublicKeyShares: publicKeyShares[i],
		})
	}

	var signingIdentities []types.IdentityKey
	for i := 0; i < threshold; i++ {
		signingIdentities = append(signingIdentities, identities[i])
	}

	signingParticipants, err := testutils.MakeInteractiveSignParticipants(protocol, signingIdentities, shards)
	require.NoError(t, err)
	for _, participant := range signingParticipants {
		if participant == nil {
			require.Error(t, fmt.Errorf("participant is nil"))
		}
	}

	r1Out, err := testutils.DoInteractiveSignRound1(signingParticipants)
	require.NoError(t, err)

	r2In := ttu.MapBroadcastO2I(signingParticipants, r1Out)
	partialSignatures, err := testutils.DoInteractiveSignRound2(signingParticipants, r2In, []byte(message))
	require.NoError(t, err)

	mappedPartialSignatures := testutils.MapPartialSignatures(signingIdentities, partialSignatures)
	var producedSignatures []*schnorr.Signature
	for i, participant := range signingParticipants {
		if participant.IsSignatureAggregator() {
			signature, err := participant.Aggregate([]byte(message), mappedPartialSignatures)
			producedSignatures = append(producedSignatures, signature)
			require.NoError(t, err)
			err = schnorr.Verify(protocol.CipherSuite(), &schnorr.PublicKey{A: signingKeyShares[i].PublicKey}, []byte(message), signature)
			require.NoError(t, err)
		}
	}
	if len(producedSignatures) == 0 {
		require.Error(t, fmt.Errorf("no signatures produced"))
	}

	// all signatures the same
	for i := 0; i < len(producedSignatures); i++ {
		for j := i + 1; j < len(producedSignatures); j++ {
			if producedSignatures[i].R.Equal(producedSignatures[j].R) == false {
				require.Error(t, fmt.Errorf("signatures not the same"))
			}
			if producedSignatures[i].S.Cmp(producedSignatures[j].S) != 0 {
				require.Error(t, fmt.Errorf("signatures not the same"))
			}
		}
	}
}

func doNonInteractiveSigning(t *testing.T, signingKeyShares []*tsignatures.SigningKeyShare, publicKeyShares []*tsignatures.PartialPublicKeys, protocol types.ThresholdSignatureProtocol, identities []types.IdentityKey, preSignatureBatch []noninteractive_signing.PreSignatureBatch, firstUnusedPreSignatureIndex int, privateNoncePairsOfAllParties [][]*noninteractive_signing.PrivateNoncePair, random *rand.Rand, participants []*pedersen.Participant, message string) {
	t.Helper()
	var shards []*frost.Shard
	var err error
	for i := range signingKeyShares {
		shards = append(shards, &frost.Shard{
			SigningKeyShare: signingKeyShares[i],
			PublicKeyShares: publicKeyShares[i],
		})
	}

	cosigners := make([]*noninteractive_signing.Cosigner, protocol.TotalParties())
	for i, identity := range identities {
		cosigners[i], err = noninteractive_signing.NewNonInteractiveCosigner(identity.(types.AuthKey), shards[i], preSignatureBatch[0], firstUnusedPreSignatureIndex, privateNoncePairsOfAllParties[i], hashset.NewHashableHashSet(identities...), protocol, hashset.NewHashableHashSet(identities...), random)
		require.NoError(t, err)
	}

	partialSignatures := make([]*frost.PartialSignature, len(participants))
	for i, participant := range cosigners {
		partialSignatures[i], err = participant.ProducePartialSignature([]byte(message))
		require.NoError(t, err)
	}
	mappedPartialSignatures := testutils.MapPartialSignatures(identities, partialSignatures)
	signatureHashSet := map[string]bool{}
	for i, cosigner := range cosigners {
		if cosigner.IsSignatureAggregator() {
			signature, err := cosigner.Aggregate([]byte(message), firstUnusedPreSignatureIndex, mappedPartialSignatures)
			require.NoError(t, err)

			s, err := signature.MarshalBinary()
			require.NoError(t, err)
			signatureHashSet[base64.StdEncoding.EncodeToString(s)] = true

			err = schnorr.Verify(protocol.CipherSuite(), &schnorr.PublicKey{A: signingKeyShares[i].PublicKey}, []byte(message), signature)
			require.NoError(t, err)
		}
	}
	require.Len(t, signatureHashSet, 1)
}

func doGeneratePreSignatures(t *testing.T, protocol types.ThresholdProtocol, identities []types.IdentityKey, tau int, random *rand.Rand, participants []*pedersen.Participant) ([]noninteractive_signing.PreSignatureBatch, [][]*noninteractive_signing.PrivateNoncePair) {
	t.Helper()
	pregenParticipants := make([]*noninteractive_signing.PreGenParticipant, protocol.TotalParties())
	var err error
	for i, identity := range identities {
		pregenParticipants[i], err = noninteractive_signing.NewPreGenParticipant(identity.(types.AuthKey), protocol, tau, random)
		require.NoError(t, err)
	}
	round1Outputs := make([]*noninteractive_signing.Round1Broadcast, len(participants))
	for i, participant := range pregenParticipants {
		round1Outputs[i], err = participant.Round1()
		require.NoError(t, err)
	}
	round2Inputs := make([]types.RoundMessages[*noninteractive_signing.Round1Broadcast], len(participants))
	for i := range participants {
		round2Inputs[i] = types.NewRoundMessages[*noninteractive_signing.Round1Broadcast]()
		for j := range participants {
			if j != i {
				round2Inputs[i].Put(participants[j].IdentityKey(), round1Outputs[j])
			}
		}
	}
	preSignatureBatch := make([]noninteractive_signing.PreSignatureBatch, len(participants))
	privateNoncePairsOfAllParties := make([][]*noninteractive_signing.PrivateNoncePair, len(participants))
	for i, participant := range pregenParticipants {
		preSignatureBatch[i], privateNoncePairsOfAllParties[i], err = participant.Round2(round2Inputs[i])
		require.NoError(t, err)
	}
	return preSignatureBatch, privateNoncePairsOfAllParties
}

func doDkg(t *testing.T, curve curves.Curve, h func() hash.Hash, n int, fz *fuzz.Fuzzer, threshold int, randomSeed int64) ([]types.IdentityKey, types.ThresholdSignatureProtocol, []*pedersen.Participant, []*tsignatures.SigningKeyShare, []*tsignatures.PartialPublicKeys) {
	t.Helper()
	cipherSuite, _ := ttu.MakeSignatureProtocol(curve, h)

	var identities []types.IdentityKey
	for i := 0; i < n; i++ {
		var transcriptPrefixes string
		var transcriptSuffixes string
		var secretValue string
		fz.Fuzz(&transcriptPrefixes)
		fz.Fuzz(&transcriptSuffixes)
		fz.Fuzz(&secretValue)
		commitedScalar, err := curve.ScalarField().Hash([]byte(secretValue))
		require.NoError(t, err)
		identity, err := ttu.MakeTestIdentity(cipherSuite, commitedScalar)
		require.NoError(t, err)
		identities = append(identities, identity)
	}

	protocol, err := ttu.MakeThresholdSignatureProtocol(cipherSuite, identities, threshold, identities)
	if err != nil {
		if errs.IsDuplicate(err) || errs.IsCount(err) {
			t.SkipNow()
		} else {
			require.NoError(t, err)
		}
	}
	uniqueSessionId, err := agreeonrandom_testutils.RunAgreeOnRandom(curve, identities, crand.Reader)
	if err != nil {
		if errs.IsDuplicate(err) || errs.IsCount(err) {
			t.SkipNow()
		} else {
			require.NoError(t, err)
		}
	}
	require.NoError(t, err)
	var randoms []io.Reader
	for i := 0; i < n; i++ {
		randoms = append(randoms, rand.New(rand.NewSource(randomSeed+int64(i))))
	}
	participants, err := testutils.MakeDkgParticipants(uniqueSessionId, protocol, identities, randoms)
	if err != nil {
		if !errs.IsKnownError(err) {
			require.NoError(t, err)
		} else {
			t.Skip()
		}
	}
	r1OutsB, r1OutsU, err := testutils.DoDkgRound1(participants, nil)
	require.NoError(t, err)
	r2InsB, r2InsU := ttu.MapO2I(participants, r1OutsB, r1OutsU)
	signingKeyShares, publicKeyShares, err := testutils.DoDkgRound2(participants, r2InsB, r2InsU)
	require.NoError(t, err)
	for _, publicKeyShare := range publicKeyShares {
		if publicKeyShare == nil {
			require.Error(t, fmt.Errorf("public key share is nil"))
		}
	}
	for i := 0; i < len(signingKeyShares); i++ {
		for j := i + 1; j < len(signingKeyShares); j++ {
			if signingKeyShares[i].Share.Cmp(signingKeyShares[j].Share) == 0 {
				require.Error(t, fmt.Errorf("duplicate signing key shares"))
			}
		}
	}

	for i := 0; i < len(signingKeyShares); i++ {
		for j := i + 1; j < len(signingKeyShares); j++ {
			if signingKeyShares[i].PublicKey.Equal(signingKeyShares[i].PublicKey) == false {
				require.Error(t, fmt.Errorf("duplicate public key shares"))
			}
		}
	}
	shamirDealer, err := shamir.NewDealer(uint(threshold), uint(n), curve)
	require.NoError(t, err)
	require.NotNil(t, shamirDealer)
	shamirShares := make([]*shamir.Share, len(participants))
	for i := 0; i < len(participants); i++ {
		shamirShares[i] = &shamir.Share{
			Id:    uint(participants[i].SharingId()),
			Value: signingKeyShares[i].Share,
		}
	}

	reconstructedPrivateKey, err := shamirDealer.Combine(shamirShares...)
	require.NoError(t, err)

	derivedPublicKey := curve.ScalarBaseMult(reconstructedPrivateKey)
	if signingKeyShares[0].PublicKey.Equal(derivedPublicKey) == false {
		require.Error(t, fmt.Errorf("public key does not match"))
	}
	return identities, protocol, participants, signingKeyShares, publicKeyShares
}
