package fuzz

import (
	"crypto/sha256"
	"crypto/sha512"
	"encoding/base64"
	"fmt"
	"hash"
	"io"
	"math"
	"math/rand"
	"strings"
	"testing"

	fuzz "github.com/google/gofuzz"
	"github.com/stretchr/testify/require"
	"golang.org/x/crypto/sha3"

	agreeonrandom_test_utils "github.com/copperexchange/knox-primitives/pkg/agreeonrandom/test_utils"
	"github.com/copperexchange/knox-primitives/pkg/core/curves"
	"github.com/copperexchange/knox-primitives/pkg/core/curves/edwards25519"
	"github.com/copperexchange/knox-primitives/pkg/core/curves/k256"
	"github.com/copperexchange/knox-primitives/pkg/core/curves/p256"
	"github.com/copperexchange/knox-primitives/pkg/core/integration"
	test_utils_integration "github.com/copperexchange/knox-primitives/pkg/core/integration/test_utils"
	"github.com/copperexchange/knox-primitives/pkg/core/protocols"
	"github.com/copperexchange/knox-primitives/pkg/dkg/pedersen"
	"github.com/copperexchange/knox-primitives/pkg/sharing/shamir"
	"github.com/copperexchange/knox-primitives/pkg/signatures/eddsa"
	"github.com/copperexchange/knox-primitives/pkg/signatures/schnorr"
	"github.com/copperexchange/knox-primitives/pkg/signatures/threshold"
	"github.com/copperexchange/knox-primitives/pkg/signatures/threshold/tschnorr/frost"
	"github.com/copperexchange/knox-primitives/pkg/signatures/threshold/tschnorr/frost/signing/noninteractive"
	"github.com/copperexchange/knox-primitives/pkg/signatures/threshold/tschnorr/frost/test_utils"
)

// testing with too many participants will slow down the fuzzer and it may cause the fuzzer to timeout or memory issue
var (
	maxParticipants          = 10
	maxNumberOfPreSignatures = 100
)

// we assume that input curves and hash functions are valid
var (
	allCurves = []curves.Curve{edwards25519.New(), k256.New(), p256.New()}
	allHashes = []func() hash.Hash{sha3.New256, sha512.New, sha256.New}
)

// Fuzz test for the FROST protocol (DKG + interactive signing)
// This test makes following assumptions:
// 1. input curves and hash functions are valid
// 2. n is between 2 and 10
// 3. threshold is between 2 and n
// 4. randomSeed is a valid int64
// Returns 1 if the fuzzer does not find a bug, 0 if inputs is not valid, panic if it finds a bug
func FuzzFrostDkgInteractiveSigning(f *testing.F) {
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
		random := rand.New(rand.NewSource(randomSeed))
		curveIndex = random.Intn(len(allCurves))
		hashIndex = random.Intn(len(allHashes))
		n = random.Intn(maxParticipants-2) + 2                      // n is between 2 and 10
		threshold = random.Intn(int(math.Max(float64(n-2), 1))) + 2 // threshold is between 2 and n
		fmt.Println("curveIndex: ", curveIndex, "hashIndex: ", hashIndex, "n: ", n, "threshold: ", threshold, "randomSeed: ", randomSeed, "message: ", message)
		curve := allCurves[curveIndex%len(allCurves)]
		h := allHashes[hashIndex%len(allHashes)]

		identities, cohortConfig, _, signingKeyShares, publicKeyShares := doDkg(t, curve, h, n, fz, threshold, randomSeed)
		doInteractiveSigning(t, signingKeyShares, publicKeyShares, threshold, identities, cohortConfig, message)
		fmt.Println("OK")
	})
}

func FuzzFrostDkgNonInteractiveSigning(f *testing.F) {
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
		random := rand.New(rand.NewSource(randomSeed))
		curveIndex = random.Intn(len(allCurves))
		hashIndex = random.Intn(len(allHashes))
		n = random.Intn(maxParticipants-2) + 2                      // n is between 2 and 10
		threshold = random.Intn(int(math.Max(float64(n-2), 1))) + 2 // threshold is between 2 and n
		tau = random.Intn(maxNumberOfPreSignatures) + 2
		firstUnusedPreSignatureIndex = random.Intn(tau) + 2

		fmt.Println("curveIndex: ", curveIndex, "hashIndex: ", hashIndex, "n: ", n, "threshold: ", threshold, "randomSeed: ", randomSeed, "firstUnusedPreSignatureIndex: ", firstUnusedPreSignatureIndex, "message: ", message, "tau: ", tau)
		curve := allCurves[curveIndex%len(allCurves)]
		h := allHashes[hashIndex%len(allHashes)]

		identities, cohortConfig, participants, signingKeyShares, publicKeyShares := doDkg(t, curve, h, n, fz, threshold, randomSeed)

		preSignatureBatch, privateNoncePairsOfAllParties := doGeneratePreSignatures(t, cohortConfig, identities, tau, random, participants)
		doNonInteractiveSigning(t, signingKeyShares, publicKeyShares, cohortConfig, identities, preSignatureBatch, firstUnusedPreSignatureIndex, privateNoncePairsOfAllParties, random, participants, message)
		fmt.Println("OK")
	})
}

func doInteractiveSigning(t *testing.T, signingKeyShares []*threshold.SigningKeyShare, publicKeyShares []*threshold.PublicKeyShares, threshold int, identities []integration.IdentityKey, cohortConfig *integration.CohortConfig, message string) {
	t.Helper()
	var shards []*frost.Shard
	for i := range signingKeyShares {
		shards = append(shards, &frost.Shard{
			SigningKeyShare: signingKeyShares[i],
			PublicKeyShares: publicKeyShares[i],
		})
	}

	var signingIdentities []integration.IdentityKey
	for i := 0; i < threshold; i++ {
		signingIdentities = append(signingIdentities, identities[i])
	}

	signingParticipants, err := test_utils.MakeInteractiveSignParticipants(cohortConfig, signingIdentities, shards)
	require.NoError(t, err)
	for _, participant := range signingParticipants {
		if participant == nil {
			require.Error(t, fmt.Errorf("participant is nil"))
		}
	}

	r1Out, err := test_utils.DoInteractiveSignRound1(signingParticipants)
	require.NoError(t, err)

	r2In := test_utils.MapInteractiveSignRound1OutputsToRound2Inputs(signingParticipants, r1Out)
	partialSignatures, err := test_utils.DoInteractiveSignRound2(signingParticipants, r2In, []byte(message))
	require.NoError(t, err)

	mappedPartialSignatures := test_utils.MapPartialSignatures(signingIdentities, partialSignatures)
	var producedSignatures []*eddsa.Signature
	for i, participant := range signingParticipants {
		if cohortConfig.IsSignatureAggregator(participant.MyIdentityKey) {
			signature, err := participant.Aggregate([]byte(message), mappedPartialSignatures)
			producedSignatures = append(producedSignatures, signature)
			require.NoError(t, err)
			err = eddsa.Verify(cohortConfig.CipherSuite.Curve, cohortConfig.CipherSuite.Hash, signature, signingKeyShares[i].PublicKey, []byte(message))
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
			if producedSignatures[i].Z.Cmp(producedSignatures[j].Z) != 0 {
				require.Error(t, fmt.Errorf("signatures not the same"))
			}
		}
	}
}

func doNonInteractiveSigning(t *testing.T, signingKeyShares []*threshold.SigningKeyShare, publicKeyShares []*threshold.PublicKeyShares, cohortConfig *integration.CohortConfig, identities []integration.IdentityKey, preSignatureBatch []*noninteractive.PreSignatureBatch, firstUnusedPreSignatureIndex int, privateNoncePairsOfAllParties [][]*noninteractive.PrivateNoncePair, random *rand.Rand, participants []*pedersen.Participant, message string) {
	t.Helper()
	var shards []*frost.Shard
	var err error
	for i := range signingKeyShares {
		shards = append(shards, &frost.Shard{
			SigningKeyShare: signingKeyShares[i],
			PublicKeyShares: publicKeyShares[i],
		})
	}

	cosigners := make([]*noninteractive.Cosigner, cohortConfig.TotalParties)
	for i, identity := range identities {
		cosigners[i], err = noninteractive.NewNonInteractiveCosigner(identity, shards[i], preSignatureBatch[0], firstUnusedPreSignatureIndex, privateNoncePairsOfAllParties[i], identities, cohortConfig, random)
		require.NoError(t, err)
	}

	partialSignatures := make([]*frost.PartialSignature, len(participants))
	for i, participant := range cosigners {
		partialSignatures[i], err = participant.ProducePartialSignature([]byte(message))
		require.NoError(t, err)
	}
	mappedPartialSignatures := test_utils.MapPartialSignatures(identities, partialSignatures)
	signatureHashSet := map[string]bool{}
	for i, cosigner := range cosigners {
		if cosigner.IsSignatureAggregator() {
			signature, err := cosigner.Aggregate([]byte(message), firstUnusedPreSignatureIndex, mappedPartialSignatures)
			require.NoError(t, err)

			s, err := signature.MarshalBinary()
			require.NoError(t, err)
			signatureHashSet[base64.StdEncoding.EncodeToString(s)] = true

			err = eddsa.Verify(cohortConfig.CipherSuite.Curve, cohortConfig.CipherSuite.Hash, signature, signingKeyShares[i].PublicKey, []byte(message))
			require.NoError(t, err)
		}
	}
	require.Len(t, signatureHashSet, 1)
}

func doGeneratePreSignatures(t *testing.T, cohortConfig *integration.CohortConfig, identities []integration.IdentityKey, tau int, random *rand.Rand, participants []*pedersen.Participant) ([]*noninteractive.PreSignatureBatch, [][]*noninteractive.PrivateNoncePair) {
	t.Helper()
	pregenParticipants := make([]*noninteractive.PreGenParticipant, cohortConfig.TotalParties)
	var err error
	for i, identity := range identities {
		pregenParticipants[i], err = noninteractive.NewPreGenParticipant(identity, cohortConfig, tau, random)
		require.NoError(t, err)
	}
	round1Outputs := make([]*noninteractive.Round1Broadcast, len(participants))
	for i, participant := range pregenParticipants {
		round1Outputs[i], err = participant.Round1()
		require.NoError(t, err)
	}
	round2Inputs := make([]map[integration.IdentityHash]*noninteractive.Round1Broadcast, len(participants))
	for i := range participants {
		round2Inputs[i] = make(map[integration.IdentityHash]*noninteractive.Round1Broadcast)
		for j := range participants {
			if j != i {
				round2Inputs[i][participants[j].MyIdentityKey.Hash()] = round1Outputs[j]
			}
		}
	}
	preSignatureBatch := make([]*noninteractive.PreSignatureBatch, len(participants))
	privateNoncePairsOfAllParties := make([][]*noninteractive.PrivateNoncePair, len(participants))
	for i, participant := range pregenParticipants {
		preSignatureBatch[i], privateNoncePairsOfAllParties[i], err = participant.Round2(round2Inputs[i])
		require.NoError(t, err)
	}
	return preSignatureBatch, privateNoncePairsOfAllParties
}

func doDkg(t *testing.T, curve curves.Curve, h func() hash.Hash, n int, fz *fuzz.Fuzzer, threshold int, randomSeed int64) ([]integration.IdentityKey, *integration.CohortConfig, []*pedersen.Participant, []*threshold.SigningKeyShare, []*threshold.PublicKeyShares) {
	t.Helper()
	cipherSuite := &integration.CipherSuite{
		Curve: curve,
		Hash:  h,
	}

	var identities []integration.IdentityKey
	for i := 0; i < n; i++ {
		var transcriptPrefixes string
		var transcriptSuffixes string
		var secretValue string
		fz.Fuzz(&transcriptPrefixes)
		fz.Fuzz(&transcriptSuffixes)
		fz.Fuzz(&secretValue)
		identity, err := test_utils_integration.MakeIdentity(cipherSuite, curve.Scalar().Hash([]byte(secretValue)), &schnorr.Options{
			TranscriptPrefixes: [][]byte{[]byte(transcriptPrefixes)},
			TranscriptSuffixes: [][]byte{[]byte(transcriptSuffixes)},
		})
		require.NoError(t, err)
		identities = append(identities, identity)
	}

	cohortConfig, err := test_utils_integration.MakeCohort(cipherSuite, protocols.FROST, identities, threshold, identities)
	require.NoError(t, err)
	uniqueSessionId, err := agreeonrandom_test_utils.ProduceSharedRandomValue(curve, identities)
	if err != nil {
		if strings.Contains(err.Error(), "duplicate identity keys") {
			t.SkipNow()
		}
	}
	require.NoError(t, err)
	var randoms []io.Reader
	for i := 0; i < n; i++ {
		randoms = append(randoms, rand.New(rand.NewSource(randomSeed+int64(i))))
	}
	participants, err := test_utils.MakeDkgParticipants(uniqueSessionId, cohortConfig, identities, randoms)
	require.NoError(t, err)
	r1OutsB, r1OutsU, err := test_utils.DoDkgRound1(participants)
	require.NoError(t, err)
	r2InsB, r2InsU := test_utils.MapDkgRound1OutputsToRound2Inputs(participants, r1OutsB, r1OutsU)
	signingKeyShares, publicKeyShares, err := test_utils.DoDkgRound2(participants, r2InsB, r2InsU)
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
	shamirDealer, err := shamir.NewDealer(threshold, n, curve)
	require.NoError(t, err)
	require.NotNil(t, shamirDealer)
	shamirShares := make([]*shamir.Share, len(participants))
	for i := 0; i < len(participants); i++ {
		shamirShares[i] = &shamir.Share{
			Id:    participants[i].GetSharingId(),
			Value: signingKeyShares[i].Share,
		}
	}

	reconstructedPrivateKey, err := shamirDealer.Combine(shamirShares...)
	require.NoError(t, err)

	derivedPublicKey := curve.ScalarBaseMult(reconstructedPrivateKey)
	if signingKeyShares[0].PublicKey.Equal(derivedPublicKey) == false {
		require.Error(t, fmt.Errorf("public key does not match"))
	}
	return identities, cohortConfig, participants, signingKeyShares, publicKeyShares
}
