package noninteractive_test

import (
	"crypto/sha512"
	"encoding/base64"
	"fmt"
	"hash"
	"os"
	"reflect"
	"runtime"
	"strconv"
	"strings"
	"testing"

	"github.com/stretchr/testify/require"
	"golang.org/x/crypto/sha3"

	agreeonrandom_test_utils "github.com/copperexchange/knox-primitives/pkg/agreeonrandom/test_utils"
	"github.com/copperexchange/knox-primitives/pkg/core/curves"
	"github.com/copperexchange/knox-primitives/pkg/core/errs"
	"github.com/copperexchange/knox-primitives/pkg/core/integration"
	test_utils_integration "github.com/copperexchange/knox-primitives/pkg/core/integration/test_utils"
	"github.com/copperexchange/knox-primitives/pkg/core/protocols"
	"github.com/copperexchange/knox-primitives/pkg/signatures/eddsa"
	"github.com/copperexchange/knox-primitives/pkg/signatures/threshold/tschnorr/frost"
	"github.com/copperexchange/knox-primitives/pkg/signatures/threshold/tschnorr/frost/signing/noninteractive"
	"github.com/copperexchange/knox-primitives/pkg/signatures/threshold/tschnorr/frost/test_utils"
)

func doDkg(curve *curves.Curve, cohortConfig *integration.CohortConfig, identities []integration.IdentityKey) (signingKeyShares []*frost.SigningKeyShare, publicKeyShares []*frost.PublicKeyShares, err error) {
	uniqueSessionId, err := agreeonrandom_test_utils.ProduceSharedRandomValue(curve, identities)
	if err != nil {
		return nil, nil, err
	}
	dkgParticipants, err := test_utils.MakeDkgParticipants(uniqueSessionId, cohortConfig, identities, nil)
	if err != nil {
		return nil, nil, err
	}

	r2OutB, r2OutU, err := test_utils.DoDkgRound1(dkgParticipants)
	if err != nil {
		return nil, nil, err
	}

	r3InB, r3InU := test_utils.MapDkgRound1OutputsToRound2Inputs(dkgParticipants, r2OutB, r2OutU)
	signingKeyShares, publicKeyShares, err = test_utils.DoDkgRound2(dkgParticipants, r3InB, r3InU)
	if err != nil {
		return nil, nil, err
	}

	return signingKeyShares, publicKeyShares, nil
}

func doPreGen(cohortConfig *integration.CohortConfig, tau int) (*noninteractive.PreSignatureBatch, [][]*noninteractive.PrivateNoncePair, error) {
	participants, err := test_utils.MakePreGenParticipants(cohortConfig, tau)
	if err != nil {
		return nil, nil, err
	}
	r1Outs, err := test_utils.DoPreGenRound1(participants)
	if err != nil {
		return nil, nil, err
	}
	r2Ins := test_utils.MapPreGenRound1OutputsToRound2Inputs(participants, r1Outs)
	preSignatureBatches, privateNoncePairsOfAllParties, err := test_utils.DoPreGenRound2(participants, r2Ins)
	if err != nil {
		return nil, nil, err
	}
	return preSignatureBatches[0], privateNoncePairsOfAllParties, nil
}

func doNonInteractiveSign(cohortConfig *integration.CohortConfig, identities []integration.IdentityKey, signingKeyShares []*frost.SigningKeyShare, publicKeySharesOfAllParties []*frost.PublicKeyShares, preSignatureBatch *noninteractive.PreSignatureBatch, firstUnusedPreSignatureIndex []int, privateNoncePairsOfAllParties [][]*noninteractive.PrivateNoncePair, message []byte) error {
	var shards []*frost.Shard
	for i := range signingKeyShares {
		shards = append(shards, &frost.Shard{
			SigningKeyShare: signingKeyShares[i],
			PublicKeyShares: publicKeySharesOfAllParties[i],
		})
	}

	cosigners, err := test_utils.MakeNonInteractiveCosigners(cohortConfig, identities, shards, preSignatureBatch, firstUnusedPreSignatureIndex, privateNoncePairsOfAllParties)
	if err != nil {
		return err
	}

	partialSignatures, err := test_utils.DoProducePartialSignature(cosigners, message)
	if err != nil {
		return err
	}

	mappedPartialSignatures := test_utils.MapPartialSignatures(identities, partialSignatures)
	signatureHashSet := map[string]bool{}
	for i, cosigner := range cosigners {
		if cosigner.IsSignatureAggregator() {
			signature, err := cosigner.Aggregate(message, firstUnusedPreSignatureIndex[i], mappedPartialSignatures)
			if err != nil {
				return err
			}

			s, err := signature.MarshalBinary()
			if err != nil {
				return err
			}
			signatureHashSet[base64.StdEncoding.EncodeToString(s)] = true

			err = eddsa.Verify(cohortConfig.CipherSuite.Curve, cohortConfig.CipherSuite.Hash, signature, signingKeyShares[i].PublicKey, message)
			if err != nil {
				return err
			}
		}
	}
	// all signatures are equal
	if len(signatureHashSet) != 1 {
		return errs.NewFailed("signatures are not equal")
	}
	return nil
}

func testHappyPath(t *testing.T, protocol protocols.Protocol, curve *curves.Curve, hash func() hash.Hash, threshold, n, tau, firstUnusedPreSignatureIndex int) {
	t.Helper()

	message := []byte("something")

	cipherSuite := &integration.CipherSuite{
		Curve: curve,
		Hash:  hash,
	}

	allIdentities, err := test_utils_integration.MakeIdentities(cipherSuite, n)
	require.NoError(t, err)

	cohortConfig, err := test_utils_integration.MakeCohort(cipherSuite, protocol, allIdentities, threshold, allIdentities)
	require.NoError(t, err)

	allSigningKeyShares, allPublicKeyShares, err := doDkg(curve, cohortConfig, allIdentities)
	require.NoError(t, err)

	for i, share := range allSigningKeyShares {
		keyShare, _ := allPublicKeyShares[i].SharesMap.Get(allIdentities[i])
		require.True(t, keyShare.Equal(curve.ScalarBaseMult(share.Share)))
	}

	preSignatureBatch, privateNoncePairsOfAllParties, err := doPreGen(cohortConfig, tau)
	require.NoError(t, err)

	firstUnusedPreSignatureIndices := make([]int, n)
	for i := 0; i < n; i++ {
		firstUnusedPreSignatureIndices[i] = firstUnusedPreSignatureIndex
	}

	err = doNonInteractiveSign(cohortConfig, allIdentities, allSigningKeyShares, allPublicKeyShares, preSignatureBatch, firstUnusedPreSignatureIndices, privateNoncePairsOfAllParties, message)
	require.NoError(t, err)
}

func TestSignNilMessage(t *testing.T) {
	t.Helper()
	curve := curves.ED25519()
	hash := sha3.New256

	cipherSuite := &integration.CipherSuite{
		Curve: curve,
		Hash:  hash,
	}

	allIdentities, err := test_utils_integration.MakeIdentities(cipherSuite, 2)
	require.NoError(t, err)

	cohortConfig, err := test_utils_integration.MakeCohort(cipherSuite, protocols.FROST, allIdentities, 2, allIdentities)
	require.NoError(t, err)

	allSigningKeyShares, allPublicKeyShares, err := doDkg(curve, cohortConfig, allIdentities)
	require.NoError(t, err)

	for i, share := range allSigningKeyShares {
		keyShare, _ := allPublicKeyShares[i].SharesMap.Get(allIdentities[i])
		require.True(t, keyShare.Equal(curve.ScalarBaseMult(share.Share)))
	}

	preSignatureBatch, privateNoncePairsOfAllParties, err := doPreGen(cohortConfig, 5)
	require.NoError(t, err)

	firstUnusedPreSignatureIndices := make([]int, 2)
	for i := 0; i < 2; i++ {
		firstUnusedPreSignatureIndices[i] = 0
	}

	err = doNonInteractiveSign(cohortConfig, allIdentities, allSigningKeyShares, allPublicKeyShares, preSignatureBatch, firstUnusedPreSignatureIndices, privateNoncePairsOfAllParties, nil)
	require.True(t, errs.IsIsNil(err))

	err = doNonInteractiveSign(cohortConfig, allIdentities, allSigningKeyShares, allPublicKeyShares, preSignatureBatch, firstUnusedPreSignatureIndices, privateNoncePairsOfAllParties, []byte{})
	require.True(t, errs.IsIsZero(err))
}

func TestHappyPath(t *testing.T) {
	t.Parallel()

	for _, curve := range []*curves.Curve{curves.ED25519(), curves.K256()} {
		for _, h := range []func() hash.Hash{sha3.New256, sha512.New} {
			for _, tau := range []int{2, 5} {
				for firstUnusedPreSignatureIndex := 0; firstUnusedPreSignatureIndex < tau; firstUnusedPreSignatureIndex++ {
					for _, thresholdConfig := range []struct {
						t int
						n int
					}{
						{t: 2, n: 3},
						{t: 3, n: 5},
						{t: 2, n: 2},
					} {
						boundedCurve := curve
						boundedHash := h
						boundedHashName := runtime.FuncForPC(reflect.ValueOf(h).Pointer()).Name()
						boundedThresholdConfig := thresholdConfig
						boundedTau := tau
						firstUnusedPreSignatureIndex := firstUnusedPreSignatureIndex
						t.Run(fmt.Sprintf("testing non interactive signing with curve=%s and hash=%s and t=%d and n=%d and tau=%d and first unused pre signature index=%d", boundedCurve.Name, boundedHashName[strings.LastIndex(boundedHashName, "/")+1:], boundedThresholdConfig.t, boundedThresholdConfig.n, boundedTau, firstUnusedPreSignatureIndex), func(t *testing.T) {
							t.Parallel()
							testHappyPath(t, protocols.FROST, boundedCurve, boundedHash, boundedThresholdConfig.t, boundedThresholdConfig.n, boundedTau, firstUnusedPreSignatureIndex)
						})
					}
				}
			}
		}
	}
}

func TestRunProfile(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping profiling test in short mode")
	}
	if os.Getenv("PROFILE_T") == "" || os.Getenv("PROFILE_N") == "" {
		t.Skip("skipping profiling test missing parameter")
	}
	var curve *curves.Curve
	var h func() hash.Hash
	th, _ := strconv.Atoi(os.Getenv("PROFILE_T"))
	n, _ := strconv.Atoi(os.Getenv("PROFILE_N"))
	if os.Getenv("PROFILE_CURVE") == "ED25519" {
		curve = curves.ED25519()
	} else {
		curve = curves.K256()
	}
	if os.Getenv("PROFILE_HASH") == "SHA3" {
		h = sha3.New256
	} else {
		h = sha512.New
	}
	for i := 0; i < 1000; i++ {
		testHappyPath(t, protocols.FROST, curve, h, th, n, 10, 0)
	}
}
