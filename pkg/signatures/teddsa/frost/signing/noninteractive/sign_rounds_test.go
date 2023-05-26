package noninteractive_test

import (
	"crypto/sha512"
	"encoding/base64"
	"fmt"
	"hash"
	"reflect"
	"runtime"
	"strings"
	"testing"

	"github.com/copperexchange/crypto-primitives-go/pkg/core/curves"
	"github.com/copperexchange/crypto-primitives-go/pkg/core/integration"
	"github.com/copperexchange/crypto-primitives-go/pkg/core/protocol"
	"github.com/copperexchange/crypto-primitives-go/pkg/signatures/teddsa/frost"
	"github.com/copperexchange/crypto-primitives-go/pkg/signatures/teddsa/frost/signing/noninteractive"
	"github.com/copperexchange/crypto-primitives-go/pkg/signatures/teddsa/test_utils"
	"github.com/stretchr/testify/require"
	"golang.org/x/crypto/sha3"
)

func doDkg(cohortConfig *integration.CohortConfig, identities []integration.IdentityKey) (signingKeyShares []*frost.SigningKeyShare, publicKeyShares []*frost.PublicKeyShares, err error) {
	dkgParticipants, err := test_utils.MakeDkgParticipants(cohortConfig, identities)
	if err != nil {
		return nil, nil, err
	}

	r1Out, err := test_utils.DoDkgRound1(dkgParticipants)
	if err != nil {
		return nil, nil, err
	}

	r2In := test_utils.MapDkgRound1OutputsToRound2Inputs(dkgParticipants, r1Out)
	r2OutB, r2OutU, err := test_utils.DoDkgRound2(dkgParticipants, r2In)
	if err != nil {
		return nil, nil, err
	}

	r3InB, r3InU := test_utils.MapDkgRound2OutputsToRound3Inputs(dkgParticipants, r2OutB, r2OutU)
	signingKeyShares, publicKeyShares, err = test_utils.DoDkgRound3(dkgParticipants, r3InB, r3InU)
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

func doNonInteractiveSign(t *testing.T, cohortConfig *integration.CohortConfig, identities []integration.IdentityKey, signingKeyShares []*frost.SigningKeyShare, publicKeySharesOfAllParties []*frost.PublicKeyShares, preSignatureBatch *noninteractive.PreSignatureBatch, firstUnusedPreSignatureIndex []int, privateNoncePairsOfAllParties [][]*noninteractive.PrivateNoncePair, message []byte) {
	t.Helper()

	cosigners, err := test_utils.MakeNonInteractiveCosigners(cohortConfig, identities, signingKeyShares, publicKeySharesOfAllParties, preSignatureBatch, firstUnusedPreSignatureIndex, privateNoncePairsOfAllParties)

	partialSignatures, err := test_utils.DoProducePartialSignature(cosigners, message)
	require.NoError(t, err)

	// first unused presignature index is correctly incremented
	indicesHashSet := map[int]bool{}
	for i, cosigner := range cosigners {
		require.Equal(t, firstUnusedPreSignatureIndex[i]+1, cosigner.FirstUnusedPreSignatureIndex)
		indicesHashSet[cosigner.FirstUnusedPreSignatureIndex] = true
	}
	require.Len(t, indicesHashSet, 1)

	mappedPartialSignatures := test_utils.MapPartialSignatures(identities, partialSignatures)
	signatureHashSet := map[string]bool{}
	for i, cosigner := range cosigners {
		if cosigner.IsSignatureAggregator() {
			signature, err := cosigner.Aggregate(message, mappedPartialSignatures)
			require.NoError(t, err)

			s, err := signature.MarshalBinary()
			require.NoError(t, err)
			signatureHashSet[base64.StdEncoding.EncodeToString(s)] = true

			err = frost.Verify(cohortConfig.CipherSuite.Curve, cohortConfig.CipherSuite.Hash, signature, signingKeyShares[i].PublicKey, message)
			require.NoError(t, err)

			// aggregate should not be considered as a new round. We check if last presignature index remains the same
			require.Equal(t, firstUnusedPreSignatureIndex[i]+1, cosigner.FirstUnusedPreSignatureIndex)
		}
	}
	// all signatures are equal
	require.Len(t, signatureHashSet, 1)
}

func testHappyPath(t *testing.T, protocol protocol.Protocol, curve *curves.Curve, hash func() hash.Hash, threshold, n, tau, firstUnusedPreSignatureIndex int) {
	t.Helper()

	message := []byte("something")

	cipherSuite := &integration.CipherSuite{
		Curve: curve,
		Hash:  hash,
	}

	allIdentities, err := test_utils.MakeIdentities(cipherSuite, n)
	require.NoError(t, err)

	cohortConfig, err := test_utils.MakeCohort(cipherSuite, protocol, allIdentities, threshold, allIdentities)
	require.NoError(t, err)

	allSigningKeyShares, allPublicKeyShares, err := doDkg(cohortConfig, allIdentities)
	require.NoError(t, err)

	for i, share := range allSigningKeyShares {
		require.True(t, allPublicKeyShares[i].SharesMap[allIdentities[i]].Equal(curve.ScalarBaseMult(share.Share)))
	}

	preSignatureBatch, privateNoncePairsOfAllParties, err := doPreGen(cohortConfig, tau)
	require.NoError(t, err)

	firstUnusedPreSignatureIndices := make([]int, n)
	for i := 0; i < n; i++ {
		firstUnusedPreSignatureIndices[i] = firstUnusedPreSignatureIndex
	}

	doNonInteractiveSign(t, cohortConfig, allIdentities, allSigningKeyShares, allPublicKeyShares, preSignatureBatch, firstUnusedPreSignatureIndices, privateNoncePairsOfAllParties, message)

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
							testHappyPath(t, protocol.FROST, boundedCurve, boundedHash, boundedThresholdConfig.t, boundedThresholdConfig.n, boundedTau, firstUnusedPreSignatureIndex)
						})
					}
				}
			}
		}
	}
}
