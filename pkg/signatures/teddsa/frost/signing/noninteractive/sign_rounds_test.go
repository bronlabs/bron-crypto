package noninteractive_test

import (
	"crypto/sha512"
	"encoding/base64"
	"fmt"
	"testing"

	"github.com/copperexchange/crypto-primitives-go/pkg/core/curves"
	"github.com/copperexchange/crypto-primitives-go/pkg/core/integration"
	"github.com/copperexchange/crypto-primitives-go/pkg/core/protocol"
	"github.com/copperexchange/crypto-primitives-go/pkg/signatures/teddsa/frost"
	"github.com/copperexchange/crypto-primitives-go/pkg/signatures/teddsa/frost/signing/noninteractive"
	"github.com/copperexchange/crypto-primitives-go/pkg/signatures/teddsa/test_utils"
	"github.com/stretchr/testify/require"
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

func doPreGen(cohortConfig *integration.CohortConfig, identities []integration.IdentityKey, tau int) (*noninteractive.PreSignatureBatch, [][]*noninteractive.PrivateNoncePair, error) {
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

func doNonInteractiveSign(t *testing.T, cohortConfig *integration.CohortConfig, identities []integration.IdentityKey, signingKeyShares []*frost.SigningKeyShare, publicKeySharesOfAllParties []*frost.PublicKeyShares, preSignatureBatch *noninteractive.PreSignatureBatch, lastUsedPreSignatureIndices []int, privateNoncePairsOfAllParties [][]*noninteractive.PrivateNoncePair, message []byte) {
	t.Helper()

	cosigners, err := test_utils.MakeNonInteractiveCosigners(cohortConfig, identities, signingKeyShares, publicKeySharesOfAllParties, preSignatureBatch, lastUsedPreSignatureIndices, privateNoncePairsOfAllParties)
	require.NoError(t, err)

	partialSignatures, indices, err := test_utils.DoProducePartialSignature(cosigners, message)
	require.NoError(t, err)
	require.Equal(t, len(indices), len(cosigners))
	require.Equal(t, len(indices), len(partialSignatures))

	// last used indices are correctly incremented and recorded
	indicesHashSet := map[int]bool{}
	for i, cosigner := range cosigners {
		indicesHashSet[indices[i]] = true
		require.Equal(t, lastUsedPreSignatureIndices[i]+1, indices[i])
		require.Equal(t, lastUsedPreSignatureIndices[i]+1, cosigner.LastUsedPreSignatureIndex)
	}
	require.Len(t, indicesHashSet, 1)

	mappedPartialSignatures := test_utils.MapPartialSignatures(identities, partialSignatures)
	signatureHashSet := map[string]bool{}
	for i, cosigner := range cosigners {
		if cosigner.IsSignatureAggregator() {
			preSignatureIndex := lastUsedPreSignatureIndices[i] + 1
			signature, err := cosigner.Aggregate(preSignatureIndex, message, mappedPartialSignatures)
			require.NoError(t, err)

			s, err := signature.MarshalBinary()
			require.NoError(t, err)
			signatureHashSet[base64.StdEncoding.EncodeToString(s)] = true

			// fmt.Println(signatureHashSet[signature])
			// signatureHashSet[signature] = true
			// signature is valid
			err = frost.Verify(cohortConfig.CipherSuite.Curve, cohortConfig.CipherSuite.Hash, signature, signingKeyShares[i].PublicKey, message)
			require.NoError(t, err)

			// aggregate should not be considered as a new round. We check if last presignature index remains the same
			require.Equal(t, lastUsedPreSignatureIndices[i]+1, cosigner.LastUsedPreSignatureIndex)
		}
	}
	// all signatures are equal
	if len(signatureHashSet) > 1 {
		for s := range signatureHashSet {
			fmt.Println(s)
		}
	}
	require.Len(t, signatureHashSet, 1)
}

func Test_HappyPath(t *testing.T) {
	t.Parallel()
	curve := curves.ED25519()
	h := sha512.New
	n := 3
	threshold := 3
	tau := 5
	lastUsedPreSignatureIndex := tau - 2
	message := []byte("something")

	cipherSuite := &integration.CipherSuite{
		Curve: curve,
		Hash:  h,
	}

	identities, err := test_utils.MakeIdentities(cipherSuite, n)
	require.NoError(t, err)

	cohortConfig, err := test_utils.MakeCohort(cipherSuite, protocol.FROST, identities, threshold, identities)
	require.NoError(t, err)

	signingKeyShares, publicKeySharesOfAllParties, err := doDkg(cohortConfig, identities)
	require.NoError(t, err)

	preSignatureBatch, privateNoncePairsOfAllParties, err := doPreGen(cohortConfig, identities, tau)
	require.NoError(t, err)

	lastUsedPreSignatureIndices := make([]int, n)
	for i := 0; i < n; i++ {
		lastUsedPreSignatureIndices[i] = lastUsedPreSignatureIndex
	}

	doNonInteractiveSign(t, cohortConfig, identities, signingKeyShares, publicKeySharesOfAllParties, preSignatureBatch, lastUsedPreSignatureIndices, privateNoncePairsOfAllParties, message)

}
