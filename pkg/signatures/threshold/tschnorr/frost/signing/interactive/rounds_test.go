package interactive_test

import (
	crand "crypto/rand"
	"crypto/sha512"
	"fmt"
	"hash"
	"reflect"
	"runtime"
	"strings"
	"testing"

	"github.com/copperexchange/crypto-primitives-go/pkg/core/errs"

	agreeonrandom_test_utils "github.com/copperexchange/crypto-primitives-go/pkg/agreeonrandom/test_utils"
	"github.com/copperexchange/crypto-primitives-go/pkg/core/curves"
	"github.com/copperexchange/crypto-primitives-go/pkg/core/integration"
	test_utils_integration "github.com/copperexchange/crypto-primitives-go/pkg/core/integration/test_utils"
	"github.com/copperexchange/crypto-primitives-go/pkg/core/protocol"
	"github.com/copperexchange/crypto-primitives-go/pkg/signatures/eddsa"
	"github.com/copperexchange/crypto-primitives-go/pkg/signatures/threshold/tschnorr/frost"
	"github.com/copperexchange/crypto-primitives-go/pkg/signatures/threshold/tschnorr/frost/test_utils"
	"github.com/stretchr/testify/require"
	"golang.org/x/crypto/sha3"
	"gonum.org/v1/gonum/stat/combin"
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

func doInteractiveSign(cohortConfig *integration.CohortConfig, identities []integration.IdentityKey, signingKeyShares []*frost.SigningKeyShare, publicKeyShares []*frost.PublicKeyShares, message []byte) error {
	var shards []*frost.Shard
	for i := range signingKeyShares {
		shards = append(shards, &frost.Shard{
			SigningKeyShare: signingKeyShares[i],
			PublicKeyShares: publicKeyShares[i],
		})
	}

	participants, err := test_utils.MakeInteractiveSignParticipants(cohortConfig, identities, shards)
	if err != nil {
		return err
	}
	for _, participant := range participants {
		if participant == nil {
			return errs.NewFailed("nil participant")
		}
	}

	r1Out, err := test_utils.DoInteractiveSignRound1(participants)
	if err != nil {
		return err
	}

	r2In := test_utils.MapInteractiveSignRound1OutputsToRound2Inputs(participants, r1Out)
	partialSignatures, err := test_utils.DoInteractiveSignRound2(participants, r2In, message)
	if err != nil {
		return err
	}

	mappedPartialSignatures := test_utils.MapPartialSignatures(identities, partialSignatures)
	var producedSignatures []*eddsa.Signature
	for i, participant := range participants {
		if cohortConfig.IsSignatureAggregator(participant.MyIdentityKey) {
			signature, err := participant.Aggregate(message, mappedPartialSignatures)
			producedSignatures = append(producedSignatures, signature)
			if err != nil {
				return err
			}
			err = eddsa.Verify(cohortConfig.CipherSuite.Curve, cohortConfig.CipherSuite.Hash, signature, signingKeyShares[i].PublicKey, message)
			if err != nil {
				return err
			}
		}
	}
	if len(producedSignatures) == 0 {
		return errs.NewFailed("no signatures produced")
	}

	// all signatures the same
	for i := 0; i < len(producedSignatures); i++ {
		for j := i + 1; j < len(producedSignatures); j++ {
			if producedSignatures[i].R.Equal(producedSignatures[j].R) == false {
				return errs.NewFailed("signatures not equal")
			}
			if producedSignatures[i].Z.Cmp(producedSignatures[j].Z) != 0 {
				return errs.NewFailed("signatures not equal")
			}
		}
	}
	return nil
}

func testHappyPath(t *testing.T, protocol protocol.Protocol, curve *curves.Curve, h func() hash.Hash, threshold, n int, message []byte) {
	t.Helper()

	cipherSuite := &integration.CipherSuite{
		Curve: curve,
		Hash:  h,
	}

	allIdentities, err := test_utils_integration.MakeIdentities(cipherSuite, n)
	require.NoError(t, err)

	cohortConfig, err := test_utils_integration.MakeCohort(cipherSuite, protocol, allIdentities, threshold, allIdentities)
	require.NoError(t, err)

	allSigningKeyShares, allPublicKeyShares, err := doDkg(curve, cohortConfig, allIdentities)
	require.NoError(t, err)

	combinations := combin.Combinations(n, threshold)
	for _, combinationIndices := range combinations {
		identities := make([]integration.IdentityKey, threshold)
		signingKeyShares := make([]*frost.SigningKeyShare, threshold)
		publicKeyShares := make([]*frost.PublicKeyShares, threshold)
		for i, index := range combinationIndices {
			identities[i] = allIdentities[index]
			signingKeyShares[i] = allSigningKeyShares[index]
			publicKeyShares[i] = allPublicKeyShares[index]
		}

		err := doInteractiveSign(cohortConfig, identities, signingKeyShares, publicKeyShares, message)
		require.NoError(t, err)
	}
}

func TestSignEmptyMessage(t *testing.T) {
	t.Helper()
	curve := curves.ED25519()
	h := sha3.New256

	cipherSuite := &integration.CipherSuite{
		Curve: curve,
		Hash:  h,
	}

	allIdentities, err := test_utils_integration.MakeIdentities(cipherSuite, 2)
	require.NoError(t, err)

	cohortConfig, err := test_utils_integration.MakeCohort(cipherSuite, protocol.FROST, allIdentities, 2, allIdentities)
	require.NoError(t, err)

	allSigningKeyShares, allPublicKeyShares, err := doDkg(curve, cohortConfig, allIdentities)
	require.NoError(t, err)

	combinations := combin.Combinations(2, 2)
	for _, combinationIndices := range combinations {
		identities := make([]integration.IdentityKey, 2)
		signingKeyShares := make([]*frost.SigningKeyShare, 2)
		publicKeyShares := make([]*frost.PublicKeyShares, 2)
		for i, index := range combinationIndices {
			identities[i] = allIdentities[index]
			signingKeyShares[i] = allSigningKeyShares[index]
			publicKeyShares[i] = allPublicKeyShares[index]
		}

		err := doInteractiveSign(cohortConfig, identities, signingKeyShares, publicKeyShares, []byte{})
		require.Error(t, err)
		require.Contains(t, err.Error(), "message is empty")

		err = doInteractiveSign(cohortConfig, identities, signingKeyShares, publicKeyShares, nil)
		require.Error(t, err)
		require.Contains(t, err.Error(), "message is empty")
	}
}

func testPreviousPartialSignatureReuse(t *testing.T, protocol protocol.Protocol, curve *curves.Curve, hash func() hash.Hash, threshold, n int) {
	t.Helper()

	cipherSuite := &integration.CipherSuite{
		Curve: curve,
		Hash:  hash,
	}

	message := []byte("Hello World!")

	maliciousParty := 0
	identities, err := test_utils_integration.MakeIdentities(cipherSuite, n)
	require.NoError(t, err)

	cohortConfig, err := test_utils_integration.MakeCohort(cipherSuite, protocol, identities, threshold, identities)
	require.NoError(t, err)

	signingKeyShares, publicKeyShares, err := doDkg(curve, cohortConfig, identities)
	require.NoError(t, err)

	var shards []*frost.Shard
	for i := range signingKeyShares {
		shards = append(shards, &frost.Shard{
			SigningKeyShare: signingKeyShares[i],
			PublicKeyShares: publicKeyShares[i],
		})
	}

	// first execution
	participantsAlpha, err := test_utils.MakeInteractiveSignParticipants(cohortConfig, identities[:threshold], shards)
	require.NoError(t, err)
	r1OutAlpha, err := test_utils.DoInteractiveSignRound1(participantsAlpha)
	require.NoError(t, err)
	r2InAlpha := test_utils.MapInteractiveSignRound1OutputsToRound2Inputs(participantsAlpha, r1OutAlpha)
	partialSignaturesAlpha, err := test_utils.DoInteractiveSignRound2(participantsAlpha, r2InAlpha, message)
	require.NoError(t, err)
	mappedPartialSignaturesAlpha := test_utils.MapPartialSignatures(identities[:threshold], partialSignaturesAlpha)
	_, err = participantsAlpha[0].Aggregate(message, mappedPartialSignaturesAlpha)
	require.NoError(t, err)

	// second execution
	participantsBeta, err := test_utils.MakeInteractiveSignParticipants(cohortConfig, identities[:threshold], shards)
	require.NoError(t, err)
	r1OutBeta, err := test_utils.DoInteractiveSignRound1(participantsBeta)
	require.NoError(t, err)
	r2InBeta := test_utils.MapInteractiveSignRound1OutputsToRound2Inputs(participantsBeta, r1OutBeta)
	partialSignaturesBeta, err := test_utils.DoInteractiveSignRound2(participantsBeta, r2InBeta, message)

	// smuggle previous round partial signature
	partialSignaturesBeta[maliciousParty] = partialSignaturesAlpha[maliciousParty]
	mappedPartialSignaturesBeta := test_utils.MapPartialSignatures(identities[:threshold], partialSignaturesBeta)
	_, err = participantsBeta[0].Aggregate(message, mappedPartialSignaturesBeta)
	require.True(t, errs.IsIdentifiableAbort(err))
}

// make sure Alice cannot change the resulting signature at aggregation time/testing that R is correctly bound to D_i and E_i.
func testRandomPartialSignature(t *testing.T, protocol protocol.Protocol, curve *curves.Curve, hash func() hash.Hash, threshold, n int) {
	t.Helper()

	cipherSuite := &integration.CipherSuite{
		Curve: curve,
		Hash:  hash,
	}

	message := []byte("Hello World!")

	maliciousParty := 0
	identities, err := test_utils_integration.MakeIdentities(cipherSuite, n)
	require.NoError(t, err)

	cohortConfig, err := test_utils_integration.MakeCohort(cipherSuite, protocol, identities, threshold, identities)
	require.NoError(t, err)

	signingKeyShares, publicKeyShares, err := doDkg(curve, cohortConfig, identities)
	require.NoError(t, err)

	var shards []*frost.Shard
	for i := range signingKeyShares {
		shards = append(shards, &frost.Shard{
			SigningKeyShare: signingKeyShares[i],
			PublicKeyShares: publicKeyShares[i],
		})
	}

	participants, err := test_utils.MakeInteractiveSignParticipants(cohortConfig, identities[:threshold], shards)
	require.NoError(t, err)
	r1Out, err := test_utils.DoInteractiveSignRound1(participants)
	require.NoError(t, err)
	r2In := test_utils.MapInteractiveSignRound1OutputsToRound2Inputs(participants, r1Out)
	partialSignatures, err := test_utils.DoInteractiveSignRound2(participants, r2In, message)
	require.NoError(t, err)

	// use random scalar
	partialSignatures[maliciousParty].Zi = curve.Scalar.Random(crand.Reader)
	mappedPartialSignatures := test_utils.MapPartialSignatures(identities[:threshold], partialSignatures)
	_, err = participants[0].Aggregate(message, mappedPartialSignatures)
	require.True(t, errs.IsIdentifiableAbort(err))
}

func Test_HappyPath(t *testing.T) {
	t.Parallel()

	for _, curve := range []*curves.Curve{curves.ED25519(), curves.K256()} {
		for _, h := range []func() hash.Hash{sha3.New256, sha512.New} {
			for _, thresholdConfig := range []struct {
				t int
				n int
			}{
				{t: 2, n: 3},
				{t: 3, n: 3},
			} {
				boundedCurve := curve
				boundedHash := h
				boundedHashName := runtime.FuncForPC(reflect.ValueOf(h).Pointer()).Name()
				boundedThresholdConfig := thresholdConfig
				t.Run(fmt.Sprintf("Interactive sign happy path with curve=%s and hash=%s and t=%d and n=%d", boundedCurve.Name, boundedHashName[strings.LastIndex(boundedHashName, "/")+1:], boundedThresholdConfig.t, boundedThresholdConfig.n), func(t *testing.T) {
					t.Parallel()
					testHappyPath(t, protocol.FROST, boundedCurve, boundedHash, boundedThresholdConfig.t, boundedThresholdConfig.n, []byte("Hello World!"))
				})
			}
		}
	}
}

func TestShouldAbortOnSignPreviousRoundReuse(t *testing.T) {
	t.Parallel()

	for _, curve := range []*curves.Curve{curves.ED25519(), curves.K256()} {
		for _, h := range []func() hash.Hash{sha3.New256, sha512.New} {
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
				t.Run(fmt.Sprintf("Abort when Alice try to use random partial signature at aggregation with curve=%s and hash=%s and t=%d and n=%d", boundedCurve.Name, boundedHashName[strings.LastIndex(boundedHashName, "/")+1:], boundedThresholdConfig.t, boundedThresholdConfig.n), func(t *testing.T) {
					t.Parallel()
					testPreviousPartialSignatureReuse(t, protocol.FROST, boundedCurve, boundedHash, boundedThresholdConfig.t, boundedThresholdConfig.n)
				})
			}
		}
	}
}

func TestShouldAbortOnRandomPartialSignature(t *testing.T) {
	t.Parallel()

	for _, curve := range []*curves.Curve{curves.ED25519(), curves.K256()} {
		for _, h := range []func() hash.Hash{sha3.New256, sha512.New} {
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
				t.Run(fmt.Sprintf("Abort when Alice try to resuse previous partial signature at aggregation with curve=%s and hash=%s and t=%d and n=%d", boundedCurve.Name, boundedHashName[strings.LastIndex(boundedHashName, "/")+1:], boundedThresholdConfig.t, boundedThresholdConfig.n), func(t *testing.T) {
					t.Parallel()
					testRandomPartialSignature(t, protocol.FROST, boundedCurve, boundedHash, boundedThresholdConfig.t, boundedThresholdConfig.n)
				})
			}
		}
	}
}
