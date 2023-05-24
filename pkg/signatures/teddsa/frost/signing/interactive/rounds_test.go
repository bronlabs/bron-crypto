package interactive_test

import (
	crand "crypto/rand"
	"crypto/sha512"
	"fmt"
	"github.com/copperexchange/crypto-primitives-go/pkg/core/curves"
	"github.com/copperexchange/crypto-primitives-go/pkg/core/integration"
	"github.com/copperexchange/crypto-primitives-go/pkg/core/protocol"
	"github.com/copperexchange/crypto-primitives-go/pkg/signatures/teddsa/frost"
	"github.com/copperexchange/crypto-primitives-go/pkg/signatures/teddsa/test_utils"
	"github.com/stretchr/testify/require"
	"golang.org/x/crypto/sha3"
	"gonum.org/v1/gonum/stat/combin"
	"hash"
	"reflect"
	"runtime"
	"strings"
	"testing"
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

func doInteractiveSign(t *testing.T, cohortConfig *integration.CohortConfig, identities []integration.IdentityKey, signingKeyShares []*frost.SigningKeyShare, publicKeyShares []*frost.PublicKeyShares, message []byte) {
	t.Helper()

	participants, err := test_utils.MakeInteractiveSignParticipants(cohortConfig, identities, signingKeyShares, publicKeyShares)
	require.NoError(t, err)
	for _, participant := range participants {
		require.NotNil(t, participant)
	}

	r1Out, err := test_utils.DoInteractiveSignRound1(participants)
	require.NoError(t, err)

	r2In := test_utils.MapInteractiveSignRound1OutputsToRound2Inputs(participants, r1Out)
	partialSignatures, err := test_utils.DoInteractiveSignRound2(participants, r2In, message)
	require.NoError(t, err)

	mappedPartialSignatures := test_utils.MapPartialSignatures(participants, partialSignatures)
	var signatures []*frost.Signature
	for i, participant := range participants {
		if cohortConfig.IsSignatureAggregator(participant.MyIdentityKey) {
			signature, err := participant.Aggregate(mappedPartialSignatures)
			signatures = append(signatures, signature)
			require.NoError(t, err)
			err = frost.Verify(cohortConfig.CipherSuite.Curve, cohortConfig.CipherSuite.Hash, signature, signingKeyShares[i].PublicKey, message)
			require.NoError(t, err)
		}
	}
	require.NotEmpty(t, signatures)

	// all signatures the same
	for i := 0; i < len(signatures); i++ {
		for j := i + 1; j < len(signatures); j++ {
			require.True(t, signatures[i].R.Equal(signatures[j].R))
			require.Zero(t, signatures[i].Z.Cmp(signatures[j].Z))
		}
	}
}

func testHappyPath(t *testing.T, protocol protocol.Protocol, curve *curves.Curve, h func() hash.Hash, threshold, n int, message []byte) {
	t.Helper()

	cipherSuite := &integration.CipherSuite{
		Curve: curve,
		Hash:  h,
	}

	allIdentities, err := test_utils.MakeIdentities(cipherSuite, n)
	require.NoError(t, err)

	cohortConfig, err := test_utils.MakeCohort(cipherSuite, protocol, allIdentities, threshold, allIdentities)
	require.NoError(t, err)

	allSigningKeyShares, allPublicKeyShares, err := doDkg(cohortConfig, allIdentities)
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

		doInteractiveSign(t, cohortConfig, identities, signingKeyShares, publicKeyShares, message)
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
	identities, err := test_utils.MakeIdentities(cipherSuite, n)
	require.NoError(t, err)

	cohortConfig, err := test_utils.MakeCohort(cipherSuite, protocol, identities, threshold, identities)
	require.NoError(t, err)

	signingKeyShares, publicKeyShares, err := doDkg(cohortConfig, identities)
	require.NoError(t, err)

	// first execution
	participantsAlpha, err := test_utils.MakeInteractiveSignParticipants(cohortConfig, identities[:threshold], signingKeyShares, publicKeyShares)
	require.NoError(t, err)
	r1OutAlpha, err := test_utils.DoInteractiveSignRound1(participantsAlpha)
	require.NoError(t, err)
	r2InAlpha := test_utils.MapInteractiveSignRound1OutputsToRound2Inputs(participantsAlpha, r1OutAlpha)
	partialSignaturesAlpha, err := test_utils.DoInteractiveSignRound2(participantsAlpha, r2InAlpha, message)
	require.NoError(t, err)
	mappedPartialSignaturesAlpha := test_utils.MapPartialSignatures(participantsAlpha, partialSignaturesAlpha)
	_, err = participantsAlpha[0].Aggregate(mappedPartialSignaturesAlpha)
	require.NoError(t, err)

	// second execution
	participantsBeta, err := test_utils.MakeInteractiveSignParticipants(cohortConfig, identities[:threshold], signingKeyShares, publicKeyShares)
	require.NoError(t, err)
	r1OutBeta, err := test_utils.DoInteractiveSignRound1(participantsBeta)
	require.NoError(t, err)
	r2InBeta := test_utils.MapInteractiveSignRound1OutputsToRound2Inputs(participantsBeta, r1OutBeta)
	partialSignaturesBeta, err := test_utils.DoInteractiveSignRound2(participantsBeta, r2InBeta, message)

	// smuggle previous round partial signature
	partialSignaturesBeta[maliciousParty] = partialSignaturesAlpha[maliciousParty]
	mappedPartialSignaturesBeta := test_utils.MapPartialSignatures(participantsBeta, partialSignaturesBeta)
	_, err = participantsBeta[0].Aggregate(mappedPartialSignaturesBeta)
	require.Error(t, err)
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
	identities, err := test_utils.MakeIdentities(cipherSuite, n)
	require.NoError(t, err)

	cohortConfig, err := test_utils.MakeCohort(cipherSuite, protocol, identities, threshold, identities)
	require.NoError(t, err)

	signingKeyShares, publicKeyShares, err := doDkg(cohortConfig, identities)
	require.NoError(t, err)

	participants, err := test_utils.MakeInteractiveSignParticipants(cohortConfig, identities[:threshold], signingKeyShares, publicKeyShares)
	require.NoError(t, err)
	r1Out, err := test_utils.DoInteractiveSignRound1(participants)
	require.NoError(t, err)
	r2In := test_utils.MapInteractiveSignRound1OutputsToRound2Inputs(participants, r1Out)
	partialSignatures, err := test_utils.DoInteractiveSignRound2(participants, r2In, message)
	require.NoError(t, err)

	// use random scalar
	partialSignatures[maliciousParty].Zi = curve.Scalar.Random(crand.Reader)
	mappedPartialSignatures := test_utils.MapPartialSignatures(participants, partialSignatures)
	_, err = participants[0].Aggregate(mappedPartialSignatures)
	require.Error(t, err)
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
