package signing_helpers_test

import (
	crand "crypto/rand"
	"crypto/sha512"
	"fmt"
	"hash"
	"reflect"
	"runtime"
	"strings"
	"testing"

	"github.com/stretchr/testify/require"
	"golang.org/x/crypto/sha3"
	"gonum.org/v1/gonum/stat/combin"

	"github.com/copperexchange/krypton-primitives/pkg/base/curves"
	"github.com/copperexchange/krypton-primitives/pkg/base/curves/edwards25519"
	"github.com/copperexchange/krypton-primitives/pkg/base/curves/k256"
	"github.com/copperexchange/krypton-primitives/pkg/base/errs"
	"github.com/copperexchange/krypton-primitives/pkg/base/protocols"
	"github.com/copperexchange/krypton-primitives/pkg/base/types/integration"
	integration_testutils "github.com/copperexchange/krypton-primitives/pkg/base/types/integration/testutils"
	schnorr "github.com/copperexchange/krypton-primitives/pkg/signatures/schnorr/vanilla"
	agreeonrandom_testutils "github.com/copperexchange/krypton-primitives/pkg/threshold/agreeonrandom/testutils"
	"github.com/copperexchange/krypton-primitives/pkg/threshold/tsignatures/tschnorr/frost"
	"github.com/copperexchange/krypton-primitives/pkg/threshold/tsignatures/tschnorr/frost/testutils"
)

func doDkg(curve curves.Curve, cohortConfig *integration.CohortConfig, identities []integration.IdentityKey) (signingKeyShares []*frost.SigningKeyShare, publicKeyShares []*frost.PublicKeyShares, err error) {
	uniqueSessionId, err := agreeonrandom_testutils.RunAgreeOnRandom(curve, identities, crand.Reader)
	if err != nil {
		return nil, nil, err
	}

	dkgParticipants, err := testutils.MakeDkgParticipants(uniqueSessionId, cohortConfig, identities, nil)
	if err != nil {
		return nil, nil, err
	}

	r2OutB, r2OutU, err := testutils.DoDkgRound1(dkgParticipants, nil)
	if err != nil {
		return nil, nil, err
	}

	r3InB, r3InU := integration_testutils.MapO2I(dkgParticipants, r2OutB, r2OutU)
	signingKeyShares, publicKeyShares, err = testutils.DoDkgRound2(dkgParticipants, r3InB, r3InU)
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

	participants, err := testutils.MakeInteractiveSignParticipants(cohortConfig, identities, shards)
	if err != nil {
		return err
	}
	for _, participant := range participants {
		if participant == nil {
			return errs.NewFailed("nil participant")
		}
	}

	r1Out, err := testutils.DoInteractiveSignRound1(participants)
	if err != nil {
		return err
	}

	r2In := integration_testutils.MapBroadcastO2I(participants, r1Out)
	partialSignatures, err := testutils.DoInteractiveSignRound2(participants, r2In, message)
	if err != nil {
		return err
	}

	mappedPartialSignatures := testutils.MapPartialSignatures(identities, partialSignatures)
	var producedSignatures []*schnorr.Signature
	for i, participant := range participants {
		if cohortConfig.IsSignatureAggregator(participant.MyIdentityKey) {
			signature, err := participant.Aggregate(message, mappedPartialSignatures)
			producedSignatures = append(producedSignatures, signature)
			if err != nil {
				return err
			}
			err = schnorr.Verify(cohortConfig.CipherSuite, &schnorr.PublicKey{A: signingKeyShares[i].PublicKey}, message, signature)
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
			if producedSignatures[i].S.Cmp(producedSignatures[j].S) != 0 {
				return errs.NewFailed("signatures not equal")
			}
		}
	}
	return nil
}

func testHappyPath(t *testing.T, protocol protocols.Protocol, curve curves.Curve, h func() hash.Hash, threshold, n int, message []byte) {
	t.Helper()

	cipherSuite := &integration.CipherSuite{
		Curve: curve,
		Hash:  h,
	}

	allIdentities, err := integration_testutils.MakeTestIdentities(cipherSuite, n)
	require.NoError(t, err)

	cohortConfig, err := integration_testutils.MakeCohortProtocol(cipherSuite, protocol, allIdentities, threshold, allIdentities)
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
	curve := edwards25519.New()
	h := sha3.New256

	cipherSuite := &integration.CipherSuite{
		Curve: curve,
		Hash:  h,
	}

	allIdentities, err := integration_testutils.MakeTestIdentities(cipherSuite, 2)
	require.NoError(t, err)

	cohortConfig, err := integration_testutils.MakeCohortProtocol(cipherSuite, protocols.FROST, allIdentities, 2, allIdentities)
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

func testPreviousPartialSignatureReuse(t *testing.T, protocol protocols.Protocol, curve curves.Curve, hash func() hash.Hash, threshold, n int) {
	t.Helper()

	cipherSuite := &integration.CipherSuite{
		Curve: curve,
		Hash:  hash,
	}

	message := []byte("Hello World!")

	maliciousParty := 0
	identities, err := integration_testutils.MakeTestIdentities(cipherSuite, n)
	require.NoError(t, err)

	cohortConfig, err := integration_testutils.MakeCohortProtocol(cipherSuite, protocol, identities, threshold, identities)
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
	participantsAlpha, err := testutils.MakeInteractiveSignParticipants(cohortConfig, identities[:threshold], shards)
	require.NoError(t, err)
	r1OutAlpha, err := testutils.DoInteractiveSignRound1(participantsAlpha)
	require.NoError(t, err)
	r2InAlpha := integration_testutils.MapBroadcastO2I(participantsAlpha, r1OutAlpha)
	partialSignaturesAlpha, err := testutils.DoInteractiveSignRound2(participantsAlpha, r2InAlpha, message)
	require.NoError(t, err)
	mappedPartialSignaturesAlpha := testutils.MapPartialSignatures(identities[:threshold], partialSignaturesAlpha)
	_, err = participantsAlpha[0].Aggregate(message, mappedPartialSignaturesAlpha)
	require.NoError(t, err)

	// second execution
	participantsBeta, err := testutils.MakeInteractiveSignParticipants(cohortConfig, identities[:threshold], shards)
	require.NoError(t, err)
	r1OutBeta, err := testutils.DoInteractiveSignRound1(participantsBeta)
	require.NoError(t, err)
	r2InBeta := integration_testutils.MapBroadcastO2I(participantsBeta, r1OutBeta)
	partialSignaturesBeta, err := testutils.DoInteractiveSignRound2(participantsBeta, r2InBeta, message)
	require.NoError(t, err)

	// smuggle previous round partial signature
	partialSignaturesBeta[maliciousParty] = partialSignaturesAlpha[maliciousParty]
	mappedPartialSignaturesBeta := testutils.MapPartialSignatures(identities[:threshold], partialSignaturesBeta)
	_, err = participantsBeta[0].Aggregate(message, mappedPartialSignaturesBeta)
	require.True(t, errs.IsIdentifiableAbort(err, nil))
}

// make sure Alice cannot change the resulting signature at aggregation time/testing that R is correctly bound to D_i and E_i.
func testRandomPartialSignature(t *testing.T, protocol protocols.Protocol, curve curves.Curve, hash func() hash.Hash, threshold, n int) {
	t.Helper()

	cipherSuite := &integration.CipherSuite{
		Curve: curve,
		Hash:  hash,
	}

	message := []byte("Hello World!")

	maliciousParty := 0
	identities, err := integration_testutils.MakeTestIdentities(cipherSuite, n)
	require.NoError(t, err)

	cohortConfig, err := integration_testutils.MakeCohortProtocol(cipherSuite, protocol, identities, threshold, identities)
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

	participants, err := testutils.MakeInteractiveSignParticipants(cohortConfig, identities[:threshold], shards)
	require.NoError(t, err)
	r1Out, err := testutils.DoInteractiveSignRound1(participants)
	require.NoError(t, err)
	r2In := integration_testutils.MapBroadcastO2I(participants, r1Out)
	partialSignatures, err := testutils.DoInteractiveSignRound2(participants, r2In, message)
	require.NoError(t, err)

	// use random scalar
	partialSignatures[maliciousParty].Zi = curve.Scalar().Random(crand.Reader)
	mappedPartialSignatures := testutils.MapPartialSignatures(identities[:threshold], partialSignatures)
	_, err = participants[0].Aggregate(message, mappedPartialSignatures)
	require.True(t, errs.IsIdentifiableAbort(err, nil))
}

func Test_HappyPath(t *testing.T) {
	t.Parallel()

	for _, curve := range []curves.Curve{edwards25519.New(), k256.New()} {
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
				t.Run(fmt.Sprintf("Interactive sign happy path with curve=%s and hash=%s and t=%d and n=%d", boundedCurve.Name(), boundedHashName[strings.LastIndex(boundedHashName, "/")+1:], boundedThresholdConfig.t, boundedThresholdConfig.n), func(t *testing.T) {
					t.Parallel()
					testHappyPath(t, protocols.FROST, boundedCurve, boundedHash, boundedThresholdConfig.t, boundedThresholdConfig.n, []byte("Hello World!"))
				})
			}
		}
	}
}

func TestShouldAbortOnSignPreviousRoundReuse(t *testing.T) {
	t.Parallel()

	for _, curve := range []curves.Curve{edwards25519.New(), k256.New()} {
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
				t.Run(fmt.Sprintf("Abort when Alice try to use random partial signature at aggregation with curve=%s and hash=%s and t=%d and n=%d", boundedCurve.Name(), boundedHashName[strings.LastIndex(boundedHashName, "/")+1:], boundedThresholdConfig.t, boundedThresholdConfig.n), func(t *testing.T) {
					t.Parallel()
					testPreviousPartialSignatureReuse(t, protocols.FROST, boundedCurve, boundedHash, boundedThresholdConfig.t, boundedThresholdConfig.n)
				})
			}
		}
	}
}

func TestShouldAbortOnRandomPartialSignature(t *testing.T) {
	t.Parallel()

	for _, curve := range []curves.Curve{edwards25519.New(), k256.New()} {
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
				t.Run(fmt.Sprintf("Abort when Alice try to resuse previous partial signature at aggregation with curve=%s and hash=%s and t=%d and n=%d", boundedCurve.Name(), boundedHashName[strings.LastIndex(boundedHashName, "/")+1:], boundedThresholdConfig.t, boundedThresholdConfig.n), func(t *testing.T) {
					t.Parallel()
					testRandomPartialSignature(t, protocols.FROST, boundedCurve, boundedHash, boundedThresholdConfig.t, boundedThresholdConfig.n)
				})
			}
		}
	}
}
