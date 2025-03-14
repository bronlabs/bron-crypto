package interactive_signing_test

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

	"github.com/bronlabs/bron-crypto/pkg/base/combinatorics"
	"github.com/bronlabs/bron-crypto/pkg/base/curves"
	"github.com/bronlabs/bron-crypto/pkg/base/curves/edwards25519"
	"github.com/bronlabs/bron-crypto/pkg/base/curves/k256"
	"github.com/bronlabs/bron-crypto/pkg/base/errs"
	"github.com/bronlabs/bron-crypto/pkg/base/types"
	ttu "github.com/bronlabs/bron-crypto/pkg/base/types/testutils"
	schnorr "github.com/bronlabs/bron-crypto/pkg/signatures/schnorr/vanilla"
	agreeonrandom_testutils "github.com/bronlabs/bron-crypto/pkg/threshold/agreeonrandom/testutils"
	"github.com/bronlabs/bron-crypto/pkg/threshold/tsignatures/tschnorr/frost"
	"github.com/bronlabs/bron-crypto/pkg/threshold/tsignatures/tschnorr/frost/testutils"
)

func doDkg(t require.TestingT, curve curves.Curve, protocol types.ThresholdProtocol, identities []types.IdentityKey) (signingKeyShares []*frost.SigningKeyShare, publicKeyShares []*frost.PublicKeyShares, err error) {
	uniqueSessionId, err := agreeonrandom_testutils.RunAgreeOnRandom(t, curve, identities, crand.Reader)
	if err != nil {
		return nil, nil, err
	}

	dkgParticipants, err := testutils.MakeDkgParticipants(uniqueSessionId, protocol, identities, nil)
	if err != nil {
		return nil, nil, err
	}

	r2OutB, r2OutU, err := testutils.DoDkgRound1(dkgParticipants, nil)
	if err != nil {
		return nil, nil, err
	}

	r3InB, r3InU := ttu.MapO2I(t, dkgParticipants, r2OutB, r2OutU)
	signingKeyShares, publicKeyShares, err = testutils.DoDkgRound2(dkgParticipants, r3InB, r3InU)
	if err != nil {
		return nil, nil, err
	}

	return signingKeyShares, publicKeyShares, nil
}

func doInteractiveSign(t require.TestingT, protocol types.ThresholdSignatureProtocol, identities []types.IdentityKey, signingKeyShares []*frost.SigningKeyShare, publicKeyShares []*frost.PublicKeyShares, message []byte) error {
	var shards []*frost.Shard
	for i := range signingKeyShares {
		shards = append(shards, &frost.Shard{
			SigningKeyShare: signingKeyShares[i],
			PublicKeyShares: publicKeyShares[i],
		})
	}

	participants, err := testutils.MakeInteractiveSignParticipants(protocol, identities, shards)
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

	r2In := ttu.MapBroadcastO2I(t, participants, r1Out)
	partialSignatures, err := testutils.DoInteractiveSignRound2(participants, r2In, message)
	if err != nil {
		return err
	}

	mappedPartialSignatures := testutils.MapPartialSignatures(identities, partialSignatures)
	var producedSignatures []*schnorr.Signature
	for i, participant := range participants {
		if participant.IsSignatureAggregator() {
			signature, err := participant.Aggregate(message, mappedPartialSignatures)
			producedSignatures = append(producedSignatures, signature)
			if err != nil {
				return err
			}
			err = schnorr.Verify(protocol.SigningSuite(), &schnorr.PublicKey{A: signingKeyShares[i].PublicKey}, message, signature)
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

func testHappyPath(t *testing.T, curve curves.Curve, h func() hash.Hash, threshold, n int, message []byte) {
	t.Helper()

	cipherSuite, err := ttu.MakeSigningSuite(curve, h)
	require.NoError(t, err)

	allIdentities, err := ttu.MakeTestIdentities(cipherSuite, n)
	require.NoError(t, err)

	protocol, err := ttu.MakeThresholdSignatureProtocol(cipherSuite, allIdentities, threshold, allIdentities)
	require.NoError(t, err)

	allSigningKeyShares, allPublicKeyShares, err := doDkg(t, curve, protocol, allIdentities)
	require.NoError(t, err)

	N := make([]int, n)
	for i := range n {
		N[i] = i
	}
	combinations, err := combinatorics.Combinations(N, uint(threshold))
	require.NoError(t, err)
	for _, combinationIndices := range combinations {
		identities := make([]types.IdentityKey, threshold)
		signingKeyShares := make([]*frost.SigningKeyShare, threshold)
		publicKeyShares := make([]*frost.PublicKeyShares, threshold)
		for i, index := range combinationIndices {
			identities[i] = allIdentities[index]
			signingKeyShares[i] = allSigningKeyShares[index]
			publicKeyShares[i] = allPublicKeyShares[index]
		}

		err := doInteractiveSign(t, protocol, identities, signingKeyShares, publicKeyShares, message)
		require.NoError(t, err)
	}
}

func TestSignEmptyMessage(t *testing.T) {
	t.Helper()
	t.Parallel()
	curve := edwards25519.NewCurve()
	h := sha3.New256

	cipherSuite, err := ttu.MakeSigningSuite(curve, h)
	require.NoError(t, err)

	allIdentities, err := ttu.MakeTestIdentities(cipherSuite, 2)
	require.NoError(t, err)

	protocol, err := ttu.MakeThresholdSignatureProtocol(cipherSuite, allIdentities, 2, allIdentities)
	require.NoError(t, err)

	allSigningKeyShares, allPublicKeyShares, err := doDkg(t, curve, protocol, allIdentities)
	require.NoError(t, err)

	N := []uint{0, 1}
	combinations, err := combinatorics.Combinations(N, 2)
	require.NoError(t, err)
	for _, combinationIndices := range combinations {
		identities := make([]types.IdentityKey, 2)
		signingKeyShares := make([]*frost.SigningKeyShare, 2)
		publicKeyShares := make([]*frost.PublicKeyShares, 2)
		for i, index := range combinationIndices {
			identities[i] = allIdentities[index]
			signingKeyShares[i] = allSigningKeyShares[index]
			publicKeyShares[i] = allPublicKeyShares[index]
		}

		err := doInteractiveSign(t, protocol, identities, signingKeyShares, publicKeyShares, []byte{})
		require.Error(t, err)
		require.Contains(t, err.Error(), "message is empty")

		err = doInteractiveSign(t, protocol, identities, signingKeyShares, publicKeyShares, nil)
		require.Error(t, err)
		require.Contains(t, err.Error(), "message is empty")
	}
}

func testPreviousPartialSignatureReuse(t *testing.T, curve curves.Curve, hash func() hash.Hash, threshold, n int) {
	t.Helper()

	cipherSuite, err := ttu.MakeSigningSuite(curve, hash)
	require.NoError(t, err)

	message := []byte("Hello World!")

	maliciousParty := 0
	aggregator := 1
	identities, err := ttu.MakeTestIdentities(cipherSuite, n)
	require.NoError(t, err)

	protocol, err := ttu.MakeThresholdSignatureProtocol(cipherSuite, identities, threshold, identities)
	require.NoError(t, err)

	signingKeyShares, publicKeyShares, err := doDkg(t, curve, protocol, identities)
	require.NoError(t, err)

	var shards []*frost.Shard
	for i := range signingKeyShares {
		shards = append(shards, &frost.Shard{
			SigningKeyShare: signingKeyShares[i],
			PublicKeyShares: publicKeyShares[i],
		})
	}

	// first execution
	participantsAlpha, err := testutils.MakeInteractiveSignParticipants(protocol, identities[:threshold], shards)
	require.NoError(t, err)
	r1OutAlpha, err := testutils.DoInteractiveSignRound1(participantsAlpha)
	require.NoError(t, err)
	r2InAlpha := ttu.MapBroadcastO2I(t, participantsAlpha, r1OutAlpha)
	partialSignaturesAlpha, err := testutils.DoInteractiveSignRound2(participantsAlpha, r2InAlpha, message)
	require.NoError(t, err)
	mappedPartialSignaturesAlpha := testutils.MapPartialSignatures(identities[:threshold], partialSignaturesAlpha)
	_, err = participantsAlpha[aggregator].Aggregate(message, mappedPartialSignaturesAlpha)
	require.NoError(t, err)

	// second execution
	participantsBeta, err := testutils.MakeInteractiveSignParticipants(protocol, identities[:threshold], shards)
	require.NoError(t, err)
	r1OutBeta, err := testutils.DoInteractiveSignRound1(participantsBeta)
	require.NoError(t, err)
	r2InBeta := ttu.MapBroadcastO2I(t, participantsBeta, r1OutBeta)
	partialSignaturesBeta, err := testutils.DoInteractiveSignRound2(participantsBeta, r2InBeta, message)
	require.NoError(t, err)

	// smuggle previous round partial signature
	partialSignaturesBeta[maliciousParty] = partialSignaturesAlpha[maliciousParty]
	mappedPartialSignaturesBeta := testutils.MapPartialSignatures(identities[:threshold], partialSignaturesBeta)
	_, err = participantsBeta[aggregator].Aggregate(message, mappedPartialSignaturesBeta)
	fmt.Println(err)
	fmt.Println(identities)
	require.True(t, errs.IsIdentifiableAbort(err, identities[maliciousParty]))
}

// make sure Alice cannot change the resulting signature at aggregation time/testing that R is correctly bound to D_i and E_i.
func testRandomPartialSignature(t *testing.T, curve curves.Curve, hash func() hash.Hash, threshold, n int) {
	t.Helper()

	cipherSuite, err := ttu.MakeSigningSuite(curve, hash)
	require.NoError(t, err)

	message := []byte("Hello World!")

	maliciousParty := 0
	aggregator := 1
	identities, err := ttu.MakeTestIdentities(cipherSuite, n)
	require.NoError(t, err)

	protocol, err := ttu.MakeThresholdSignatureProtocol(cipherSuite, identities, threshold, identities)
	require.NoError(t, err)

	signingKeyShares, publicKeyShares, err := doDkg(t, curve, protocol, identities)
	require.NoError(t, err)

	var shards []*frost.Shard
	for i := range signingKeyShares {
		shards = append(shards, &frost.Shard{
			SigningKeyShare: signingKeyShares[i],
			PublicKeyShares: publicKeyShares[i],
		})
	}

	participants, err := testutils.MakeInteractiveSignParticipants(protocol, identities[:threshold], shards)
	require.NoError(t, err)
	r1Out, err := testutils.DoInteractiveSignRound1(participants)
	require.NoError(t, err)
	r2In := ttu.MapBroadcastO2I(t, participants, r1Out)
	partialSignatures, err := testutils.DoInteractiveSignRound2(participants, r2In, message)
	require.NoError(t, err)

	// use random scalar
	partialSignatures[maliciousParty].Zi, err = curve.ScalarField().Random(crand.Reader)
	require.NoError(t, err)
	mappedPartialSignatures := testutils.MapPartialSignatures(identities[:threshold], partialSignatures)
	_, err = participants[aggregator].Aggregate(message, mappedPartialSignatures)
	require.True(t, errs.IsIdentifiableAbort(err, identities[maliciousParty]))
}

func Test_HappyPath(t *testing.T) {
	t.Parallel()

	for _, curve := range []curves.Curve{edwards25519.NewCurve(), k256.NewCurve()} {
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
					testHappyPath(t, boundedCurve, boundedHash, boundedThresholdConfig.t, boundedThresholdConfig.n, []byte("Hello World!"))
				})
			}
		}
	}
}

func TestShouldAbortOnSignPreviousRoundReuse(t *testing.T) {
	t.Parallel()

	for _, curve := range []curves.Curve{edwards25519.NewCurve(), k256.NewCurve()} {
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
					testPreviousPartialSignatureReuse(t, boundedCurve, boundedHash, boundedThresholdConfig.t, boundedThresholdConfig.n)
				})
			}
		}
	}
}

func TestShouldAbortOnRandomPartialSignature(t *testing.T) {
	t.Parallel()

	for _, curve := range []curves.Curve{edwards25519.NewCurve(), k256.NewCurve()} {
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
					testRandomPartialSignature(t, boundedCurve, boundedHash, boundedThresholdConfig.t, boundedThresholdConfig.n)
				})
			}
		}
	}
}
