package dkg_test

import (
	"crypto/sha512"
	"fmt"
	"github.com/copperexchange/crypto-primitives-go/pkg/core/protocol"
	"github.com/copperexchange/crypto-primitives-go/pkg/sharing"
	"github.com/copperexchange/crypto-primitives-go/pkg/signatures/teddsa/test_utils"
	"hash"
	"testing"

	"github.com/copperexchange/crypto-primitives-go/pkg/core/curves"
	"github.com/copperexchange/crypto-primitives-go/pkg/core/integration"
	"github.com/stretchr/testify/require"
	"golang.org/x/crypto/sha3"
)

func happyPath(t *testing.T, curve *curves.Curve, h func() hash.Hash, threshold int, n int) {
	t.Parallel()

	cipherSuite := &integration.CipherSuite{
		Curve: curve,
		Hash:  h,
	}

	identities, err := test_utils.MakeIdentities(cipherSuite, n)
	require.NoError(t, err)
	cohortConfig, err := test_utils.MakeCohort(cipherSuite, protocol.FROST, identities, threshold)
	require.NoError(t, err)

	participants, err := test_utils.MakeDkgParticipants(cohortConfig)
	require.NoError(t, err)

	r1Outs, err := test_utils.DoDkgRound1(participants)
	require.NoError(t, err)
	for _, out := range r1Outs {
		require.NotNil(t, out)
	}

	r2Ins := test_utils.MapDkgRound1OutputsToRound2Inputs(participants, r1Outs)
	r2OutsB, r2OutsU, err := test_utils.DoDkgRound2(participants, r2Ins)
	require.NoError(t, err)
	for _, out := range r2OutsU {
		require.Len(t, out, cohortConfig.TotalParties-1)
	}

	r3InsB, r3InsU := test_utils.MapDkgRound2OutputsToRound3Inputs(participants, r2OutsB, r2OutsU)
	signingKeyShares, publicKeyShares, err := test_utils.DoDkgRound3(participants, r3InsB, r3InsU)
	require.NoError(t, err)
	for _, publicKeyShare := range publicKeyShares {
		require.NotNil(t, publicKeyShare)
	}

	// each signing share is different
	for i := 0; i < len(signingKeyShares); i++ {
		for j := i + 1; j < len(signingKeyShares); j++ {
			require.NotZero(t, signingKeyShares[i].Share.Cmp(signingKeyShares[j].Share))
		}
	}

	// each public key is the same
	for i := 0; i < len(signingKeyShares); i++ {
		for j := i + 1; j < len(signingKeyShares); j++ {
			require.True(t, signingKeyShares[i].PublicKey.Equal(signingKeyShares[i].PublicKey))
		}
	}

	shamirDealer, err := sharing.NewShamir(2, 3, curve)
	require.NoError(t, err)
	require.NotNil(t, shamirDealer)
	shamirShares := make([]*sharing.ShamirShare, len(participants))
	for i := 0; i < len(participants); i++ {
		shamirShares[i] = &sharing.ShamirShare{
			Id:    participants[i].MyShamirId,
			Value: signingKeyShares[i].Share,
		}
	}

	reconstructedPrivateKey, err := shamirDealer.Combine(shamirShares...)
	require.NoError(t, err)

	derivedPublicKey := curve.ScalarBaseMult(reconstructedPrivateKey)
	require.True(t, signingKeyShares[0].PublicKey.Equal(derivedPublicKey))
}

func Test_HappyPath(t *testing.T) {
	for _, curve := range []*curves.Curve{curves.ED25519(), curves.K256()} {
		for i, h := range []func() hash.Hash{sha3.New256, sha512.New} {
			for _, thresholdConfig := range []struct {
				t int
				n int
			}{
				{t: 2, n: 3},
				{t: 2, n: 3},
			} {
				boundedCurve := curve
				boundedHash := h
				boundedIndex := i
				boundedThresholdConfig := thresholdConfig
				t.Run(fmt.Sprintf("Happy path with curve=%s and hash index=%d and t=%d and n=%d", boundedCurve.Name, boundedIndex, boundedThresholdConfig.t, boundedThresholdConfig.n), func(t *testing.T) {
					happyPath(t, boundedCurve, boundedHash, boundedThresholdConfig.t, boundedThresholdConfig.n)
				})
			}
		}
	}
}
