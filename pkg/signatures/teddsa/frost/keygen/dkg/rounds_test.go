package dkg_test

import (
	"github.com/copperexchange/crypto-primitives-go/pkg/sharing"
	"testing"

	"github.com/copperexchange/crypto-primitives-go/pkg/core/curves"
	"github.com/copperexchange/crypto-primitives-go/pkg/core/integration"
	"github.com/stretchr/testify/require"
	"golang.org/x/crypto/sha3"
)

func Test_HappyPath(t *testing.T) {
	t.Parallel()

	curve := curves.ED25519()
	h := sha3.New256
	cipherSuite := &integration.CipherSuite{
		Curve: curve,
		Hash:  h,
	}

	cohortConfig, err := MakeCohort(cipherSuite, "FROST", 2, 3)
	require.NoError(t, err)

	participants, err := MakeDkgParticipants(cohortConfig)
	require.NoError(t, err)

	r1Outs, err := DoDkgRound1(participants)
	require.NoError(t, err)
	for _, out := range r1Outs {
		require.NotNil(t, out)
	}

	r2Ins := MapDkgRound1OutputsToRound2Inputs(participants, r1Outs)
	r2OutsB, r2OutsU, err := DoDkgRound2(participants, r2Ins)
	require.NoError(t, err)
	for _, out := range r2OutsU {
		require.Len(t, out, cohortConfig.TotalParties-1)
	}

	r3InsB, r3InsU := MapDkgRound2OutputsToRound3Inputs(participants, r2OutsB, r2OutsU)
	signingKeyShares, publicKeyShares, err := DoDkgRound3(participants, r3InsB, r3InsU)
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
