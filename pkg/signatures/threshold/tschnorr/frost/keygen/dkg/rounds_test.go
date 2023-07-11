package dkg_test

import (
	"crypto/sha512"
	"fmt"
	"github.com/copperexchange/crypto-primitives-go/pkg/core/errs"
	"hash"
	"reflect"
	"runtime"
	"strings"
	"testing"

	agreeonrandom_test_utils "github.com/copperexchange/crypto-primitives-go/pkg/agreeonrandom/test_utils"
	"github.com/copperexchange/crypto-primitives-go/pkg/core/curves"
	"github.com/copperexchange/crypto-primitives-go/pkg/core/integration"
	test_utils_integration "github.com/copperexchange/crypto-primitives-go/pkg/core/integration/test_utils"
	"github.com/copperexchange/crypto-primitives-go/pkg/core/protocol"
	"github.com/copperexchange/crypto-primitives-go/pkg/sharing/shamir"
	"github.com/copperexchange/crypto-primitives-go/pkg/signatures/threshold/tschnorr/frost/test_utils"
	"github.com/stretchr/testify/require"
	"golang.org/x/crypto/sha3"
)

func testHappyPath(t *testing.T, curve *curves.Curve, h func() hash.Hash, threshold int, n int) {
	t.Helper()

	cipherSuite := &integration.CipherSuite{
		Curve: curve,
		Hash:  h,
	}

	identities, err := test_utils_integration.MakeIdentities(cipherSuite, n)
	require.NoError(t, err)
	cohortConfig, err := test_utils_integration.MakeCohort(cipherSuite, protocol.FROST, identities, threshold, identities)
	require.NoError(t, err)

	uniqueSessionId := agreeonrandom_test_utils.ProduceSharedRandomValue(t, curve, identities, n)

	participants, err := test_utils.MakeDkgParticipants(uniqueSessionId, cohortConfig, identities, nil)
	require.NoError(t, err)

	r1OutsB, r1OutsU, err := test_utils.DoDkgRound1(participants)
	require.NoError(t, err)
	for _, out := range r1OutsU {
		require.Len(t, out, cohortConfig.TotalParties-1)
	}

	r2InsB, r2InsU := test_utils.MapDkgRound1OutputsToRound2Inputs(participants, r1OutsB, r1OutsU)
	signingKeyShares, publicKeyShares, err := test_utils.DoDkgRound2(participants, r2InsB, r2InsU)

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

	shamirDealer, err := shamir.NewDealer(threshold, n, curve)
	require.NoError(t, err)
	require.NotNil(t, shamirDealer)
	shamirShares := make([]*shamir.Share, len(participants))
	for i := 0; i < len(participants); i++ {
		shamirShares[i] = &shamir.Share{
			Id:    participants[i].GetShamirId(),
			Value: signingKeyShares[i].Share,
		}
	}

	reconstructedPrivateKey, err := shamirDealer.Combine(shamirShares...)
	require.NoError(t, err)

	derivedPublicKey := curve.ScalarBaseMult(reconstructedPrivateKey)
	require.True(t, signingKeyShares[0].PublicKey.Equal(derivedPublicKey))
}

func testInvalidSid(t *testing.T, curve *curves.Curve, h func() hash.Hash, threshold int, n int) {
	t.Helper()

	cipherSuite := &integration.CipherSuite{
		Curve: curve,
		Hash:  h,
	}

	identities, err := test_utils_integration.MakeIdentities(cipherSuite, n)
	require.NoError(t, err)
	cohortConfig, err := test_utils_integration.MakeCohort(cipherSuite, protocol.FROST, identities, threshold, identities)
	require.NoError(t, err)

	uniqueSessionId := agreeonrandom_test_utils.ProduceSharedRandomValue(t, curve, identities, n)

	participants, err := test_utils.MakeDkgParticipants(uniqueSessionId, cohortConfig, identities, nil)
	participants[0].UniqueSessionId = []byte("invalid")
	require.NoError(t, err)

	r1OutsB, r1OutsU, err := test_utils.DoDkgRound1(participants)
	require.NoError(t, err)
	for _, out := range r1OutsU {
		require.Len(t, out, cohortConfig.TotalParties-1)
	}

	r2InsB, r2InsU := test_utils.MapDkgRound1OutputsToRound2Inputs(participants, r1OutsB, r1OutsU)
	_, _, err = test_utils.DoDkgRound2(participants, r2InsB, r2InsU)
	require.True(t, errs.IsIdentifiableAbort(err))
}

func Test_HappyPath(t *testing.T) {
	t.Parallel()
	for _, curve := range []*curves.Curve{curves.K256(), curves.ED25519()} {
		for _, h := range []func() hash.Hash{sha3.New256, sha512.New} {
			for _, thresholdConfig := range []struct {
				t int
				n int
			}{
				{t: 2, n: 2},
				{t: 2, n: 3},
				{t: 3, n: 3},
			} {
				boundedCurve := curve
				boundedHash := h
				boundedHashName := runtime.FuncForPC(reflect.ValueOf(h).Pointer()).Name()
				boundedThresholdConfig := thresholdConfig
				t.Run(fmt.Sprintf("Happy path with curve=%s and hash=%s and t=%d and n=%d", boundedCurve.Name, boundedHashName[strings.LastIndex(boundedHashName, "/")+1:], boundedThresholdConfig.t, boundedThresholdConfig.n), func(t *testing.T) {
					t.Parallel()
					testHappyPath(t, boundedCurve, boundedHash, boundedThresholdConfig.t, boundedThresholdConfig.n)
				})
			}
		}
	}
}

func TestInvalidSid(t *testing.T) {
	t.Parallel()
	for _, curve := range []*curves.Curve{curves.K256(), curves.ED25519()} {
		for _, h := range []func() hash.Hash{sha3.New256, sha512.New} {
			for _, thresholdConfig := range []struct {
				t int
				n int
			}{
				{t: 2, n: 2},
				{t: 2, n: 3},
				{t: 3, n: 3},
			} {
				boundedCurve := curve
				boundedHash := h
				boundedHashName := runtime.FuncForPC(reflect.ValueOf(h).Pointer()).Name()
				boundedThresholdConfig := thresholdConfig
				t.Run(fmt.Sprintf("Happy path with curve=%s and hash=%s and t=%d and n=%d", boundedCurve.Name, boundedHashName[strings.LastIndex(boundedHashName, "/")+1:], boundedThresholdConfig.t, boundedThresholdConfig.n), func(t *testing.T) {
					t.Parallel()
					testInvalidSid(t, boundedCurve, boundedHash, boundedThresholdConfig.t, boundedThresholdConfig.n)
				})
			}
		}
	}
}
