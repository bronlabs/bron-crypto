package recovery_test

import (
	crand "crypto/rand"
	"fmt"
	"hash"
	"testing"

	"github.com/stretchr/testify/require"
	"golang.org/x/crypto/sha3"

	"github.com/copperexchange/krypton-primitives/pkg/base/curves"
	"github.com/copperexchange/krypton-primitives/pkg/base/curves/k256"
	"github.com/copperexchange/krypton-primitives/pkg/base/datastructures/hashset"
	"github.com/copperexchange/krypton-primitives/pkg/base/polynomials"
	polynomialsUtils "github.com/copperexchange/krypton-primitives/pkg/base/polynomials/utils"
	"github.com/copperexchange/krypton-primitives/pkg/base/protocols"
	"github.com/copperexchange/krypton-primitives/pkg/base/types/integration"
	integration_testutils "github.com/copperexchange/krypton-primitives/pkg/base/types/integration/testutils"
	agreeonrandom_testutils "github.com/copperexchange/krypton-primitives/pkg/threshold/agreeonrandom/testutils"
	gennaro_testutils "github.com/copperexchange/krypton-primitives/pkg/threshold/dkg/gennaro/testutils"
	"github.com/copperexchange/krypton-primitives/pkg/threshold/recovery/testutils"
	"github.com/copperexchange/krypton-primitives/pkg/threshold/sharing/shamir"
	"github.com/copperexchange/krypton-primitives/pkg/threshold/tsignatures"
)

func setup(t *testing.T, curve curves.Curve, h func() hash.Hash, threshold, n int) (uniqueSessiondId []byte, identities []integration.IdentityKey, cohortConfig *integration.CohortConfig, dkgSigningKeyShares []*tsignatures.SigningKeyShare, dkgPublicKeyShares []*tsignatures.PublicKeyShares) {
	t.Helper()

	cipherSuite := &integration.CipherSuite{
		Curve: curve,
		Hash:  h,
	}

	identities, err := integration_testutils.MakeTestIdentities(cipherSuite, n)
	require.NoError(t, err)
	cohortConfig, err = integration_testutils.MakeCohortProtocol(cipherSuite, protocols.FROST, identities, threshold, identities)
	require.NoError(t, err)

	uniqueSessionId, err := agreeonrandom_testutils.RunAgreeOnRandom(curve, identities, crand.Reader)
	require.NoError(t, err)

	dkgSigningKeyShares, dkgPublicKeyShares, err = gennaro_testutils.RunDKG(uniqueSessionId, cohortConfig, identities)
	require.NoError(t, err)

	return uniqueSessionId, identities, cohortConfig, dkgSigningKeyShares, dkgPublicKeyShares
}

func testHappyPath(t *testing.T, curve curves.Curve, threshold, n int) {
	t.Helper()

	uniqueSessionId, identities, cohortConfig, dkgSigningKeyShares, dkgPublicKeyShares := setup(t, curve, sha3.New256, threshold, n)
	for i := 0; i < n; i++ {
		lostPartyIndex := i
		t.Run(fmt.Sprintf("running recovery for participant index %d", lostPartyIndex), func(t *testing.T) {
			t.Parallel()

			recovererIdentities := []integration.IdentityKey{}
			for j, identity := range identities {
				if j == lostPartyIndex {
					continue
				}
				recovererIdentities = append(recovererIdentities, identity)
			}
			require.Len(t, recovererIdentities, len(identities)-1)

			presentRecoverers := hashset.NewHashSet(recovererIdentities)
			allPresentRecoverers := make([]*hashset.HashSet[integration.IdentityKey], len(identities))
			for i := 0; i < len(identities); i++ {
				allPresentRecoverers[i] = presentRecoverers.Clone()
			}

			_, recoveredShare, err := testutils.RunRecovery(uniqueSessionId, cohortConfig, allPresentRecoverers, identities, lostPartyIndex, dkgSigningKeyShares, dkgPublicKeyShares, nil)
			require.NoError(t, err)
			require.Zero(t, recoveredShare.Share.Cmp(dkgSigningKeyShares[lostPartyIndex].Share))
		})
	}
}

func Test_HappyPath(t *testing.T) {
	t.Parallel()

	for _, curve := range []curves.Curve{k256.NewCurve()} {
		for _, thresholdConfig := range []struct {
			t int
			n int
		}{
			{t: 2, n: 3},
			{t: 2, n: 5},
			{t: 3, n: 5},
		} {
			boundedCurve := curve
			boundedThresholdConfig := thresholdConfig
			t.Run(fmt.Sprintf("Happy path with curve=%s and t=%d and n=%d", boundedCurve.Name(), boundedThresholdConfig.t, boundedThresholdConfig.n), func(t *testing.T) {
				t.Parallel()
				testHappyPath(t, boundedCurve, boundedThresholdConfig.t, boundedThresholdConfig.n)
			})
		}
	}
}

func TestSanity(t *testing.T) {
	t.Parallel()
	curve := k256.NewCurve()
	secret, err := curve.ScalarField().Random(crand.Reader)
	require.NoError(t, err)

	dealer, err := shamir.NewDealer(2, 3, curve)
	require.NoError(t, err)
	shares, err := dealer.Split(secret, crand.Reader)
	require.NoError(t, err)

	alice := shares[0]
	aliceX := curve.ScalarField().New(uint64(alice.Id))

	bob := shares[1]
	bobX := curve.ScalarField().New(uint64(bob.Id))

	charlie := shares[2]
	charlieX := curve.ScalarField().New(uint64(charlie.Id))

	xs := []curves.Scalar{bobX, charlieX}

	l2Poly, err := polynomialsUtils.Li(polynomials.GetScalarUnivariatePolynomialsSet(curve.ScalarRing()), 0, xs)
	require.NoError(t, err)

	l3Poly, err := polynomialsUtils.Li(polynomials.GetScalarUnivariatePolynomialsSet(curve.ScalarRing()), 1, xs)
	require.NoError(t, err)

	partialBob := l2Poly.ScalarMul(bob.Value)
	partialCharlie := l3Poly.ScalarMul(charlie.Value)

	recovered := partialBob.Add(partialCharlie).Eval(aliceX)
	require.Zero(t, alice.Value.Cmp(recovered))
}
