package recovery_test

import (
	crand "crypto/rand"
	"fmt"
	"hash"
	"testing"

	"github.com/stretchr/testify/require"
	"golang.org/x/crypto/sha3"

	"github.com/bronlabs/krypton-primitives/pkg/base/curves"
	"github.com/bronlabs/krypton-primitives/pkg/base/curves/k256"
	ds "github.com/bronlabs/krypton-primitives/pkg/base/datastructures"
	"github.com/bronlabs/krypton-primitives/pkg/base/datastructures/hashset"
	"github.com/bronlabs/krypton-primitives/pkg/base/polynomials/interpolation/lagrange"
	"github.com/bronlabs/krypton-primitives/pkg/base/types"
	ttu "github.com/bronlabs/krypton-primitives/pkg/base/types/testutils"
	agreeonrandom_testutils "github.com/bronlabs/krypton-primitives/pkg/threshold/agreeonrandom/testutils"
	jf_testutils "github.com/bronlabs/krypton-primitives/pkg/threshold/dkg/jf/testutils"
	"github.com/bronlabs/krypton-primitives/pkg/threshold/recovery/testutils"
	"github.com/bronlabs/krypton-primitives/pkg/threshold/sharing/shamir"
	"github.com/bronlabs/krypton-primitives/pkg/threshold/tsignatures"
)

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

	l2, err := lagrange.L_i(curve, 0, xs, aliceX)
	require.NoError(t, err)
	l3, err := lagrange.L_i(curve, 1, xs, aliceX)
	require.NoError(t, err)

	partialBob := bob.Value.Mul(l2)
	partialCharlie := charlie.Value.Mul(l3)

	recovered := partialBob.Add(partialCharlie)
	require.Zero(t, alice.Value.Cmp(recovered))
}

func setup(t *testing.T, curve curves.Curve, h func() hash.Hash, threshold, n int) (uniqueSessiondId []byte, identities []types.IdentityKey, protocol types.ThresholdProtocol, dkgSigningKeyShares []*tsignatures.SigningKeyShare, dkgPublicKeyShares []*tsignatures.PartialPublicKeys) {
	t.Helper()

	cipherSuite, err := ttu.MakeSigningSuite(curve, h)
	require.NoError(t, err)
	identities, err = ttu.MakeTestIdentities(cipherSuite, n)
	require.NoError(t, err)
	protocol, err = ttu.MakeThresholdProtocol(curve, identities, threshold)
	require.NoError(t, err)

	uniqueSessionId, err := agreeonrandom_testutils.RunAgreeOnRandom(t, curve, identities, crand.Reader)
	require.NoError(t, err)

	dkgSigningKeyShares, dkgPublicKeyShares = jf_testutils.DoDkgHappyPath(t, uniqueSessionId, protocol, identities)

	return uniqueSessionId, identities, protocol, dkgSigningKeyShares, dkgPublicKeyShares
}

func testHappyPath(t *testing.T, curve curves.Curve, threshold, n int) {
	t.Helper()

	uniqueSessionId, identities, protocol, dkgSigningKeyShares, dkgPublicKeyShares := setup(t, curve, sha3.New256, threshold, n)
	for i := 0; i < n; i++ {
		lostPartyIndex := i
		t.Run(fmt.Sprintf("running recovery for participant index %d", lostPartyIndex), func(t *testing.T) {
			t.Parallel()

			presentRecoverers := hashset.NewHashableHashSet(identities...)
			presentRecoverers.Remove(identities[lostPartyIndex])
			allPresentRecoverers := make([]ds.Set[types.IdentityKey], len(identities))
			for i := 0; i < len(identities); i++ {
				allPresentRecoverers[i] = presentRecoverers.Clone()
			}

			_, recoveredShare, err := testutils.RunRecovery(t, uniqueSessionId, protocol, allPresentRecoverers, identities, lostPartyIndex, dkgSigningKeyShares, dkgPublicKeyShares, nil)
			require.NoError(t, err)
			require.Zero(t, recoveredShare.Share.Cmp(dkgSigningKeyShares[lostPartyIndex].Share))
		})
	}
}
