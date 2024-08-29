package recovery_test

import (
	crand "crypto/rand"
	"fmt"
	"hash"
	"testing"
	"time"

	"github.com/stretchr/testify/require"
	"golang.org/x/crypto/sha3"
	"golang.org/x/sync/errgroup"

	"github.com/copperexchange/krypton-primitives/pkg/base/curves"
	"github.com/copperexchange/krypton-primitives/pkg/base/curves/k256"
	ds "github.com/copperexchange/krypton-primitives/pkg/base/datastructures"
	"github.com/copperexchange/krypton-primitives/pkg/base/datastructures/hashset"
	"github.com/copperexchange/krypton-primitives/pkg/base/polynomials/interpolation/lagrange"
	"github.com/copperexchange/krypton-primitives/pkg/base/roundbased/simulator"
	"github.com/copperexchange/krypton-primitives/pkg/base/types"
	ttu "github.com/copperexchange/krypton-primitives/pkg/base/types/testutils"
	agreeonrandom_testutils "github.com/copperexchange/krypton-primitives/pkg/threshold/agreeonrandom/testutils"
	jf_testutils "github.com/copperexchange/krypton-primitives/pkg/threshold/dkg/jf/testutils"
	"github.com/copperexchange/krypton-primitives/pkg/threshold/recovery"
	"github.com/copperexchange/krypton-primitives/pkg/threshold/recovery/testutils"
	"github.com/copperexchange/krypton-primitives/pkg/threshold/sharing/shamir"
	"github.com/copperexchange/krypton-primitives/pkg/threshold/tsignatures"
)

func setup(t *testing.T, curve curves.Curve, h func() hash.Hash, threshold, n int) (uniqueSessiondId []byte, identities []types.IdentityKey, protocol types.ThresholdProtocol, dkgSigningKeyShares []*tsignatures.SigningKeyShare, dkgPublicKeyShares []*tsignatures.PartialPublicKeys) {
	t.Helper()

	cipherSuite, err := ttu.MakeSigningSuite(curve, h)
	require.NoError(t, err)
	identities, err = ttu.MakeTestIdentities(cipherSuite, n)
	require.NoError(t, err)
	protocol, err = ttu.MakeThresholdProtocol(curve, identities, threshold)
	require.NoError(t, err)

	uniqueSessionId, err := agreeonrandom_testutils.RunAgreeOnRandom(curve, identities, crand.Reader)
	require.NoError(t, err)

	dkgSigningKeyShares, dkgPublicKeyShares, err = jf_testutils.RunDKG(uniqueSessionId, protocol, identities)
	require.NoError(t, err)

	return uniqueSessionId, identities, protocol, dkgSigningKeyShares, dkgPublicKeyShares
}

func testHappyPath(t *testing.T, curve curves.Curve, threshold, n int) (participant []*recovery.Participant) {
	t.Helper()

	uniqueSessionId, identities, protocol, dkgSigningKeyShares, dkgPublicKeyShares := setup(t, curve, sha3.New256, threshold, n)
	var parties []*recovery.Participant
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

			_, recoveredShare, err := testutils.RunRecovery(uniqueSessionId, protocol, allPresentRecoverers, identities, lostPartyIndex, dkgSigningKeyShares, dkgPublicKeyShares, nil)
			require.NoError(t, err)
			parties, err = testutils.MakeParticipants(uniqueSessionId, protocol, allPresentRecoverers, identities, lostPartyIndex, dkgSigningKeyShares, dkgPublicKeyShares, nil)
			require.NoError(t, err)
			require.Zero(t, recoveredShare.Share.Cmp(dkgSigningKeyShares[lostPartyIndex].Share))
			require.NotNil(t, parties)
		})
	}
	return parties
}

func testHappyPathWithParallelParties(t *testing.T, curve curves.Curve, threshold, n int) (participant []*recovery.Participant) {
	t.Helper()

	uniqueSessionId, identities, protocol, dkgSigningKeyShares, dkgPublicKeyShares := setup(t, curve, sha3.New256, threshold, n)
	var parties []*recovery.Participant
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

			_, recoveredShare, err := testutils.RunRecoveryWithParallelParties(uniqueSessionId, protocol, allPresentRecoverers, identities, lostPartyIndex, dkgSigningKeyShares, dkgPublicKeyShares, nil)
			require.NoError(t, err)
			parties, err = testutils.MakeParticipants(uniqueSessionId, protocol, allPresentRecoverers, identities, lostPartyIndex, dkgSigningKeyShares, dkgPublicKeyShares, nil)
			require.NoError(t, err)
			require.Zero(t, recoveredShare.Share.Cmp(dkgSigningKeyShares[lostPartyIndex].Share))
			require.NotNil(t, parties)
		})
	}
	return parties
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
				participant := testHappyPath(t, boundedCurve, boundedThresholdConfig.t, boundedThresholdConfig.n)
				happyPathRoundBasedRunner(t, participant, curve, boundedThresholdConfig.t, boundedThresholdConfig.n)
			})
			t.Run(fmt.Sprintf("Happy path with parallel parties on curve=%s and t=%d and n=%d", boundedCurve.Name(), boundedThresholdConfig.t, boundedThresholdConfig.n), func(t *testing.T) {
				t.Parallel()
				participant := testHappyPathWithParallelParties(t, boundedCurve, boundedThresholdConfig.t, boundedThresholdConfig.n)
				happyPathRoundBasedRunner(t, participant, curve, boundedThresholdConfig.t, boundedThresholdConfig.n)
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

func happyPathRoundBasedRunner(t *testing.T, participants []*recovery.Participant, curve curves.Curve, threshold, n int) {
	t.Helper()
	_, _, protocol, dkgSigningKeyShares, _ := setup(t, curve, sha3.New256, threshold, n)
	router := simulator.NewEchoBroadcastMessageRouter(protocol.Participants())
	signingKeyShares := make([]*tsignatures.SigningKeyShare, n)
	errChan := make(chan error)
	go func() {
		var errGrp errgroup.Group
		for i, party := range participants {
			errGrp.Go(func() error {
				var err error
				signingKeyShares[i], err = party.Run(router)
				return err
			})
		}
		errChan <- errGrp.Wait()
	}()

	select {
	case err := <-errChan:
		require.NoError(t, err)
	case <-time.After(5 * time.Second):
		require.Fail(t, "timeout")
	}

	t.Run("Testing", func(t *testing.T) {
		t.Parallel()
		for i := range participants {
			require.Zero(t, signingKeyShares[i].Share.Cmp(dkgSigningKeyShares[i].Share))
		}
	})
}
