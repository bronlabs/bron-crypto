package pedersen_test

import (
	"testing"
	"time"

	"github.com/stretchr/testify/require"
	"golang.org/x/sync/errgroup"

	"github.com/copperexchange/krypton-primitives/pkg/base/curves/k256"
	"github.com/copperexchange/krypton-primitives/pkg/base/roundbased/simulator"
	ttu "github.com/copperexchange/krypton-primitives/pkg/base/types/testutils"
	"github.com/copperexchange/krypton-primitives/pkg/threshold/dkg/pedersen/testutils"
	"github.com/copperexchange/krypton-primitives/pkg/threshold/sharing/shamir"
	"github.com/copperexchange/krypton-primitives/pkg/threshold/tsignatures"
)

func Test_HappyPathRandomRoundBasedRunner(t *testing.T) {
	t.Parallel()

	const n = 3
	const threshold = 2
	const sessionId = "testSessionId"
	curve := k256.NewCurve()
	identities, err := ttu.MakeDeterministicTestIdentities(n)
	require.NoError(t, err)
	protocol, err := ttu.MakeThresholdProtocol(curve, identities, threshold)
	require.NoError(t, err)
	participants, err := testutils.MakeParticipants([]byte(sessionId), protocol, identities, nil)
	require.NoError(t, err)

	router := simulator.NewEchoBroadcastMessageRouter(protocol.Participants())
	signingKeyShares := make([]*tsignatures.SigningKeyShare, n)
	publicKeyShares := make([]*tsignatures.PartialPublicKeys, n)
	errChan := make(chan error)
	go func() {
		var errGrp errgroup.Group
		for i, party := range participants {
			errGrp.Go(func() error {
				var err error
				signingKeyShares[i], publicKeyShares[i], err = party.Run(router)
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

	t.Run("each signing key share is different than all others", func(t *testing.T) {
		t.Parallel()
		for i := 0; i < len(signingKeyShares); i++ {
			for j := i + 1; j < len(signingKeyShares); j++ {
				require.NotZero(t, signingKeyShares[i].Share.Cmp(signingKeyShares[j].Share))
			}
		}
	})

	t.Run("each public key is the same as all others", func(t *testing.T) {
		t.Parallel()
		for i := 0; i < len(signingKeyShares); i++ {
			for j := i + 1; j < len(signingKeyShares); j++ {
				require.True(t, signingKeyShares[i].PublicKey.Equal(signingKeyShares[j].PublicKey))
			}
		}
	})

	t.Run("reconstructed private key is the dlog of the public key", func(t *testing.T) {
		t.Parallel()
		shamirDealer, err := shamir.NewDealer(uint(threshold), uint(n), curve)
		require.NoError(t, err)
		require.NotNil(t, shamirDealer)
		shamirShares := make([]*shamir.Share, len(participants))
		for i := 0; i < len(participants); i++ {
			shamirShares[i] = &shamir.Share{
				Id:    uint(participants[i].SharingId()),
				Value: signingKeyShares[i].Share,
			}
		}

		reconstructedPrivateKey, err := shamirDealer.Combine(shamirShares...)
		require.NoError(t, err)

		derivedPublicKey := curve.ScalarBaseMult(reconstructedPrivateKey)
		require.True(t, signingKeyShares[0].PublicKey.Equal(derivedPublicKey))
	})
}
