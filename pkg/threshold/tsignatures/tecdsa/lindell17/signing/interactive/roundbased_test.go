package interactive_signing_test

import (
	crand "crypto/rand"
	"crypto/sha256"
	"testing"
	"time"

	"github.com/stretchr/testify/require"
	"golang.org/x/sync/errgroup"

	"github.com/copperexchange/krypton-primitives/pkg/base/curves/k256"
	"github.com/copperexchange/krypton-primitives/pkg/base/datastructures/hashset"
	"github.com/copperexchange/krypton-primitives/pkg/base/roundbased/simulator"
	"github.com/copperexchange/krypton-primitives/pkg/base/types"
	"github.com/copperexchange/krypton-primitives/pkg/base/types/testutils"
	"github.com/copperexchange/krypton-primitives/pkg/signatures/ecdsa"
	"github.com/copperexchange/krypton-primitives/pkg/threshold/tsignatures/tecdsa/lindell17/keygen/trusted_dealer"
	interactive_signing "github.com/copperexchange/krypton-primitives/pkg/threshold/tsignatures/tecdsa/lindell17/signing/interactive"
)

func Test_HappyPathRoundBased(t *testing.T) {
	t.Parallel()

	// setup
	sessionId := []byte("TestSession")
	curve := k256.NewCurve()
	hash := sha256.New
	cipherSuite, err := testutils.MakeSigningSuite(curve, hash)
	require.NoError(t, err)
	identities, err := testutils.MakeTestIdentities(cipherSuite, 3)
	require.NoError(t, err)
	alice, bob, charlie := identities[0], identities[1], identities[2]
	protocol, err := testutils.MakeThresholdSignatureProtocol(cipherSuite, identities, 2, identities)
	require.NoError(t, err)
	message := []byte("Hello World!")
	require.NoError(t, err)
	shards, err := trusted_dealer.Keygen(protocol, crand.Reader)
	require.NoError(t, err)
	require.NotNil(t, shards)
	require.Equal(t, shards.Size(), int(protocol.TotalParties()))
	aliceShard, exists := shards.Get(alice)
	require.True(t, exists)
	bobShard, exists := shards.Get(bob)
	require.True(t, exists)
	_, exists = shards.Get(charlie)
	require.True(t, exists)

	primary, err := interactive_signing.NewPrimaryCosigner(sessionId, alice.(types.AuthKey), bob, aliceShard, protocol, cn, nil, crand.Reader)
	require.NotNil(t, primary)
	require.NoError(t, err)

	secondary, err := interactive_signing.NewSecondaryCosigner(sessionId, bob.(types.AuthKey), alice, bobShard, protocol, cn, nil, crand.Reader)
	require.NotNil(t, secondary)
	require.NoError(t, err)

	router := simulator.NewEchoBroadcastMessageRouter(hashset.NewHashableHashSet(primary.IdentityKey(), secondary.IdentityKey()))
	var signature *ecdsa.Signature
	errChan := make(chan error)
	go func() {
		var errGrp errgroup.Group
		errGrp.Go(func() error {
			var err error
			signature, err = interactive_signing.PrimaryRunner(router, primary, message)
			return err
		})
		errGrp.Go(func() error {
			return interactive_signing.SecondaryRunner(router, secondary, message)
		})
		errChan <- errGrp.Wait()
	}()

	select {
	case err = <-errChan:
		require.NoError(t, err)
	case <-time.After(10 * time.Second):
		require.Fail(t, "timeout")
	}

	err = ecdsa.Verify(signature, cipherSuite.Hash(), bobShard.SigningKeyShare.PublicKey, message)
	require.NoError(t, err)
}
