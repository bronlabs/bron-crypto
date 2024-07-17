package vsot_test

import (
	crand "crypto/rand"
	"testing"
	"time"

	"github.com/stretchr/testify/require"
	"golang.org/x/crypto/sha3"
	"golang.org/x/sync/errgroup"

	"github.com/copperexchange/krypton-primitives/pkg/base/curves"
	"github.com/copperexchange/krypton-primitives/pkg/base/curves/k256"
	"github.com/copperexchange/krypton-primitives/pkg/base/curves/p256"
	"github.com/copperexchange/krypton-primitives/pkg/base/datastructures/hashset"
	"github.com/copperexchange/krypton-primitives/pkg/base/roundbased/simulator"
	"github.com/copperexchange/krypton-primitives/pkg/base/types"
	ttu "github.com/copperexchange/krypton-primitives/pkg/base/types/testutils"
	"github.com/copperexchange/krypton-primitives/pkg/ot"
	"github.com/copperexchange/krypton-primitives/pkg/ot/base/vsot"
	"github.com/copperexchange/krypton-primitives/pkg/ot/base/vsot/testutils"
	ot_testutils "github.com/copperexchange/krypton-primitives/pkg/ot/testutils"
	randomisedFischlin "github.com/copperexchange/krypton-primitives/pkg/proofs/sigma/compiler/randfischlin"
)

func getKeys(t *testing.T) (senderKey, receiverKey types.AuthKey) {
	t.Helper()
	cipherSuite, err := ttu.MakeSigningSuite(k256.NewCurve(), sha3.New256)
	require.NoError(t, err)
	authKeys, err := ttu.MakeTestAuthKeys(cipherSuite, 2)
	require.NoError(t, err)
	return authKeys[0], authKeys[1]
}

func TestHappyPathVSOT_ROT(t *testing.T) {
	t.Parallel()
	curveInstances := []curves.Curve{
		k256.NewCurve(),
		p256.NewCurve(),
	}
	senderKey, receiverKey := getKeys(t)
	for _, curve := range curveInstances {
		Xi := 256
		L := 4
		uniqueSessionId := [32]byte{}
		_, err := crand.Read(uniqueSessionId[:])
		require.NoError(t, err)
		sender, receiver, err := testutils.RunVSOT(senderKey, receiverKey, Xi, L, curve, uniqueSessionId[:], crand.Reader)
		require.NoError(t, err)
		err = ot_testutils.ValidateOT(Xi, L, sender.MessagePairs, receiver.Choices, receiver.ChosenMessages)
		require.NoError(t, err)
	}
}
func TestHappyPathVSOT_OT(t *testing.T) {
	t.Parallel()
	curveInstances := []curves.Curve{
		k256.NewCurve(),
		p256.NewCurve(),
	}
	senderKey, receiverKey := getKeys(t)
	for _, curve := range curveInstances {
		Xi := 128
		L := 3
		uniqueSessionId := [32]byte{}
		_, err := crand.Read(uniqueSessionId[:])
		require.NoError(t, err)
		sender, receiver, err := testutils.RunVSOT(senderKey, receiverKey, Xi, L, curve, uniqueSessionId[:], crand.Reader)
		require.NoError(t, err)
		err = ot_testutils.ValidateOT(Xi, L, sender.MessagePairs, receiver.Choices, receiver.ChosenMessages)
		require.NoError(t, err)
		// Generate inputs for (chosen) OT
		_, senderMessages, err := ot_testutils.GenerateOTinputs(Xi, L)
		require.NoError(t, err)

		// Run (chosen) OT
		masks, err := sender.Encrypt(senderMessages)
		require.NoError(t, err)
		receiverOTchosenMessages, err := receiver.Decrypt(masks)
		require.NoError(t, err)

		// Validate result
		err = ot_testutils.ValidateOT(Xi, L, senderMessages, receiver.Choices, receiverOTchosenMessages)
		require.NoError(t, err)
	}
}

func TestHappyPathVSOT_COT(t *testing.T) {
	t.Parallel()
	curveInstances := []curves.Curve{
		k256.NewCurve(),
		p256.NewCurve(),
	}
	senderKey, receiverKey := getKeys(t)
	for _, curve := range curveInstances {
		Xi := 128
		L := 3
		uniqueSessionId := [32]byte{}
		_, err := crand.Read(uniqueSessionId[:])
		require.NoError(t, err)
		sender, receiver, err := testutils.RunVSOT(senderKey, receiverKey, Xi, L, curve, uniqueSessionId[:], crand.Reader)
		require.NoError(t, err)
		err = ot_testutils.ValidateOT(Xi, L, sender.MessagePairs, receiver.Choices, receiver.ChosenMessages)
		require.NoError(t, err)

		// Generate inputs for Correlated OT
		x := receiver.Choices
		_, a, err := ot_testutils.GenerateCOTinputs(Xi, L, curve)
		require.NoError(t, err)

		// Run (chosen) OT
		z_A, tau, err := sender.CreateCorrelation(a)
		require.NoError(t, err)
		z_B, err := receiver.ApplyCorrelation(tau)
		require.NoError(t, err)

		// Validate result
		err = ot_testutils.ValidateCOT(Xi, L, x, a, z_B, z_A)
		require.NoError(t, err)
	}
}

func TestHappyPathVSOT_ROT_WithRunner(t *testing.T) {
	t.Parallel()
	curveInstances := []curves.Curve{
		k256.NewCurve(),
		p256.NewCurve(),
	}
	senderKey, receiverKey := getKeys(t)
	for _, curve := range curveInstances {
		Xi := 256
		L := 4
		uniqueSessionId := [32]byte{}
		_, err := crand.Read(uniqueSessionId[:])
		require.NoError(t, err)

		prng := crand.Reader
		protocol, err := types.NewProtocol(curve, hashset.NewHashableHashSet(senderKey.(types.IdentityKey), receiverKey.(types.IdentityKey)))
		require.NoError(t, err)
		receiver, err := vsot.NewReceiver(receiverKey, protocol, Xi, L, uniqueSessionId[:], randomisedFischlin.Name, nil, prng)
		require.NoError(t, err)

		sender, err := vsot.NewSender(senderKey, protocol, Xi, L, uniqueSessionId[:], randomisedFischlin.Name, nil, prng)
		require.NoError(t, err)

		router := simulator.NewEchoBroadcastMessageRouter(protocol.Participants())

		var senderOutput *ot.SenderRotOutput
		var receiverOutput *ot.ReceiverRotOutput

		errChan := make(chan error)
		go func() {
			var errGrp errgroup.Group
			errGrp.Go(func() error {

				err = sender.Run(router, receiver)
				return err
			})
			errGrp.Go(func() error {
				senderOutput, receiverOutput, err = receiver.Run(router, sender)
				return err

			})
			errChan <- errGrp.Wait()
		}()
		select {
		case err = <-errChan:
			require.NoError(t, err)
		case <-time.After(30 * time.Second):
			require.Fail(t, "timeout")
		}

		err = ot_testutils.ValidateOT(Xi, L, senderOutput.MessagePairs, receiverOutput.Choices, receiverOutput.ChosenMessages)
		require.NoError(t, err)
	}
}

func TestHappyPathVSOT_OT_WithRunner(t *testing.T) {
	t.Parallel()
	curveInstances := []curves.Curve{
		k256.NewCurve(),
		p256.NewCurve(),
	}
	senderKey, receiverKey := getKeys(t)
	for _, curve := range curveInstances {
		Xi := 128
		L := 3
		uniqueSessionId := [32]byte{}
		_, err := crand.Read(uniqueSessionId[:])
		require.NoError(t, err)
		prng := crand.Reader
		protocol, err := types.NewProtocol(curve, hashset.NewHashableHashSet(senderKey.(types.IdentityKey), receiverKey.(types.IdentityKey)))
		require.NoError(t, err)
		receiver, err := vsot.NewReceiver(receiverKey, protocol, Xi, L, uniqueSessionId[:], randomisedFischlin.Name, nil, prng)
		require.NoError(t, err)

		sender, err := vsot.NewSender(senderKey, protocol, Xi, L, uniqueSessionId[:], randomisedFischlin.Name, nil, prng)
		require.NoError(t, err)

		router := simulator.NewEchoBroadcastMessageRouter(protocol.Participants())

		var senderOutput *ot.SenderRotOutput
		var receiverOutput *ot.ReceiverRotOutput

		errChan := make(chan error)
		go func() {
			var errGrp errgroup.Group
			errGrp.Go(func() error {

				err = sender.Run(router, receiver)
				return err
			})
			errGrp.Go(func() error {
				senderOutput, receiverOutput, err = receiver.Run(router, sender)
				return err

			})
			errChan <- errGrp.Wait()
		}()
		select {
		case err = <-errChan:
			require.NoError(t, err)
		case <-time.After(30 * time.Second):
			require.Fail(t, "timeout")
		}

		err = ot_testutils.ValidateOT(Xi, L, senderOutput.MessagePairs, receiverOutput.Choices, receiverOutput.ChosenMessages)
		require.NoError(t, err)
		// Generate inputs for (chosen) OT
		_, senderMessages, err := ot_testutils.GenerateOTinputs(Xi, L)
		require.NoError(t, err)

		// Run (chosen) OT
		masks, err := senderOutput.Encrypt(senderMessages)
		require.NoError(t, err)
		receiverOTchosenMessages, err := receiverOutput.Decrypt(masks)
		require.NoError(t, err)

		// Validate result
		err = ot_testutils.ValidateOT(Xi, L, senderMessages, receiverOutput.Choices, receiverOTchosenMessages)
		require.NoError(t, err)
	}
}

func TestHappyPathVSOT_COT_WithRunner(t *testing.T) {
	t.Parallel()
	curveInstances := []curves.Curve{
		k256.NewCurve(),
		p256.NewCurve(),
	}
	senderKey, receiverKey := getKeys(t)
	for _, curve := range curveInstances {
		Xi := 128
		L := 3
		uniqueSessionId := [32]byte{}
		_, err := crand.Read(uniqueSessionId[:])
		require.NoError(t, err)
		prng := crand.Reader
		protocol, err := types.NewProtocol(curve, hashset.NewHashableHashSet(senderKey.(types.IdentityKey), receiverKey.(types.IdentityKey)))
		require.NoError(t, err)
		receiver, err := vsot.NewReceiver(receiverKey, protocol, Xi, L, uniqueSessionId[:], randomisedFischlin.Name, nil, prng)
		require.NoError(t, err)

		sender, err := vsot.NewSender(senderKey, protocol, Xi, L, uniqueSessionId[:], randomisedFischlin.Name, nil, prng)
		require.NoError(t, err)

		router := simulator.NewEchoBroadcastMessageRouter(protocol.Participants())

		var senderOutput *ot.SenderRotOutput
		var receiverOutput *ot.ReceiverRotOutput

		errChan := make(chan error)
		go func() {
			var errGrp errgroup.Group
			errGrp.Go(func() error {

				err = sender.Run(router, receiver)
				return err
			})
			errGrp.Go(func() error {
				senderOutput, receiverOutput, err = receiver.Run(router, sender)
				return err

			})
			errChan <- errGrp.Wait()
		}()
		select {
		case err = <-errChan:
			require.NoError(t, err)
		case <-time.After(30 * time.Second):
			require.Fail(t, "timeout")
		}

		err = ot_testutils.ValidateOT(Xi, L, senderOutput.MessagePairs, receiverOutput.Choices, receiverOutput.ChosenMessages)
		require.NoError(t, err)

		// Generate inputs for Correlated OT
		x := receiverOutput.Choices
		_, a, err := ot_testutils.GenerateCOTinputs(Xi, L, curve)
		require.NoError(t, err)

		// Run (chosen) OT
		z_A, tau, err := senderOutput.CreateCorrelation(a)
		require.NoError(t, err)
		z_B, err := receiverOutput.ApplyCorrelation(tau)
		require.NoError(t, err)

		// Validate result
		err = ot_testutils.ValidateCOT(Xi, L, x, a, z_B, z_A)
		require.NoError(t, err)
	}
}
