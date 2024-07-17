package softspoken_test

import (
	crand "crypto/rand"
	"io"
	"testing"
	"time"

	"github.com/stretchr/testify/require"
	"golang.org/x/crypto/sha3"
	"golang.org/x/sync/errgroup"

	"github.com/copperexchange/krypton-primitives/pkg/base"
	"github.com/copperexchange/krypton-primitives/pkg/base/curves"
	"github.com/copperexchange/krypton-primitives/pkg/base/curves/k256"
	"github.com/copperexchange/krypton-primitives/pkg/base/curves/p256"
	"github.com/copperexchange/krypton-primitives/pkg/base/curves/pallas"
	"github.com/copperexchange/krypton-primitives/pkg/base/datastructures/hashset"
	"github.com/copperexchange/krypton-primitives/pkg/base/roundbased/simulator"
	"github.com/copperexchange/krypton-primitives/pkg/base/types"
	ttu "github.com/copperexchange/krypton-primitives/pkg/base/types/testutils"
	"github.com/copperexchange/krypton-primitives/pkg/ot"
	bbot_testutils "github.com/copperexchange/krypton-primitives/pkg/ot/base/bbot/testutils"
	vsot_testutils "github.com/copperexchange/krypton-primitives/pkg/ot/base/vsot/testutils"
	"github.com/copperexchange/krypton-primitives/pkg/ot/extension/softspoken"
	"github.com/copperexchange/krypton-primitives/pkg/ot/extension/softspoken/testutils"
	ot_testutils "github.com/copperexchange/krypton-primitives/pkg/ot/testutils"
)

var curveInstances = []curves.Curve{
	k256.NewCurve(),
	p256.NewCurve(),
	pallas.NewCurve(),
}

func getKeys(t *testing.T) (senderKey, receiverKey types.AuthKey) {
	t.Helper()
	cipherSuite, err := ttu.MakeSigningSuite(k256.NewCurve(), sha3.New256)
	require.NoError(t, err)
	authKeys, err := ttu.MakeTestAuthKeys(cipherSuite, 2)
	require.NoError(t, err)
	return authKeys[0], authKeys[1]
}

var baseOTrunners = []func(senderKey, receiverKey types.AuthKey, batchSize, messageLength int, curve curves.Curve, uniqueSessionId []byte, rng io.Reader) (*ot.SenderRotOutput, *ot.ReceiverRotOutput, error){
	vsot_testutils.RunVSOT,
	bbot_testutils.RunBBOT,
}

func Test_HappyPath_ROTe(t *testing.T) {
	t.Parallel()
	senderKey, receiverKey := getKeys(t)
	for _, curve := range curveInstances {
		for _, baseOTrunner := range baseOTrunners {
			// Generic setup
			L := 4
			Xi := 4 * base.ComputationalSecurity
			uniqueSessionId := [ot.KappaBytes]byte{}
			_, err := crand.Read(uniqueSessionId[:])
			require.NoError(t, err)

			// BaseOTs
			baseOtSend, baseOtRec, err := baseOTrunner(senderKey, receiverKey, ot.Kappa, 1, curve, uniqueSessionId[:], crand.Reader)
			require.NoError(t, err)
			err = ot_testutils.ValidateOT(ot.Kappa, 1, baseOtSend.MessagePairs, baseOtRec.Choices, baseOtRec.ChosenMessages)
			require.NoError(t, err)

			// Set OTe inputs
			receiverChoices, _, err := ot_testutils.GenerateCOTinputs(Xi, L, nil)
			require.NoError(t, err)

			// Run OTe
			senderMesages, receiverChosenMessage, err := testutils.RunSoftspokenROTe(
				senderKey, receiverKey, Xi, L, curve, uniqueSessionId[:], crand.Reader, baseOtSend, baseOtRec, receiverChoices)
			require.NoError(t, err)

			// Check ROTe result
			err = ot_testutils.ValidateOT(Xi, L, senderMesages, receiverChoices, receiverChosenMessage)
			require.NoError(t, err)
		}
	}
}

func Test_HappyPath_COTe(t *testing.T) {
	t.Parallel()
	senderKey, receiverKey := getKeys(t)
	for _, curve := range curveInstances {
		for _, baseOTrunner := range baseOTrunners {
			// Generic setup
			L := 4
			Xi := 4 * base.ComputationalSecurity
			uniqueSessionId := [ot.KappaBytes]byte{}
			_, err := crand.Read(uniqueSessionId[:])
			require.NoError(t, err)

			// BaseOTs
			baseOtSend, baseOtRec, err := baseOTrunner(senderKey, receiverKey, ot.Kappa, 1, curve, uniqueSessionId[:], crand.Reader)
			require.NoError(t, err)
			err = ot_testutils.ValidateOT(ot.Kappa, 1, baseOtSend.MessagePairs, baseOtRec.Choices, baseOtRec.ChosenMessages)
			require.NoError(t, err)

			// Set COTe inputs
			choices, cOTeSenderInput, err := ot_testutils.GenerateCOTinputs(Xi, L, curve)
			require.NoError(t, err)

			// Run COTe
			cOTeSenderOutput, cOTeReceiverOutput, err := testutils.RunSoftspokenCOTe(
				senderKey, receiverKey, curve, uniqueSessionId[:], crand.Reader, baseOtSend, baseOtRec, choices, cOTeSenderInput, L, Xi)
			require.NoError(t, err)

			// Check COTe result
			err = ot_testutils.ValidateCOT(Xi, L, choices, cOTeSenderInput, cOTeSenderOutput, cOTeReceiverOutput)
			require.NoError(t, err)
		}
	}
}

func Test_HappyPath_ROTe_WithRunner(t *testing.T) {
	t.Parallel()
	senderKey, receiverKey := getKeys(t)
	for _, curve := range curveInstances {
		for _, baseOTrunner := range baseOTrunners {
			// Generic setup
			L := 4
			Xi := 4 * base.ComputationalSecurity
			uniqueSessionId := [ot.KappaBytes]byte{}
			_, err := crand.Read(uniqueSessionId[:])
			require.NoError(t, err)

			// BaseOTs
			baseOtSend, baseOtRec, err := baseOTrunner(senderKey, receiverKey, ot.Kappa, 1, curve, uniqueSessionId[:], crand.Reader)
			require.NoError(t, err)
			err = ot_testutils.ValidateOT(ot.Kappa, 1, baseOtSend.MessagePairs, baseOtRec.Choices, baseOtRec.ChosenMessages)
			require.NoError(t, err)

			prng := crand.Reader
			// Set OTe inputs
			receiverChoices, _, err := ot_testutils.GenerateCOTinputs(Xi, L, nil)
			require.NoError(t, err)

			protocol, err := types.NewProtocol(curve, hashset.NewHashableHashSet(senderKey.(types.IdentityKey), receiverKey.(types.IdentityKey)))
			require.NoError(t, err)

			// Setup OTe
			sender, err := softspoken.NewSoftspokenSender(senderKey, protocol, baseOtRec, uniqueSessionId[:], nil, prng, nil, L, Xi)
			require.NoError(t, err)

			receiver, err := softspoken.NewSoftspokenReceiver(receiverKey, protocol, baseOtSend, uniqueSessionId[:], nil, prng, nil, L, Xi)
			require.NoError(t, err)

			router := simulator.NewEchoBroadcastMessageRouter(hashset.NewHashableHashSet(sender.IdentityKey(), receiver.IdentityKey()))
			var oTeSenderOutput [][2][][16]byte
			var oTeReceiverOutput [][][16]byte
			errChan := make(chan error)

			go func() {
				var errGrp errgroup.Group
				errGrp.Go(func() error {
					var err error
					oTeReceiverOutput, err = receiver.Run(router, sender, receiverChoices)
					return err
				})
				errGrp.Go(func() error {
					oTeSenderOutput, err = sender.Run(router, receiver)
					return err
				})
				errChan <- errGrp.Wait()
			}()

			select {
			case err = <-errChan:
				require.NoError(t, err)
			case <-time.After(10 * time.Second):
				require.Fail(t, "timeout")
			}

			// Check ROTe result
			err = ot_testutils.ValidateOT(Xi, L, oTeSenderOutput, receiverChoices, oTeReceiverOutput)
			require.NoError(t, err)
		}
	}
}

func Test_HappyPath_COTe_WithRunner(t *testing.T) {
	t.Parallel()
	senderKey, receiverKey := getKeys(t)
	for _, curve := range curveInstances {
		for _, baseOTrunner := range baseOTrunners {
			// Generic setup
			L := 4
			Xi := 4 * base.ComputationalSecurity
			uniqueSessionId := [ot.KappaBytes]byte{}
			_, err := crand.Read(uniqueSessionId[:])
			require.NoError(t, err)

			// BaseOTs
			baseOtSend, baseOtRec, err := baseOTrunner(senderKey, receiverKey, ot.Kappa, 1, curve, uniqueSessionId[:], crand.Reader)
			require.NoError(t, err)
			err = ot_testutils.ValidateOT(ot.Kappa, 1, baseOtSend.MessagePairs, baseOtRec.Choices, baseOtRec.ChosenMessages)
			require.NoError(t, err)

			// Set COTe inputs
			choices, cOTeSenderInput, err := ot_testutils.GenerateCOTinputs(Xi, L, curve)
			require.NoError(t, err)

			// Run COTe
			protocol, err := types.NewProtocol(curve, hashset.NewHashableHashSet(senderKey.(types.IdentityKey), receiverKey.(types.IdentityKey)))
			require.NoError(t, err)

			// Setup COTe
			prng := crand.Reader
			sender, err := softspoken.NewSoftspokenSender(senderKey, protocol, baseOtRec, uniqueSessionId[:], nil, prng, nil, L, Xi)
			require.NoError(t, err)

			receiver, err := softspoken.NewSoftspokenReceiver(receiverKey, protocol, baseOtSend, uniqueSessionId[:], nil, prng, nil, L, Xi)
			require.NoError(t, err)

			router := simulator.NewEchoBroadcastMessageRouter(hashset.NewHashableHashSet(sender.IdentityKey(), receiver.IdentityKey()))
			errChan := make(chan error)

			go func() {
				var errGrp errgroup.Group
				errGrp.Go(func() error {
					var err error
					_, err = receiver.Run(router, sender, choices)
					return err
				})
				errGrp.Go(func() error {
					_, err = sender.Run(router, receiver)
					return err
				})
				errChan <- errGrp.Wait()
			}()

			select {
			case err = <-errChan:
				require.NoError(t, err)
			case <-time.After(10 * time.Second):
				require.Fail(t, "timeout")
			}

			z_A, tau, err := sender.Output.CreateCorrelation(cOTeSenderInput)
			require.NoError(t, err, "could not run softspoken receiver round 2")
			z_B, err := receiver.Output.ApplyCorrelation(tau)
			require.NoError(t, err, "could not run softspoken receiver round 3")

			// Check COTe result
			err = ot_testutils.ValidateCOT(Xi, L, choices, cOTeSenderInput, z_A, z_B)
			require.NoError(t, err)
		}
	}
}
