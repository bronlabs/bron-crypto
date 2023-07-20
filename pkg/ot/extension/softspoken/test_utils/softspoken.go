package test_utils

import (
	"testing"

	"github.com/copperexchange/crypto-primitives-go/pkg/core/curves"
	"github.com/copperexchange/crypto-primitives-go/pkg/core/errs"
	"github.com/copperexchange/crypto-primitives-go/pkg/ot/base/vsot"
	"github.com/copperexchange/crypto-primitives-go/pkg/ot/base/vsot/test_utils"
	"github.com/copperexchange/crypto-primitives-go/pkg/ot/extension/softspoken"
	"github.com/stretchr/testify/require"
)

// RunBaseOT is a utility function encapsulating the entire process of
// running a base OT, so that other tests can use it / bootstrap themselves.
// As a black box, this function uses randomized inputs, and does:
//
//	.             ┌---> R: k^i_{Δ_i}, Δ_i
//	BaseOT_{κ}()--┤
//	.             └---> S: k^i_0, k^i_1
func RunBaseOT(t *testing.T, curve *curves.Curve, uniqueSessionId [vsot.DigestSize]byte) (*vsot.SenderOutput, *vsot.ReceiverOutput, error) {
	t.Helper()
	senderOutput, receiverOutput, err := test_utils.RunVSOT(t, curve, softspoken.Kappa, uniqueSessionId[:])
	if err != nil {
		return nil, nil, errs.WrapFailed(err, "Base OT run failed")
	}
	return senderOutput, receiverOutput, nil
}

// RunSoftspokenCOTe is a utility function encapsulating the entire process of
// running a SoftspokenOT extension and derandomizing its result.
// As a black box, this function does:
//
//		R: x ---┐                           ┌---> R: z_B
//		        ├--- COTe_{κ, L, M}(x, α)---┤
//		S: α ---┘                           └---> S: z_A
//	 s.t. z_A + z_B = x • α
//
// If useForcedReuse: use a single OTe batch for all the inputOpt batches.
// NOTE: it should only be used by setting L=1 in "participants.go"
func RunSoftspokenCOTe(t *testing.T,
	useForcedReuse bool,
	curve *curves.Curve,
	uniqueSessionId [vsot.DigestSize]byte,
	baseOtSenderOutput *vsot.SenderOutput, // baseOT seeds for OTe receiver
	baseOtReceiverOutput *vsot.ReceiverOutput, // baseOT seeds for OTe sender
	choices *softspoken.OTeInputChoices, // receiver's input, the Choice bits x
	inputOpts []softspoken.COTeInputOpt, // sender's input, the InputOpt batches of α
) (cOTeSenderOutputs []softspoken.COTeSenderOutput, cOTeReceiverOutputs []softspoken.COTeReceiverOutput, err error) {
	t.Helper()

	// Setup COTe
	sender, err := softspoken.NewCOtSender(baseOtReceiverOutput, uniqueSessionId, nil, curve, useForcedReuse)
	require.NoError(t, err)
	receiver, err := softspoken.NewCOtReceiver(baseOtSenderOutput, uniqueSessionId, nil, curve, useForcedReuse)
	require.NoError(t, err)

	// Run COTe
	extPackedChoices, oTeReceiverOutput, round1Output, err :=
		receiver.Round1ExtendAndProveConsistency(choices)
	require.NoError(t, err)
	_, cOTeSenderOutputs, round2Output, err :=
		sender.Round2ExtendAndCheckConsistency(round1Output, inputOpts)
	require.NoError(t, err)
	cOTeReceiverOutputs, err = receiver.Round3Derandomize(round2Output, extPackedChoices, oTeReceiverOutput)
	require.NoError(t, err)
	return cOTeSenderOutputs, cOTeReceiverOutputs, nil
}

// RunSoftspokenOTe is a utility function encapsulating the entire process of
// running a random OT extension without derandomization.
// As a black box, this function does:
//
//		R: x ---┐                        ┌---> R: (v_x)
//		        ├--- COTe_{κ, L, M}(x)---┤
//		S:   ---┘                        └---> S: (v_0, v_1)
//	 s.t. v_x = v_1 • (x) + v_0 • (1-x)
func RunSoftspokenOTe(t *testing.T,
	curve *curves.Curve,
	uniqueSessionId [vsot.DigestSize]byte,
	baseOtSenderOutput *vsot.SenderOutput, // baseOT seeds for OTe receiver
	baseOtReceiverOutput *vsot.ReceiverOutput, // baseOT seeds for OTe sender
	choices *softspoken.OTeInputChoices, // receiver's input, the Choice bits x
) (oTeSenderOutputs *softspoken.OTeSenderOutput, oTeReceiverOutputs *softspoken.OTeReceiverOutput, err error) {
	t.Helper()
	// Setup OTe
	useForcedReuse := false
	sender, err := softspoken.NewCOtSender(baseOtReceiverOutput, uniqueSessionId, nil, curve, useForcedReuse)
	require.NoError(t, err)
	receiver, err := softspoken.NewCOtReceiver(baseOtSenderOutput, uniqueSessionId, nil, curve, useForcedReuse)
	require.NoError(t, err)

	// Run OTe
	_, oTeReceiverOutput, round1Output, err :=
		receiver.Round1ExtendAndProveConsistency(choices)
	require.NoError(t, err)
	oTeSenderOutput, _, _, err :=
		sender.Round2ExtendAndCheckConsistency(round1Output, nil)
	require.NoError(t, err)
	require.NoError(t, err)
	return oTeSenderOutput, oTeReceiverOutput, nil
}
