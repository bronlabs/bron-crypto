package test_utils

import (
	"crypto/rand"
	"testing"

	"github.com/stretchr/testify/require"

	"github.com/copperexchange/knox-primitives/pkg/core/bitstring"
	"github.com/copperexchange/knox-primitives/pkg/core/curves"
	"github.com/copperexchange/knox-primitives/pkg/core/errs"
	"github.com/copperexchange/knox-primitives/pkg/ot/base/vsot"
	"github.com/copperexchange/knox-primitives/pkg/ot/base/vsot/test_utils"
	"github.com/copperexchange/knox-primitives/pkg/ot/extension/softspoken"
)

// ------------------------------ BASE OTs ---------------------------------- //
// RunSoftspokenBaseOT is a utility function encapsulating the entire process of
// running a base OT, so that other tests can use it / bootstrap themselves.
// As a black box, this function uses randomised inputs, and does:
//
//	.             ┌---> R: k^i_{Δ_i}, Δ_i
//	BaseOT_{κ}()--┤
//	.             └---> S: k^i_0, k^i_1
func RunSoftspokenBaseOT(t *testing.T, curve curves.Curve, uniqueSessionId [vsot.DigestSize]byte) (*vsot.SenderOutput, *vsot.ReceiverOutput, error) {
	t.Helper()
	senderOutput, receiverOutput, err := test_utils.RunVSOT(t, curve, softspoken.Zeta, uniqueSessionId[:])
	if err != nil {
		return nil, nil, errs.WrapFailed(err, "Base OT run failed")
	}
	return senderOutput, receiverOutput, nil
}

// CheckSoftspokenBaseOTOutputs checks the results of a base OT run, testing
// that k^i_{Δ_i} = k^i_1 • Δ_i + k^i_0 • (1-Δ_i).
func CheckSoftspokenBaseOTOutputs(t *testing.T, baseOtSenderOutput *vsot.SenderOutput, baseOtReceiverOutput *vsot.ReceiverOutput) {
	t.Helper()
	// Check length matching
	Zeta := len(baseOtSenderOutput.OneTimePadEncryptionKeys)
	require.Equal(t, Zeta, len(baseOtReceiverOutput.RandomChoiceBits))
	require.Equal(t, Zeta, softspoken.Zeta)
	// Check baseOT results
	for i := 0; i < Zeta; i++ {
		require.Equal(t, baseOtReceiverOutput.OneTimePadDecryptionKey[i],
			baseOtSenderOutput.OneTimePadEncryptionKeys[i][baseOtReceiverOutput.RandomChoiceBits[i]])
	}
}

// ----------------------------- OT extension ------------------------------- //
// RunSoftspokenOTe is a utility function encapsulating the entire process of
// running a random OT extension without derandomization.
// As a black box, this function does:
//
//		R: x ---┐                        ┌---> R: (v_x)
//		        ├--- COTe_{κ, L, M}(x)---┤
//		S:   ---┘                        └---> S: (v_0, v_1)
//	 s.t. v_x = v_1 • (x) + v_0 • (1-x)
func RunSoftspokenOTe(t *testing.T,
	curve curves.Curve,
	uniqueSessionId []byte,
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
	_, oTeReceiverOutput, round1Output, err := receiver.Round1ExtendAndProveConsistency(choices)
	require.NoError(t, err)
	oTeSenderOutput, _, _, err := sender.Round2ExtendAndCheckConsistency(round1Output, nil)
	require.NoError(t, err)
	require.NoError(t, err)
	return oTeSenderOutput, oTeReceiverOutput, nil
}

// CheckSoftspokenOTeOutputs checks the results of a random OT extension run,
// testing that v_x = v_1 • x + v_0 • (1-x).
func CheckSoftspokenOTeOutputs(t *testing.T,
	oTeSenderOutput *softspoken.OTeSenderOutput, // (v_0, v_1)
	oTeReceiverOutput *softspoken.OTeReceiverOutput, // (v_x)
	choices *softspoken.OTeInputChoices, // receiver's input, the Choice bits x
) {
	t.Helper()
	Zeta := len(oTeSenderOutput[0])
	// Check length matching
	require.Equal(t, len(oTeReceiverOutput), len(oTeSenderOutput[1]))
	// Check OTe results
	for i := len(oTeReceiverOutput); i < Zeta; i++ {
		// Check that v_x = v_1 • x + v_0 • (1-x)
		if bitstring.SelectBit(choices[:], i) != 0 {
			require.Equal(t, oTeSenderOutput[1][i], oTeReceiverOutput[i])
		} else {
			require.Equal(t, oTeSenderOutput[0][i], oTeReceiverOutput[i])
		}
	}
}

// ------------------------- Correlated OT extension ------------------------ //
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
// NOTE: it should only be used by setting L=1 in "participants.go".
func RunSoftspokenCOTe(t *testing.T,
	useForcedReuse bool,
	curve curves.Curve,
	uniqueSessionId []byte,
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
	extPackedChoices, oTeReceiverOutput, round1Output, err := receiver.Round1ExtendAndProveConsistency(choices)
	require.NoError(t, err)
	_, cOTeSenderOutputs, round2Output, err := sender.Round2ExtendAndCheckConsistency(round1Output, inputOpts)
	require.NoError(t, err)
	cOTeReceiverOutputs, err = receiver.Round3Derandomize(round2Output, extPackedChoices, oTeReceiverOutput)
	require.NoError(t, err)
	return cOTeSenderOutputs, cOTeReceiverOutputs, nil
}

// GenerateSoftspokenRandomInputs generates random inputs for the SoftspokenOT
// Correlated OT extension.
func GenerateSoftspokenRandomInputs(t *testing.T, inputBatchLen int, curve curves.Curve) (
	choices softspoken.OTeInputChoices, // receiver's input, the Choice bits x
	inputOpts []softspoken.COTeInputOpt, // sender's input, the InputOpt α
) {
	t.Helper()
	choices = softspoken.OTeInputChoices{}
	_, err := rand.Read(choices[:])
	require.NoError(t, err)
	if curve == nil {
		return choices, nil
	}
	inputOpts = make([]softspoken.COTeInputOpt, inputBatchLen)
	for batchIndex := 0; batchIndex < inputBatchLen; batchIndex++ {
		for i := 0; i < softspoken.Zeta; i++ {
			for k := 0; k < softspoken.OTeWidth; k++ {
				inputOpts[batchIndex][i][k] = curve.Scalar().Random(rand.Reader)
			}
		}
	}
	return choices, inputOpts
}

// CheckSoftspokenCOTeOutputs checks the results of a Correlated OT extension run,
// testing that z_A + z_B = x • α.
func CheckSoftspokenCOTeOutputs(t *testing.T,
	cOTeSenderOutputs []softspoken.COTeSenderOutput,
	cOTeReceiverOutputs []softspoken.COTeReceiverOutput,
	inputOpts []softspoken.COTeInputOpt,
	choices softspoken.OTeInputChoices,
) {
	t.Helper()
	inputBatchLen := len(inputOpts)
	// Check length matching
	require.Equal(t, len(cOTeSenderOutputs), len(cOTeReceiverOutputs))
	require.Equal(t, len(cOTeSenderOutputs), len(inputOpts))
	require.Equal(t, len(cOTeReceiverOutputs), len(inputOpts))
	// Check correlation in COTe results
	for batchIndex := 0; batchIndex < inputBatchLen; batchIndex++ {
		for i := 0; i < softspoken.Zeta; i++ {
			x := bitstring.SelectBit(choices[:], i)
			for k := 0; k < softspoken.OTeWidth; k++ {
				// Check each correlation z_A = x • α - z_B
				z_A := cOTeSenderOutputs[batchIndex][i][k]
				z_B := cOTeReceiverOutputs[batchIndex][i][k]
				alpha := inputOpts[batchIndex][i][k]
				if x != 0 {
					require.Zero(t, z_A.Cmp(alpha.Sub(z_B)))
				} else {
					require.Zero(t, z_A.Cmp(z_B.Neg()))
				}
			}
		}
	}
}
