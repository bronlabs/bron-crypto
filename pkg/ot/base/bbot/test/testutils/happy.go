package bbot_testutils

import (
	"io"
	"testing"

	"github.com/copperexchange/krypton-primitives/pkg/base/testutils/require"
	ot_testutils "github.com/copperexchange/krypton-primitives/pkg/ot/testutils"
)

func HappyPath(t *testing.T, scenario *ot_testutils.OtScenario, pp *ot_testutils.OtParams, rng io.Reader) {
	// Protocol Setup (includes running functionalities for inputs)
	sender, receiver, err := CreateParticipants(scenario, rng, pp, pp)
	require.OnlyInvalidParameterError(t, pp.CanBeInvalid(), err, "Invalid OT parameters")

	// Protocol Run
	senderRotOutput, receiverRotOutput, senderOtInput, receiverOtOutput, a, z_A, z_B, err := RunAllOTs(sender, receiver, nil)
	require.OnlyInvalidParameterError(t, pp.CanBeInvalid(), err, "Invalid OT parameters")

	// Protocol Validation
	err = ot_testutils.ValidateOT(sender.Protocol.Xi, sender.Protocol.L,
		senderRotOutput.MessagePairs, receiverRotOutput.Choices, receiverRotOutput.ChosenMessages)
	require.NoError(t, err, "could not validate ROT")

	err = ot_testutils.ValidateOT(sender.Protocol.Xi, sender.Protocol.L,
		senderOtInput, receiverRotOutput.Choices, receiverOtOutput)
	require.NoError(t, err, "could not validate OT")

	err = ot_testutils.ValidateCOT(sender.Protocol.Xi, sender.Protocol.L, receiverRotOutput.Choices, a, z_B, z_A)
	require.NoError(t, err, "could not validate COT")
}
