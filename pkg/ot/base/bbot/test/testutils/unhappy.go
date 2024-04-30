package bbot_testutils

import (
	"io"
	"testing"

	"github.com/copperexchange/krypton-primitives/pkg/base/testutils/require"
	ot_testutils "github.com/copperexchange/krypton-primitives/pkg/ot/testutils"
)

// Standard unhappy cases:
// - Mismatched protocol parameters (e.g., session ID, curve, Xi, L, hash, ...)
// - Invalid sender / receiver state (e.g., skipping rounds)
// - Reuse of previous run.
//

func UnhappyPathMistmatchParameters(t *testing.T, scenario *ot_testutils.OtScenario,
	pp *ot_testutils.OtParams, senderParams *ot_testutils.OtParams, rng io.Reader) {
	// Protocol Setup
	sender, receiver, err := CreateParticipants(scenario, rng, pp, senderParams)
	require.OnlyInvalidParameterError(t, pp.CanBeInvalid(), err, "Invalid OT parameters")

	// Protocol Run
	_, _, _, _, _, _, _, err = RunAllOTs(sender, receiver, nil)
	require.Error(t, err, "Mismatched parameters should fail")
}

func UnhappyPathReuse(t *testing.T, scenario *ot_testutils.OtScenario,
	pp *ot_testutils.OtParams, reuseParams *ot_testutils.ReuseParams, rng io.Reader) {
	// Protocol Setup
	sender, receiver, err := CreateParticipants(scenario, rng, pp, pp)
	require.OnlyInvalidParameterError(t, pp.CanBeInvalid(), err, "Invalid OT parameters")

	// Protocol Run
	_, _, err = RunROT_Reuse(sender, receiver, nil)
	require.Error(t, err, "Reuse should fail")
}
