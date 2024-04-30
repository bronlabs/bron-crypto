package bbot_test

import (
	"testing"

	"github.com/copperexchange/krypton-primitives/pkg/base/testutils/property"
	"github.com/copperexchange/krypton-primitives/pkg/base/testutils/require"
	bbot_testutils "github.com/copperexchange/krypton-primitives/pkg/ot/base/bbot/test/testutils"
	ot_testutils "github.com/copperexchange/krypton-primitives/pkg/ot/testutils"
)

func TestPropertyBBOT_AllOTs(t *testing.T) {
	t.Parallel()

	// testutils.SkipIfShort(t)

	// Create MPC scenario
	scenario, err := ot_testutils.GenerateScenario()
	require.NoError(t, err)

	// Run the happy/unhappy paths
	property.RunHappyPath(t, scenario, bbot_testutils.HappyPath)

	property.RunUnhappyPath(t, scenario, bbot_testutils.UnhappyPathMistmatchParameters)

	property.RunUnhappyPath(t, scenario, bbot_testutils.UnhappyPathReuse)
}
