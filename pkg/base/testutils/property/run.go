package property

import (
	"testing"

	"github.com/copperexchange/krypton-primitives/pkg/base/testutils"
	"pgregory.net/rapid"
)

func RunHappyPath[ScenarioT any, P any, ParamT testutils.PublicParams[P]](
	t *testing.T,
	scenario *ScenarioT,
	run testutils.RunHappyFunct[ScenarioT, P, ParamT],
) bool {
	return t.Run("HappyPath", rapid.MakeCheck(func(rapidT *rapid.T) {
		t.Parallel()
		publicParameters := testutils.GetPublicParamsGenerator[P, ParamT]().Draw(rapidT, "Parameters").(ParamT)
		rng := testutils.PickReader(t, publicParameters.Seed())
		run(t, scenario, publicParameters, rng)
	}))
}

func RunUnhappyPath[ScenarioT any, P any, U any, ParamT testutils.PublicParams[P], UnhappyT testutils.UnhappyParams[U]](
	t *testing.T,
	scenario *ScenarioT,
	run testutils.RunUnhappyFunct[ScenarioT, P, U, ParamT, UnhappyT],
) bool {
	return t.Run("UnhappyPath", rapid.MakeCheck(func(rapidT *rapid.T) {
		t.Parallel()
		publicParameters := testutils.GetPublicParamsGenerator[P, ParamT]().Draw(rapidT, "Parameters").(ParamT)
		unhappyParameters := testutils.GetUnhappyParamsGenerator[U, UnhappyT]().Draw(rapidT, "UnhappyParameters").(UnhappyT)
		rng := testutils.PickReader(t, publicParameters.Seed())
		run(t, scenario, publicParameters, unhappyParameters, rng)
	}))
}
