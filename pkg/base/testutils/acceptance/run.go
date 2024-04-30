package acceptance

import (
	"fmt"
	"testing"

	"github.com/copperexchange/krypton-primitives/pkg/base/testutils"
)

func RunHappyPath[ScenarioT any, P any, ParamT testutils.PublicParams[P]](
	t *testing.T,
	scenario *ScenarioT,
	publicParameters ParamT,
	run testutils.RunHappyFunct[ScenarioT, P, ParamT],
) bool {
	testName := fmt.Sprintf("HappyPath %s", publicParameters.String())
	return t.Run(testName, func(t *testing.T) {
		t.Parallel()
		rng := testutils.PickReader(t, publicParameters.Seed())
		run(t, scenario, publicParameters, rng)
	})
}

func RunUnhappyPath[ScenarioT any, P any, U any, PublicParamT testutils.PublicParams[P], UnhappyParamT testutils.UnhappyParams[U]](
	t *testing.T,
	scenario *ScenarioT,
	publicParameters PublicParamT,
	unhappyParameters UnhappyParamT,
	run testutils.RunUnhappyFunct[ScenarioT, P, U, PublicParamT, UnhappyParamT],
) bool {
	testName := fmt.Sprintf("UnhappyPath %s %s %s", unhappyParameters.Name(), publicParameters.String(), unhappyParameters.String())
	return t.Run(testName, func(t *testing.T) {
		t.Parallel()
		rng := testutils.PickReader(t, publicParameters.Seed())
		run(t, scenario, publicParameters, unhappyParameters, rng)
	})
}
