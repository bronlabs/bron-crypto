package bbot_test

import (
	"testing"

	"github.com/copperexchange/krypton-primitives/pkg/base/curves"
	"github.com/copperexchange/krypton-primitives/pkg/base/curves/k256"
	"github.com/copperexchange/krypton-primitives/pkg/base/curves/p256"
	"github.com/copperexchange/krypton-primitives/pkg/base/testutils"

	"github.com/copperexchange/krypton-primitives/pkg/base/testutils/acceptance"
	"github.com/copperexchange/krypton-primitives/pkg/base/testutils/require"
	bbot_testutils "github.com/copperexchange/krypton-primitives/pkg/ot/base/bbot/test/testutils"
	ot_testutils "github.com/copperexchange/krypton-primitives/pkg/ot/testutils"
)

var acceptanceParams = struct {
	Xis    []int
	Ls     []int
	Curves []curves.Curve
}{
	Xis:    []int{128, 256},
	Ls:     []int{4},
	Curves: []curves.Curve{k256.NewCurve(), p256.NewCurve()},
}

func FuzzBBOT(f *testing.F) {
	// Create MPC scenario
	scenario, err := ot_testutils.GenerateScenario()
	require.NoError(f, err)

	// Record all combinations of the acceptance parameters
	for _, Curve := range acceptanceParams.Curves {
		for _, Xi := range acceptanceParams.Xis {
			for _, L := range acceptanceParams.Ls {
				f.Add(Xi, L, testutils.GetCurveIndex(Curve), []byte("BBOTseed"), 1)
			}
		}
	}

	f.Fuzz(func(t *testing.T, Xi int, L int, CurveIndex int, Seed []byte, reuseRound int) {
		// Set parameters and run the happy path
		publicParameters := &ot_testutils.OtParams{
			SessionId:    testutils.SampleSessionId(testutils.PickReader(t, []byte(Seed))),
			Xi:           Xi,
			L:            L,
			Curve:        testutils.PickCurve(CurveIndex),
			MayBeInvalid: true,
		}
		acceptance.RunHappyPath(t, scenario, publicParameters, bbot_testutils.HappyPath)

		// Set Parameters and run the unhappy paths
		mistmatchedParameters := &ot_testutils.OtParams{
			SessionId:    testutils.SampleSessionId(testutils.PickReader(t, []byte(Seed))),
			Xi:           Xi,
			L:            L,
			Curve:        testutils.PickCurve(CurveIndex),
			MayBeInvalid: true,
		}
		acceptance.RunUnhappyPath(t, scenario, publicParameters, mistmatchedParameters,
			bbot_testutils.UnhappyPathMistmatchParameters)

		reuseParameters := &ot_testutils.ReuseParams{
			ReuseRound: uint(reuseRound),
		}
		acceptance.RunUnhappyPath(t, scenario, publicParameters, reuseParameters,
			bbot_testutils.UnhappyPathReuse)
	})
}
