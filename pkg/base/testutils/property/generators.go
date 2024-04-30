package property

import (
	"github.com/copperexchange/krypton-primitives/pkg/base/curves"
	"github.com/copperexchange/krypton-primitives/pkg/base/testutils"
	"pgregory.net/rapid"
)

var CurveGen = rapid.Custom(func(t *rapid.T) curves.Curve {
	curveIndex := rapid.IntRange(0, 5).Draw(t, "CurveIndex")
	return testutils.PickCurve(curveIndex)
})

var NonPairingCurveGen = rapid.Custom(func(t *rapid.T) curves.Curve {
	curveIndex := rapid.IntRange(2, 5).Draw(t, "CurveIndex")
	return testutils.PickCurve(curveIndex)
})

var SessionIdGen = rapid.Custom(func(t *rapid.T) []byte {
	return rapid.SliceOfN(rapid.Byte(), 1, 32).Draw(t, "SessionId")
})
