package dkg

import (
	"github.com/copperexchange/krypton-primitives/pkg/base/curves/curveutils"
)

func init() {
	curveutils.RegisterCurvesForGob()
}
