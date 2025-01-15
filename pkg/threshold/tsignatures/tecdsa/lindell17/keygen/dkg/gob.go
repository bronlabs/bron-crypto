package dkg

import (
	"github.com/bronlabs/krypton-primitives/pkg/base/curves/curveutils"
	"github.com/bronlabs/krypton-primitives/pkg/proofs/sigma/compiler_utils"
)

func init() {
	curveutils.RegisterCurvesForGob()
	compiler_utils.RegisterNICompilersForGob()
}
