package jf

import (
	"github.com/copperexchange/krypton-primitives/pkg/base/curves/curveutils"
	"github.com/copperexchange/krypton-primitives/pkg/proofs/sigma/compiler_utils"
)

func init() {
	curveutils.RegisterCurvesForGob()
	compiler_utils.RegisterNICompilersForGob()
}
