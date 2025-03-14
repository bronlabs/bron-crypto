package dkg

import (
	"github.com/bronlabs/bron-crypto/pkg/base/curves/curveutils"
	"github.com/bronlabs/bron-crypto/pkg/proofs/sigma/compiler_utils"
)

func init() {
	curveutils.RegisterCurvesForGob()
	compilerUtils.RegisterNICompilersForGob()
}
