package signing

import (
	"github.com/bronlabs/krypton-primitives/pkg/base/curves/curveutils"
	compilerUtils "github.com/bronlabs/krypton-primitives/pkg/proofs/sigma/compiler_utils"
)

//nolint:gochecknoinits // We need the init function here.
func init() {
	curveutils.RegisterCurvesForGob()
	compilerUtils.RegisterNICompilersForGob()
}
