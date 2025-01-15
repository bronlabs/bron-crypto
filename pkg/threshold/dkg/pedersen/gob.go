package pedersen

import (
	"github.com/bronlabs/krypton-primitives/pkg/base/curves/curveutils"
	"github.com/bronlabs/krypton-primitives/pkg/proofs/sigma/compiler_utils"
)

//nolint:gochecknoinits // We need the init function here.
func init() {
	curveutils.RegisterCurvesForGob()
	compiler_utils.RegisterNICompilersForGob()
}
