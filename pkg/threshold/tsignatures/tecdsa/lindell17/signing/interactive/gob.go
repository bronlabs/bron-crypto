package interactive_signing

import (
	"github.com/bronlabs/bron-crypto/pkg/base/curves/curveutils"
	"github.com/bronlabs/bron-crypto/pkg/proofs/sigma/compiler_utils"
)

//nolint:gochecknoinits // We need the init function here.
func init() {
	curveutils.RegisterCurvesForGob()
	compilerUtils.RegisterNICompilersForGob()
}
