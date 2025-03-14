package setup

import (
	"github.com/bronlabs/bron-crypto/pkg/base/curves/curveutils"
)

//nolint:gochecknoinits // We need the init function here.
func init() {
	curveutils.RegisterCurvesForGob()
}
