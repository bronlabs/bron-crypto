package curves_test

import (
	"github.com/copperexchange/krypton-primitives/pkg/base/curves"
	"github.com/copperexchange/krypton-primitives/pkg/base/curves/bls12381"
	"github.com/copperexchange/krypton-primitives/pkg/base/curves/edwards25519"
	"github.com/copperexchange/krypton-primitives/pkg/base/curves/k256"
	"github.com/copperexchange/krypton-primitives/pkg/base/curves/p256"
	"github.com/copperexchange/krypton-primitives/pkg/base/curves/pallas"
)

var TestCurves = []curves.Curve{
	bls12381.NewG1(),
	edwards25519.NewCurve(),
	p256.NewCurve(),
	k256.NewCurve(),
	pallas.NewCurve(),
}
