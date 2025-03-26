package curves_test

import (
	"github.com/bronlabs/bron-crypto/pkg/base/curves"
	"github.com/bronlabs/bron-crypto/pkg/base/curves/bls12381"
	"github.com/bronlabs/bron-crypto/pkg/base/curves/edwards25519"
	"github.com/bronlabs/bron-crypto/pkg/base/curves/k256"
	"github.com/bronlabs/bron-crypto/pkg/base/curves/p256"
	"github.com/bronlabs/bron-crypto/pkg/base/curves/pasta"
)

var TestCurves = []curves.Curve{
	bls12381.NewG1(),
	bls12381.NewG2(),
	edwards25519.NewCurve(),
	p256.NewCurve(),
	k256.NewCurve(),
	pasta.NewPallasCurve(),
	pasta.NewVestaCurve(),
}
