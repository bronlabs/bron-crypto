package curveutils

import (
	"github.com/bronlabs/bron-crypto/pkg/base/curves/bls12381"
	"github.com/bronlabs/bron-crypto/pkg/base/curves/curve25519"
	"github.com/bronlabs/bron-crypto/pkg/base/curves/edwards25519"
	"github.com/bronlabs/bron-crypto/pkg/base/curves/k256"
	"github.com/bronlabs/bron-crypto/pkg/base/curves/p256"
	"github.com/bronlabs/bron-crypto/pkg/base/curves/pasta"
)

func RegisterCurvesForGob() {
	bls12381.RegisterForGob()
	bls12381.RegisterForGob()
	curve25519.RegisterForGob()
	edwards25519.RegisterForGob()
	k256.RegisterForGob()
	p256.RegisterForGob()
	pasta.RegisterForGob()
}
