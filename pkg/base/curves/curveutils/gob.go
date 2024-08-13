package curveutils

import (
	"github.com/copperexchange/krypton-primitives/pkg/base/curves/bls12381"
	"github.com/copperexchange/krypton-primitives/pkg/base/curves/curve25519"
	"github.com/copperexchange/krypton-primitives/pkg/base/curves/edwards25519"
	"github.com/copperexchange/krypton-primitives/pkg/base/curves/k256"
	"github.com/copperexchange/krypton-primitives/pkg/base/curves/p256"
	"github.com/copperexchange/krypton-primitives/pkg/base/curves/pallas"
)

func RegisterCurvesForGob() {
	bls12381.RegisterForGob()
	bls12381.RegisterForGob()
	curve25519.RegisterForGob()
	edwards25519.RegisterForGob()
	k256.RegisterForGob()
	p256.RegisterForGob()
	pallas.RegisterForGob()
}
