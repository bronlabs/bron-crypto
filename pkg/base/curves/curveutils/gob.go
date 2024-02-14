package curveutils

import (
	"encoding/gob"

	"github.com/copperexchange/krypton-primitives/pkg/base/curves"
	"github.com/copperexchange/krypton-primitives/pkg/base/curves/bls12381"
	"github.com/copperexchange/krypton-primitives/pkg/base/curves/curve25519"
	"github.com/copperexchange/krypton-primitives/pkg/base/curves/edwards25519"
	"github.com/copperexchange/krypton-primitives/pkg/base/curves/k256"
	"github.com/copperexchange/krypton-primitives/pkg/base/curves/p256"
	"github.com/copperexchange/krypton-primitives/pkg/base/curves/pallas"
	"github.com/copperexchange/krypton-primitives/pkg/base/errs"
)

func RegisterForGob(curve curves.Curve) error {
	switch curve.Name() {
	case bls12381.NameG1:
		gob.Register(&bls12381.G1{})
		gob.Register(&bls12381.PointG1{})
		gob.Register(&bls12381.Scalar{})
		gob.Register(&bls12381.BaseFieldElementG1{})
		return nil
	case bls12381.NameG2:
		gob.Register(&bls12381.G2{})
		gob.Register(&bls12381.PointG2{})
		gob.Register(&bls12381.Scalar{})
		gob.Register(&bls12381.BaseFieldElementG2{})
		return nil
	case curve25519.Name:
		gob.Register(&curve25519.Curve{})
		gob.Register(&curve25519.Point{})
		gob.Register(&curve25519.Scalar{})
		gob.Register(&curve25519.BaseFieldElement{})
		return nil
	case edwards25519.Name:
		gob.Register(&edwards25519.Curve{})
		gob.Register(&edwards25519.Point{})
		gob.Register(&edwards25519.Scalar{})
		gob.Register(&edwards25519.BaseFieldElement{})
		return nil
	case k256.Name:
		gob.Register(&k256.Curve{})
		gob.Register(&k256.Point{})
		gob.Register(&k256.Scalar{})
		gob.Register(&k256.BaseFieldElement{})
		return nil
	case p256.Name:
		gob.Register(&p256.Curve{})
		gob.Register(&p256.Point{})
		gob.Register(&p256.Scalar{})
		gob.Register(&p256.BaseFieldElement{})
		return nil
	case pallas.Name:
		gob.Register(&pallas.Curve{})
		gob.Register(&pallas.Point{})
		gob.Register(&pallas.Scalar{})
		gob.Register(&pallas.BaseFieldElement{})
		return nil
	default:
		return errs.NewType("curve %s is not supported for gob", curve.Name())
	}
}
