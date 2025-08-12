package bls12381

import (
	"github.com/bronlabs/bron-crypto/pkg/base/algebra"
	"github.com/bronlabs/bron-crypto/pkg/base/curves"
)

const FamilyName = "BLS12381"

type FamilyTrait struct{}

func (f *FamilyTrait) Name() string {
	return FamilyName
}
func (f *FamilyTrait) SourceSubGroup() curves.PairingFriendlyCurve[*PointG1, *BaseFieldElementG1, *PointG2, *BaseFieldElementG2, *GtElement, *Scalar] {
	return NewG1()
}
func (f *FamilyTrait) TwistedSubGroup() curves.PairingFriendlyCurve[*PointG2, *BaseFieldElementG2, *PointG1, *BaseFieldElementG1, *GtElement, *Scalar] {
	return NewG2()
}
func (f *FamilyTrait) TargetSubGroup() algebra.MultiplicativeGroup[*GtElement] {
	return NewGt()
}

func (f *FamilyTrait) GetPPE(name curves.PairingAlgorithm) (out curves.PPE[*PointG1, *BaseFieldElementG1, *PointG2, *BaseFieldElementG2, *GtElement, *Scalar], exists bool) {
	switch name {
	case OptimalAteAlgorithm:
		return NewOptimalAtePPE(), true
	default:
		return nil, false
	}
}
