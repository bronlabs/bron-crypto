package bls12381

import (
	"github.com/bronlabs/bron-crypto/pkg/base/algebra"
	"github.com/bronlabs/bron-crypto/pkg/base/curves"
)

// FamilyName is the BLS12-381 family name.
const FamilyName = "BLS12381"

// FamilyTrait provides traits for the BLS12-381 family.
type FamilyTrait struct{}

// Name returns the name of the structure.
func (f *FamilyTrait) Name() string {
	return FamilyName
}

// SourceSubGroup returns the source subgroup.
func (f *FamilyTrait) SourceSubGroup() curves.PairingFriendlyCurve[*PointG1, *BaseFieldElementG1, *PointG2, *BaseFieldElementG2, *GtElement, *Scalar] {
	return NewG1()
}

// TwistedSubGroup returns the twisted subgroup.
func (f *FamilyTrait) TwistedSubGroup() curves.PairingFriendlyCurve[*PointG2, *BaseFieldElementG2, *PointG1, *BaseFieldElementG1, *GtElement, *Scalar] {
	return NewG2()
}

// TargetSubGroup returns the target subgroup.
func (f *FamilyTrait) TargetSubGroup() algebra.MultiplicativeGroup[*GtElement] {
	return NewGt()
}

// GetPPE returns a pairing engine by algorithm name.
func (f *FamilyTrait) GetPPE(name curves.PairingAlgorithm) (out curves.PPE[*PointG1, *BaseFieldElementG1, *PointG2, *BaseFieldElementG2, *GtElement, *Scalar], exists bool) {
	switch name {
	case OptimalAteAlgorithm:
		return NewOptimalAtePPE(), true
	default:
		return nil, false
	}
}
