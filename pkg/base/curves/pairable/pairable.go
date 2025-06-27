package pairable

import (
	"sync"

	"github.com/bronlabs/bron-crypto/pkg/base/curves"
	"github.com/bronlabs/bron-crypto/pkg/base/curves/pairable/bls12381"
)

var (
	familyInstanceBLS12381 *BLS12381
	familyInitOnceBLS12381 sync.Once
)

func NewBLS12381() curves.PairingFriendlyFamily[*bls12381.PointG1, *bls12381.BaseFieldElementG1, *bls12381.PointG2, *bls12381.BaseFieldElementG2, *bls12381.GtElement, *bls12381.Scalar] {
	familyInitOnceBLS12381.Do(func() { familyInstanceBLS12381 = &BLS12381{} })
	return familyInstanceBLS12381
}

type BLS12381 struct{ bls12381.FamilyTrait }
