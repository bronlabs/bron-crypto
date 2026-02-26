package constructions_test

import (
	"github.com/bronlabs/bron-crypto/pkg/base/algebra"
	"github.com/bronlabs/bron-crypto/pkg/base/algebra/constructions"
)

func _[FE algebra.FieldElement[FE]]() {
	var _ algebra.MultiplicativeGroup[*constructions.FieldUnitSubGroupElement[FE]] = &constructions.FieldUnitSubGroup[FE]{}
	var _ algebra.MultiplicativeGroupElement[*constructions.FieldUnitSubGroupElement[FE]] = &constructions.FieldUnitSubGroupElement[FE]{}
}
