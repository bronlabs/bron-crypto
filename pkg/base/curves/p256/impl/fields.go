//go:generate go run github.com/bronlabs/krypton-primitives/tools/field-codegen --mode word-by-word-montgomery --modulus "2^256 - 2^224 + 2^192 + 2^96 - 1" --type Fp --sqrt sqrt
//go:generate go run github.com/bronlabs/krypton-primitives/tools/field-codegen --mode word-by-word-montgomery --modulus "2^256 - 2^224 + 2^192 - 89188191075325690597107910205041859247" --type Fq --sqrt sqrt
package impl

import (
	fieldsImpl "github.com/bronlabs/krypton-primitives/pkg/base/curves/impl/fields"
)

func sqrt[FP fieldsImpl.FiniteFieldPtrConstraint[FP, F], F any](out, x, rootOfUnity *F, e uint64, progenitorExp []uint8) (ok uint64) {
	return fieldsImpl.TonelliShanks[FP, F](out, x, rootOfUnity, e, progenitorExp)
}
