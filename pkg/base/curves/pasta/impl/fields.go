//go:generate go run github.com/bronlabs/bron-crypto/tools/field-codegen --mode word-by-word-montgomery --modulus "2^254 + 45560315531419706090280762371685220353" --type Fp --sqrt sqrt
//go:generate go run github.com/bronlabs/bron-crypto/tools/field-codegen --mode word-by-word-montgomery --modulus "2^254 + 45560315531506369815346746415080538113" --type Fq --sqrt sqrt
package impl

import (
	fieldsImpl "github.com/bronlabs/bron-crypto/pkg/base/algebra/impl/fields"
	"github.com/bronlabs/bron-crypto/pkg/base/ct"
)

func sqrt[FP fieldsImpl.FiniteFieldElementPtr[FP, F], F any](out, x, rootOfUnity *F, e uint64, progenitorExp []uint8) (ok ct.Bool) {
	return fieldsImpl.TonelliShanks[FP, F](out, x, rootOfUnity, e, progenitorExp)
}
