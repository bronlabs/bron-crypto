//go:generate go run github.com/bronlabs/bron-crypto/tools/field-codegen --mode word-by-word-montgomery --modulus "2^256 - 2^32 - 977" --type Fp --sqrt sqrt
//go:generate go run github.com/bronlabs/bron-crypto/tools/field-codegen --mode word-by-word-montgomery --modulus "2^256 - 432420386565659656852420866394968145599" --type Fq --sqrt sqrt
package impl

import (
	fieldsImpl "github.com/bronlabs/bron-crypto/pkg/base/algebra/impl/fields"
	"github.com/bronlabs/bron-crypto/pkg/base/ct"
)

func sqrt[FP fieldsImpl.FiniteFieldElementPtr[FP, F], F any](out, x, rootOfUnity *F, e uint64, progenitorExp []uint8) (ok ct.Bool) {
	return fieldsImpl.TonelliShanks[FP, F](out, x, rootOfUnity, e, progenitorExp)
}
