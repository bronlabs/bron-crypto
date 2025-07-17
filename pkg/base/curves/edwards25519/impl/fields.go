//go:generate go run github.com/bronlabs/bron-crypto/tools/field-codegen --mode unsaturated-solinas --fiat-only --modulus "2^255 - 19" --type Fp
//go:generate go run github.com/bronlabs/bron-crypto/tools/field-codegen --mode word-by-word-montgomery --modulus "0x1000000000000000000000000000000014def9dea2f79cd65812631a5cf5d3ed" --type Fq --sqrt fqSqrt
package impl

import (
	fieldsImpl "github.com/bronlabs/bron-crypto/pkg/base/algebra/impl/fields"
	"github.com/bronlabs/bron-crypto/pkg/base/ct"
)

func fqSqrt(out, x, rootOfUnity *Fq, e uint64, progenitorExp []uint8) (ok ct.Bool) {
	return fieldsImpl.TonelliShanks(out, x, rootOfUnity, e, progenitorExp)
}
