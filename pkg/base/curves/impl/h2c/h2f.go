package h2c

import (
	"slices"

	fieldsImpl "github.com/bronlabs/bron-crypto/pkg/base/curves/impl/fields"
)

type HasherParams interface {
	L() uint64
	MessageExpander() MessageExpander
}

func HashToField[FP fieldsImpl.FiniteFieldPtrConstraint[FP, F], F any](out []F, params HasherParams, dstStr string, msg []byte) {
	m := fieldsImpl.Degree[FP]()
	l := params.L()
	expander := params.MessageExpander()
	dst := []byte(dstStr)
	count := len(out)

	//  1. len_in_bytes = count * m * L
	lenInBytes := uint64(count) * m * l
	//  2. uniform_bytes = expand_message(msg, DST, len_in_bytes)
	uniformBytes := expander.ExpandMessage(dst, msg, uint(lenInBytes))
	//  3. for i in (0, ..., count - 1):
	for i := uint64(0); i < uint64(len(out)); i++ {
		var e [][]byte
		//  4.   for j in (0, ..., m - 1):
		for j := uint64(0); j < m; j++ {
			//  5.     elm_offset = L * (j + i * m)
			elmOffset := l * (j + i*m)
			//  6.     tv = substr(uniform_bytes, elm_offset, L)
			tv := uniformBytes[elmOffset : elmOffset+l]
			//  7.     e_j = OS2IP(tv) mod p
			slices.Reverse(tv)
			e = append(e, tv)
		}
		//  8.   u_i = (e_0, ..., e_(m - 1))
		FP(&out[i]).SetUniformBytes(e...)
	}
}
