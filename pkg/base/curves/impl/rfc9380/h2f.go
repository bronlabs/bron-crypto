package rfc9380

import (
	"slices"

	fieldsImpl "github.com/bronlabs/bron-crypto/pkg/base/algebra/impl/fields"
)

// HasherParams exposes parameters for hash-to-field expansion.
type HasherParams interface {
	// L returns the hash-to-field length in bytes.
	L() uint64
	// MessageExpander returns the RFC 9380 message expander.
	MessageExpander() MessageExpander
}

// HashToField expands msg into field elements as specified by RFC 9380.
func HashToField[FP fieldsImpl.FiniteFieldElementPtr[FP, F], F any](out []F, params HasherParams, dstStr string, msg []byte) {
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
	for i := range uint64(len(out)) {
		e := make([][]byte, m)
		//  4.   for j in (0, ..., m - 1):
		for j := range m {
			//  5.     elm_offset = L * (j + i * m)
			elmOffset := l * (j + i*m)
			//  6.     tv = substr(uniform_bytes, elm_offset, L)
			tv := uniformBytes[elmOffset : elmOffset+l]
			//  7.     e_j = OS2IP(tv) mod p
			slices.Reverse(tv)
			e[j] = tv
		}
		//  8.   u_i = (e_0, ..., e_(m - 1))
		FP(&out[i]).SetUniformBytes(e...)
	}
}
