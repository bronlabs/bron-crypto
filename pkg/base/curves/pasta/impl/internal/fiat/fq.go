//go:generate ../../../../../../../scripts/word_by_word_montgomery.sh "fq" 64 "2^254 + 45560315531506369815346746415080538113"

package fiat

// FqSelect is a multi-limb conditional select.
// This is workaround for bug in fiat-crypto (fqUint1 is not exported).
func FqSelect(out1 *[4]uint64, arg1 uint64, arg2 *[4]uint64, arg3 *[4]uint64) {
	FqSelectznz(out1, fqUint1(arg1), arg2, arg3)
}
