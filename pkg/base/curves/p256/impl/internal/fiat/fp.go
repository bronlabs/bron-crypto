//go:generate ../../../../../../../scripts/word_by_word_montgomery.sh "fp" 64 "2^256 - 2^224 + 2^192 + 2^96 - 1"

package fiat

// FpSelect is a multi-limb conditional select.
// This is workaround for bug in fiat-crypto (fpUint1 is not exported).
func FpSelect(out1 *[4]uint64, arg1 uint64, arg2 *[4]uint64, arg3 *[4]uint64) {
	FpSelectznz(out1, fpUint1(arg1), arg2, arg3)
}
