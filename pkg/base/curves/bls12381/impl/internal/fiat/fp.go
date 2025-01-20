//go:generate ../../../../../../../scripts/word_by_word_montgomery.sh "fp" 64 "0x1a0111ea397fe69a4b1ba7b6434bacd764774b84f38512bf6730d2a0f6b0f6241eabfffeb153ffffb9feffffffffaaab"

package fiat

// FpSelect is a multi-limb conditional select.
// This is workaround for bug in fiat-crypto (fpUint1 is not exported).
func FpSelect(out1 *[6]uint64, arg1 uint64, arg2 *[6]uint64, arg3 *[6]uint64) {
	FpSelectznz(out1, fpUint1(arg1), arg2, arg3)
}
