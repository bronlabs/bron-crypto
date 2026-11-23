package iknp03

import (
	"encoding/binary"

	"github.com/bronlabs/bron-crypto/pkg/ot"
)

// transposeColumns takes the κ columns of l bits each, packed least-significant
// bit first, and returns the l rows of κ bits of the transposed matrix as
// messages: bit i of row j is bit j of column i. There must be exactly κ =
// MessageBitLen[M] columns, l must be a multiple of blockBits and every column
// must have the same length; callers validate this. The work is done in
// 64×64-bit blocks with transpose64.
func transposeColumns[M ot.Message](columns [][]byte) []M {
	k := len(columns)
	if k == 0 {
		return nil
	}
	l := len(columns[0]) * 8
	rows := make([]M, l)

	var block [blockBits]uint64
	for bi := range k / blockBits {
		for bj := range l / blockBits {
			for r := range blockBits {
				block[r] = binary.LittleEndian.Uint64(columns[bi*blockBits+r][bj*8:])
			}
			transpose64(block[:])
			for c := range blockBits {
				binary.LittleEndian.PutUint64(ot.MessageAsSlice(&rows[bj*blockBits+c])[bi*8:], block[c])
			}
		}
	}
	return rows
}

// transpose64 transposes a 64×64 bit matrix in place, block[r] holding row r
// with column c at bit c, by swapping off-diagonal sub-blocks at every scale
// (see https://eprint.iacr.org/2017/793.pdf, Fig. 2).
func transpose64(block []uint64) {
	masks := [6]uint64{
		0x5555555555555555,
		0x3333333333333333,
		0x0f0f0f0f0f0f0f0f,
		0x00ff00ff00ff00ff,
		0x0000ffff0000ffff,
		0x00000000ffffffff,
	}

	for stage := range 6 {
		step := 1 << stage
		mask := masks[stage]
		shift := uint(step)
		for base := 0; base < 64; base += 2 * step {
			for i := range step {
				a := block[base+i]
				b := block[base+i+step]
				block[base+i] = (a & mask) | ((b & mask) << shift)
				block[base+i+step] = ((a >> shift) & mask) | (b & ^mask)
			}
		}
	}
}
