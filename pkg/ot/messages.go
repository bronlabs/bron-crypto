package ot

import (
	"github.com/copperexchange/krypton-primitives/pkg/base/bitstring"
	"github.com/copperexchange/krypton-primitives/pkg/base/curves"
)

type (
	PackedBits []byte // Choice (x) are the "packed" choice bits.

	MessageElement = [KappaBytes]byte // [κ]bits, κ-bit chunks of the ROT/OT message.
	Message        = []MessageElement // [L][κ]bits, the messages in ROT/OT.

	CorrelatedElement = curves.Scalar       // ℤq, each element of the COT message.
	CorrelatedMessage = []CorrelatedElement // [L]ℤq, (a, Z_A, z_B) are the L-scalar messages in COT.
)

func (c PackedBits) Select(i int) byte {
	return bitstring.SelectBit(c, i)
}
