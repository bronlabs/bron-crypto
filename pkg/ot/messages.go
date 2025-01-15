package ot

import (
	"github.com/bronlabs/krypton-primitives/pkg/base/bitstring"
	"github.com/bronlabs/krypton-primitives/pkg/base/curves"
)

type (
	PackedBits = bitstring.PackedBits // Choice (x) are the "packed" choice bits.

	MessageElement = [KappaBytes]byte // [κ]bits, κ-bit chunks of the ROT/OT message.
	Message        = []MessageElement // [L][κ]bits, the messages in ROT/OT.

	CorrelatedElement = curves.Scalar       // ℤq, each element of the COT message.
	CorrelatedMessage = []CorrelatedElement // [L]ℤq, (a, Z_A, z_B) are the L-scalar messages in COT.
)
