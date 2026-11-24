package iknp03

import "github.com/bronlabs/bron-crypto/pkg/ot"

const (
	// protocolDomainSeparator is appended to the session transcript when a
	// participant is created.
	protocolDomainSeparator = "BRON_CRYPTO-IKNP03-"
	// uLabel labels the receiver's columns u_1..u_κ, which both parties append
	// to the transcript at every extension.
	uLabel = "BRON_CRYPTO-IKNP03-U-"
	// blockBits is the granularity of the bit-matrix transposition: the number
	// of extended OTs l must be a multiple of it, as κ is by construction.
	blockBits = 64
	// MaxExtension keeps the size of one extension below the CBOR array limit
	// for OT outputs. For larger batches, make successive Extend calls on the
	// same participants.
	MaxExtension = 1 << 16
)

// Seed is the message type of the base OTs: the 128-bit input of the PRG.
type Seed = ot.Message128
