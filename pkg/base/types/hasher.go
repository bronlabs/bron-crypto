package types

// HasherType indicates the type of hash function used by a hasher instance.
type HasherType uint

// ExpandMessageType indicates which expand function is used for hash to curve operations.
type ExpandMessageType uint

const (
	// SHA256 - use Sha256.New
	SHA256 HasherType = iota
	// SHA512 - use Sha512.New
	SHA512
	// SHA3_256 - use Sha3.New256
	SHA3_256
	// SHA3_384 - use Sha3.New384
	SHA3_384
	// SHA3_512 - use Sha3.New512
	SHA3_512
	// BLAKE2B_256 - use blake2b.New256(nil)
	BLAKE2B_256
	// BLAKE2B_512 - use blake2b.New512(nil)
	BLAKE2B_512
	// BLAKE2S - use blake2b.NewXOF(32, nil)
	BLAKE2S
	// SHAKE128 - use Sha3.NewShake128
	SHAKE128
	// SHAKE256 - use Sha3.NewShake256
	SHAKE256
)

const (
	// XMD - use ExpandMsgXmd.
	XMD ExpandMessageType = iota
	// XOF - use ExpandMsgXof.
	XOF
)

// ExpandMessageName returns the name of the expand message function.
func (hashType HasherType) ExpandMessageName() string {
	switch hashType {
	case SHA256, SHA512, SHA3_256, SHA3_384, SHA3_512, BLAKE2B_256, BLAKE2B_512:
		return "XMD"
	case SHAKE128, SHAKE256, BLAKE2S:
		return "XOF"
	default:
		return "unknown"
	}
}

// ExpandMessageType returns the type of the expand message function.
func (hashType HasherType) ExpandMessageType() ExpandMessageType {
	switch hashType {
	case SHA256, SHA512, SHA3_256, SHA3_384, SHA3_512, BLAKE2B_256, BLAKE2B_512:
		return XMD
	case SHAKE128, SHAKE256, BLAKE2S:
		return XOF
	default:
		return XMD
	}
}

// Name returns the name of the hash function.
func (hashType HasherType) Name() string {
	switch hashType {
	case SHA256:
		return "SHA256"
	case SHA512:
		return "SHA512"
	case SHA3_256:
		return "SHA3_256"
	case SHA3_384:
		return "SHA3_384"
	case SHA3_512:
		return "SHA3_512"
	case BLAKE2B_256:
		return "BLAKE2B_256"
	case BLAKE2B_512:
		return "BLAKE2B_512"
	case BLAKE2S:
		return "BLAKE2S"
	case SHAKE128:
		return "SHAKE128"
	case SHAKE256:
		return "SHAKE256"
	default:
		return "unknown"
	}
}
func (emt ExpandMessageType) Name() string {
	switch emt {
	case XMD:
		return "XMD"
	case XOF:
		return "XOF"
	default:
		return "unknown"
	}
}
