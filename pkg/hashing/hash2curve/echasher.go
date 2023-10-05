package hash2curve

import (
	"crypto/sha256"
	"crypto/sha512"
	"hash"

	"golang.org/x/crypto/blake2b"
	"golang.org/x/crypto/sha3"

	"github.com/copperexchange/krypton-primitives/pkg/base/types"
)

// EllipticPointHashType is to indicate which expand operation is used
// for hash to curve operations.
type EllipticPointHashType uint

// EllipticPointHashName is to indicate the hash function is used
// for hash to curve operations.
type EllipticPointHashName uint

const (
	// XMD - use ExpandMsgXmd.
	XMD EllipticPointHashType = iota
	// XOF - use ExpandMsgXof.
	XOF
)

const (
	SHA256 EllipticPointHashName = iota
	SHA512
	SHA3_256
	SHA3_384
	SHA3_512
	BLAKE2B
	SHAKE128
	SHAKE256
)

// EllipticPointHasher is the type of hashing methods for
// hashing byte sequences to curve point.
type EllipticPointHasher struct {
	name     EllipticPointHashName
	hashType EllipticPointHashType
	xmd      hash.Hash
	xof      sha3.ShakeHash

	_ types.Incomparable
}

// Name returns the hash name for this hasher.
func (e *EllipticPointHasher) Name() string {
	return e.name.String()
}

// Type returns the hash type for this hasher.
func (e *EllipticPointHasher) Type() EllipticPointHashType {
	return e.hashType
}

// Xmd returns the hash method for ExpandMsgXmd.
func (e *EllipticPointHasher) Xmd() hash.Hash {
	return e.xmd
}

// Xof returns the hash method for ExpandMsgXof.
func (e *EllipticPointHasher) Xof() sha3.ShakeHash {
	return e.xof
}

// EllipticPointHasherSha256 creates a point hasher that uses Sha256.
func EllipticPointHasherSha256() *EllipticPointHasher {
	return &EllipticPointHasher{
		name:     SHA256,
		hashType: XMD,
		xmd:      sha256.New(),
	}
}

// EllipticPointHasherSha512 creates a point hasher that uses Sha512.
func EllipticPointHasherSha512() *EllipticPointHasher {
	return &EllipticPointHasher{
		name:     SHA512,
		hashType: XMD,
		xmd:      sha512.New(),
	}
}

// EllipticPointHasherSha3256 creates a point hasher that uses Sha3256.
func EllipticPointHasherSha3256() *EllipticPointHasher {
	return &EllipticPointHasher{
		name:     SHA3_256,
		hashType: XMD,
		xmd:      sha3.New256(),
	}
}

// EllipticPointHasherSha3384 creates a point hasher that uses Sha3384.
func EllipticPointHasherSha3384() *EllipticPointHasher {
	return &EllipticPointHasher{
		name:     SHA3_384,
		hashType: XMD,
		xmd:      sha3.New384(),
	}
}

// EllipticPointHasherSha3512 creates a point hasher that uses Sha3512.
func EllipticPointHasherSha3512() *EllipticPointHasher {
	return &EllipticPointHasher{
		name:     SHA3_512,
		hashType: XMD,
		xmd:      sha3.New512(),
	}
}

// EllipticPointHasherBlake2b creates a point hasher that uses Blake2b.
func EllipticPointHasherBlake2b() *EllipticPointHasher {
	h, _ := blake2b.New(64, []byte{})
	return &EllipticPointHasher{
		name:     BLAKE2B,
		hashType: XMD,
		xmd:      h,
	}
}

// EllipticPointHasherShake128 creates a point hasher that uses Shake128.
func EllipticPointHasherShake128() *EllipticPointHasher {
	return &EllipticPointHasher{
		name:     SHAKE128,
		hashType: XOF,
		xof:      sha3.NewShake128(),
	}
}

// EllipticPointHasherShake256 creates a point hasher that uses Shake256.
func EllipticPointHasherShake256() *EllipticPointHasher {
	return &EllipticPointHasher{
		name:     SHAKE128,
		hashType: XOF,
		xof:      sha3.NewShake256(),
	}
}

func (t EllipticPointHashType) String() string {
	switch t {
	case XMD:
		return "XMD"
	case XOF:
		return "XOF"
	}
	return "unknown"
}

func (n EllipticPointHashName) String() string {
	switch n {
	case SHA256:
		return "SHA-256"
	case SHA512:
		return "SHA-512"
	case SHA3_256:
		return "SHA3-256"
	case SHA3_384:
		return "SHA3-384"
	case SHA3_512:
		return "SHA3-512"
	case BLAKE2B:
		return "BLAKE2b"
	case SHAKE128:
		return "SHAKE-128"
	case SHAKE256:
		return "SHAKE-256"
	}
	return "unknown"
}
