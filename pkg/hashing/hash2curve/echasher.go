package hash2curve

import (
	"crypto/sha256"
	"crypto/sha512"
	"hash"

	"golang.org/x/crypto/blake2b"
	"golang.org/x/crypto/sha3"

	"github.com/copperexchange/krypton-primitives/pkg/base/types"
)

// EllipticCurveHashType is to indicate which expand operation is used
// for hash to curve operations.
type EllipticCurveHashType uint

const (
	// XMD - use ExpandMsgXmd.
	XMD EllipticCurveHashType = iota
	// XOF - use ExpandMsgXof.
	XOF
)

func (t EllipticCurveHashType) String() string {
	switch t {
	case XMD:
		return "XMD"
	case XOF:
		return "XOF"
	}
	return "unknown"
}

// EllipticCurveHashName is to indicate the hash function is used
// for hash to curve operations.
type EllipticCurveHashName uint

const (
	SHA256 EllipticCurveHashName = iota
	SHA512
	SHA3_256
	SHA3_384
	SHA3_512
	BLAKE2B
	SHAKE128
	SHAKE256
)

func (n EllipticCurveHashName) String() string {
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

// EllipticCurveHasher is the type of hashing methods for
// hashing byte sequences to curve point.
type EllipticCurveHasher struct {
	name     EllipticCurveHashName
	hashType EllipticCurveHashType
	xmd      hash.Hash
	xof      sha3.ShakeHash

	_ types.Incomparable
}

// Name returns the hash name for this hasher.
func (e *EllipticCurveHasher) Name() string {
	return e.name.String()
}

// Type returns the hash type for this hasher.
func (e *EllipticCurveHasher) Type() EllipticCurveHashType {
	return e.hashType
}

// Xmd returns the hash method for ExpandMsgXmd.
func (e *EllipticCurveHasher) Xmd() hash.Hash {
	return e.xmd
}

// Xof returns the hash method for ExpandMsgXof.
func (e *EllipticCurveHasher) Xof() sha3.ShakeHash {
	return e.xof
}

// EllipticCurveHasherSha256 creates a point hasher that uses Sha256.
func EllipticCurveHasherSha256() *EllipticCurveHasher {
	return &EllipticCurveHasher{
		name:     SHA256,
		hashType: XMD,
		xmd:      sha256.New(),
	}
}

// EllipticCurveHasherSha512 creates a point hasher that uses Sha512.
func EllipticCurveHasherSha512() *EllipticCurveHasher {
	return &EllipticCurveHasher{
		name:     SHA512,
		hashType: XMD,
		xmd:      sha512.New(),
	}
}

// EllipticCurveHasherSha3256 creates a point hasher that uses Sha3256.
func EllipticCurveHasherSha3256() *EllipticCurveHasher {
	return &EllipticCurveHasher{
		name:     SHA3_256,
		hashType: XMD,
		xmd:      sha3.New256(),
	}
}

// EllipticCurveHasherSha3384 creates a point hasher that uses Sha3384.
func EllipticCurveHasherSha3384() *EllipticCurveHasher {
	return &EllipticCurveHasher{
		name:     SHA3_384,
		hashType: XMD,
		xmd:      sha3.New384(),
	}
}

// EllipticCurveHasherSha3512 creates a point hasher that uses Sha3512.
func EllipticCurveHasherSha3512() *EllipticCurveHasher {
	return &EllipticCurveHasher{
		name:     SHA3_512,
		hashType: XMD,
		xmd:      sha3.New512(),
	}
}

// EllipticCurveHasherBlake2b creates a point hasher that uses Blake2b.
func EllipticCurveHasherBlake2b() *EllipticCurveHasher {
	h, _ := blake2b.New(64, []byte{})
	return &EllipticCurveHasher{
		name:     BLAKE2B,
		hashType: XMD,
		xmd:      h,
	}
}

// EllipticCurveHasherShake128 creates a point hasher that uses Shake128.
func EllipticCurveHasherShake128() *EllipticCurveHasher {
	return &EllipticCurveHasher{
		name:     SHAKE128,
		hashType: XOF,
		xof:      sha3.NewShake128(),
	}
}

// EllipticCurveHasherShake256 creates a point hasher that uses Shake256.
func EllipticCurveHasherShake256() *EllipticCurveHasher {
	return &EllipticCurveHasher{
		name:     SHAKE128,
		hashType: XOF,
		xof:      sha3.NewShake256(),
	}
}
