package hash2curve

import (
	"crypto/sha256"
	"crypto/sha512"
	"crypto/subtle"
	"hash"

	"golang.org/x/crypto/blake2b"
	"golang.org/x/crypto/sha3"

	"github.com/copperexchange/krypton-primitives/pkg/base/types"
)

// EllipticCurveHasher is the type of hashing methods for hashing byte sequences to curve point.
type EllipticCurveHasher struct {
	hasherType        types.HasherType
	expandMessageType types.ExpandMessageType
	xmd               hash.Hash
	xof               sha3.ShakeHash

	_ types.Incomparable
}

// Name returns the hash name for this hasher.
func (e *EllipticCurveHasher) Name() string {
	return e.hasherType.Name()
}

// Type returns the hash type for this hasher.
func (e *EllipticCurveHasher) Type() types.ExpandMessageType {
	return e.expandMessageType
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
		hasherType:        types.SHA256,
		expandMessageType: types.XMD,
		xmd:               sha256.New(),
	}
}

// EllipticCurveHasherSha512 creates a point hasher that uses Sha512.
func EllipticCurveHasherSha512() *EllipticCurveHasher {
	return &EllipticCurveHasher{
		hasherType:        types.SHA512,
		expandMessageType: types.XMD,
		xmd:               sha512.New(),
	}
}

// EllipticCurveHasherSha3256 creates a point hasher that uses Sha3256.
func EllipticCurveHasherSha3256() *EllipticCurveHasher {
	return &EllipticCurveHasher{
		hasherType:        types.SHA3_256,
		expandMessageType: types.XMD,
		xmd:               sha3.New256(),
	}
}

// EllipticCurveHasherSha3384 creates a point hasher that uses Sha3384.
func EllipticCurveHasherSha3384() *EllipticCurveHasher {
	return &EllipticCurveHasher{
		hasherType:        types.SHA3_384,
		expandMessageType: types.XMD,
		xmd:               sha3.New384(),
	}
}

// EllipticCurveHasherSha3512 creates a point hasher that uses Sha3512.
func EllipticCurveHasherSha3512() *EllipticCurveHasher {
	return &EllipticCurveHasher{
		hasherType:        types.SHA3_512,
		expandMessageType: types.XMD,
		xmd:               sha3.New512(),
	}
}

// EllipticCurveHasherBlake2b creates a point hasher that uses Blake2b.
func EllipticCurveHasherBlake2b() *EllipticCurveHasher {
	h, _ := blake2b.New(64, []byte{})
	return &EllipticCurveHasher{
		hasherType:        types.BLAKE2B_512,
		expandMessageType: types.XMD,
		xmd:               h,
	}
}

// EllipticCurveHasherShake128 creates a point hasher that uses Shake128.
func EllipticCurveHasherShake128() *EllipticCurveHasher {
	return &EllipticCurveHasher{
		hasherType:        types.SHAKE128,
		expandMessageType: types.XOF,
		xof:               sha3.NewShake128(),
	}
}

// EllipticCurveHasherShake256 creates a point hasher that uses Shake256.
func EllipticCurveHasherShake256() *EllipticCurveHasher {
	return &EllipticCurveHasher{
		hasherType:        types.SHAKE128,
		expandMessageType: types.XOF,
		xof:               sha3.NewShake256(),
	}
}

// ExpandMsgXmd expands the msg with the domain to output a byte array
// with outLen in size using a fixed size hash.
// See https://datatracker.ietf.org/doc/html/draft-irtf-cfrg-hash-to-curve-13#section-5.4.1
func ExpandMsgXmd(h *EllipticCurveHasher, msg, domain []byte, outLen int) []byte {
	domain = getDomainXmd(h.xmd, domain)
	domainLen := byte(len(domain))
	h.xmd.Reset()
	// DST_prime = DST || I2OSP(len(DST), 1)
	// b_0 = H(Z_pad || msg || l_i_b_str || I2OSP(0, 1) || DST_prime)
	_, _ = h.xmd.Write(make([]byte, h.xmd.BlockSize()))
	_, _ = h.xmd.Write(msg)
	_, _ = h.xmd.Write([]byte{uint8(outLen >> 8), uint8(outLen)})
	_, _ = h.xmd.Write([]byte{0})
	_, _ = h.xmd.Write(domain)
	_, _ = h.xmd.Write([]byte{domainLen})
	b0 := h.xmd.Sum(nil)

	// b_1 = H(b_0 || I2OSP(1, 1) || DST_prime)
	h.xmd.Reset()
	_, _ = h.xmd.Write(b0)
	_, _ = h.xmd.Write([]byte{1})
	_, _ = h.xmd.Write(domain)
	_, _ = h.xmd.Write([]byte{domainLen})
	b1 := h.xmd.Sum(nil)

	// b_i = H(strxor(b_0, b_(i - 1)) || I2OSP(i, 1) || DST_prime)
	ell := (outLen + h.xmd.Size() - 1) / h.xmd.Size()
	bi := b1
	out := make([]byte, outLen)
	for i := 1; i < ell; i++ {
		h.xmd.Reset()
		// b_i = H(strxor(b_0, b_(i - 1)) || I2OSP(i, 1) || DST_prime)
		tmp := make([]byte, h.xmd.Size())
		subtle.XORBytes(tmp, b0, bi)
		_, _ = h.xmd.Write(tmp)
		_, _ = h.xmd.Write([]byte{1 + uint8(i)})
		_, _ = h.xmd.Write(domain)
		_, _ = h.xmd.Write([]byte{domainLen})

		// b_1 || ... || b_(ell - 1)
		copy(out[(i-1)*h.xmd.Size():i*h.xmd.Size()], bi)
		bi = h.xmd.Sum(nil)
	}
	// b_ell
	copy(out[(ell-1)*h.xmd.Size():], bi)
	return out[:outLen]
}

// ExpandMsgXof expands the msg with the domain to output a byte array
// with outLen in size using a xof hash
// See https://datatracker.ietf.org/doc/html/draft-irtf-cfrg-hash-to-curve-13#section-5.4.2
func ExpandMsgXof(h *EllipticCurveHasher, msg, domain []byte, outLen int) []byte {
	domain = getDomainXof(h.xof, domain)
	domainLen := byte(len(domain))
	h.xof.Reset()
	_, _ = h.xof.Write(msg)
	_, _ = h.xof.Write([]byte{uint8(outLen >> 8), uint8(outLen)})
	_, _ = h.xof.Write(domain)
	_, _ = h.xof.Write([]byte{domainLen})
	out := make([]byte, outLen)
	_, _ = h.xof.Read(out)
	return out
}

func getDomainXmd(h hash.Hash, domain []byte) []byte {
	var out []byte
	if len(domain) > MaxDstLen {
		h.Reset()
		_, _ = h.Write([]byte(OversizeDstSalt))
		_, _ = h.Write(domain)
		out = h.Sum(nil)
	} else {
		out = domain
	}
	return out
}

func getDomainXof(h sha3.ShakeHash, domain []byte) []byte {
	var out []byte
	if len(domain) > MaxDstLen {
		h.Reset()
		_, _ = h.Write([]byte(OversizeDstSalt))
		_, _ = h.Write(domain)
		var tv [64]byte
		_, _ = h.Read(tv[:])
		out = tv[:]
	} else {
		out = domain
	}
	return out
}
