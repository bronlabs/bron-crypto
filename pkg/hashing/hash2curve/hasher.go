package hash2curve

import (
	"bytes"
	"crypto/sha256"
	"crypto/sha512"
	"crypto/subtle"
	"hash"

	"github.com/copperexchange/krypton-primitives/pkg/base"
	"github.com/copperexchange/krypton-primitives/pkg/base/constants"
	"github.com/copperexchange/krypton-primitives/pkg/base/curves"
	"github.com/copperexchange/krypton-primitives/pkg/base/errs"
	"golang.org/x/crypto/sha3"
)

const (
	// MaxDstLen the max size for dst in hash to curve.
	MaxDstLen = 255
	// MaxExpMsgOutLen is the max size for the output of the expand message function in bytes.
	MaxExpMsgOutLen = 65535
	// MaxExpMsgBlockLen the max size  for the output of the expand message function in blocks.
	MaxExpMsgBlockLen = 255
)
const (
	DST_ID_SEPARATOR   = "_"
	DST_TAG_SEPARATOR  = ":"
	DST_ENC_VAR        = "RO"
	DST_EXP_TAG_XMD    = "XMD"
	DST_EXP_TAG_XOF    = "XOF"
	DST_OVERSIZE_SALT  = "H2C-OVERSIZE-DST-"
	DST_TAG_SHA256     = "SHA-256"
	DST_TAG_SHA512     = "SHA-512"
	DST_TAG_SHAKE256   = "SHAKE256"
	DST_TAG_SSWU       = "SSWU"
	DST_TAG_ELLIGATOR2 = "ELL2"
)

type CurveHasher interface {
	// ExpandMessage expands an input `msg` to a byte string of length `outLen`,
	// using an optional `appId` for the domain separation tag.
	// It follows https://datatracker.ietf.org/doc/html/rfc9380#section-5.3
	ExpandMessage(msg, dst []byte, outLen int) ([]byte, error)
	// GenerateDST generates the domain sepaaration tag.
	// It follows https://datatracker.ietf.org/doc/html/rfc9380#section-8.10
	GenerateDST(curve curves.Curve) []byte
}

/* ------------------------- FIXED-LENGTH HASHERS --------------------------- */

func NewCurveHasherSha256(curve curves.Curve) CurveHasher {
	return &FixedLengthCurveHasher{sha256.New(), DST_TAG_SHA256}
}

func NewCurveHasherSha512(curve curves.Curve) CurveHasher {
	return &FixedLengthCurveHasher{sha512.New(), DST_TAG_SHA512}
}

// FixedLengthCurveHasher encapsulates the fixed-length hash functions of sha256, sha512, sha3 and blake2b.
type FixedLengthCurveHasher struct {
	hash.Hash
	hashName string
}

// ExpandMessage implements the fixed-length hash variant `expand_message_xmd`
// from https://datatracker.ietf.org/doc/html/rfc9380#section-5.3.1
func (flh *FixedLengthCurveHasher) ExpandMessage(msg, dst []byte, outLen int) ([]byte, error) {
	// step 1 & 2
	ell := base.CeilDiv(outLen, flh.Size())
	if ell > MaxExpMsgBlockLen || outLen > MaxExpMsgOutLen {
		return nil, errs.NewFailed("outLen is too large")
	}
	// steps 3-7
	//  b_0 = H(Z_pad || msg || l_i_b_str || I2OSP(0, 1) || DST || I2OSP(len(DST), 1))
	dstLen := byte(len(dst))
	flh.Reset()
	_, _ = flh.Write(make([]byte, flh.BlockSize()))
	_, _ = flh.Write(msg)
	_, _ = flh.Write([]byte{uint8(outLen >> 8), uint8(outLen)})
	_, _ = flh.Write([]byte{0})
	_, _ = flh.Write(dst)
	_, _ = flh.Write([]byte{dstLen})
	b0 := flh.Sum(nil)
	// step 8
	//  b_1 = H(b_0 || I2OSP(1, 1) || DST_prime)
	flh.Reset()
	_, _ = flh.Write(b0)
	_, _ = flh.Write([]byte{1})
	_, _ = flh.Write(dst)
	_, _ = flh.Write([]byte{dstLen})
	b1 := flh.Sum(nil)
	// steps 9-11
	bi := b1
	out := make([]byte, outLen)
	for i := 1; i < ell; i++ {
		flh.Reset()
		//  b_i = H(strxor(b_0, b_(i - 1)) || I2OSP(i, 1) || DST_prime)
		tmp := make([]byte, flh.Size())
		subtle.XORBytes(tmp, b0, bi)
		_, _ = flh.Write(tmp)
		_, _ = flh.Write([]byte{1 + uint8(i)})
		_, _ = flh.Write(dst)
		_, _ = flh.Write([]byte{dstLen})
		//  uniform_bytes = b_1 || ... || b_(ell - 1)
		copy(out[(i-1)*flh.Size():i*flh.Size()], bi)
		bi = flh.Sum(nil)
	}
	//  || b_ell
	copy(out[(ell-1)*flh.Size():], bi)
	// step 12
	return out[:outLen], nil
}

// GenerateDST returns the dst to be used in the ExpandMessage function, following
// the dst expansion from https://datatracker.ietf.org/doc/html/rfc9380#section-5.3.2
func (flh *FixedLengthCurveHasher) GenerateDST(curve curves.Curve) (dst []byte) {
	dst = generateDst(curve, flh.hashName, DST_EXP_TAG_XMD)
	if len(dst) > MaxDstLen {
		flh.Reset()
		_, _ = flh.Write([]byte(DST_OVERSIZE_SALT))
		_, _ = flh.Write([]byte(dst))
		dst = flh.Sum(nil)
	}
	return dst
}

/* ----------------------- VARIABLE-LENGTH HASHERS -------------------------- */

func NewShake256Hasher() CurveHasher {
	return &VariableLengthHasher{sha3.NewShake256(), DST_TAG_SHAKE256}
}

// VariableLengthHasher encapsulates the variable-length hash functions of blake2b.XOF and sha3.ShakeHash.
type VariableLengthHasher struct {
	sha3.ShakeHash
	hashName string
}

// ExpandMessage implements the variable-length hash variant `expand_msg_xof` from
// https://datatracker.ietf.org/doc/html/rfc9380#section-5.3.2
func (vlh *VariableLengthHasher) ExpandMessage(msg, dst []byte, outLen int) ([]byte, error) {
	// step 1
	if outLen > MaxExpMsgOutLen {
		panic("expandMsgXof: outLen is too large")
	}
	// step 2-4
	//  uniform_bytes = H(msg || I2OSP(len_in_bytes, 2) || DST || I2OSP(len(DST), 1), len_in_bytes)
	dstLen := byte(len(dst))
	vlh.Reset()
	_, _ = vlh.Write(msg)
	_, _ = vlh.Write([]byte{uint8(outLen >> 8), uint8(outLen)})
	_, _ = vlh.Write(dst)
	_, _ = vlh.Write([]byte{dstLen})
	// step 5
	out := make([]byte, outLen)
	_, _ = vlh.Read(out)
	return out, nil
}

// getDstXof returns the dst to be used in the expandMsgXof function, following
// the dst expansion from https://datatracker.ietf.org/doc/html/rfc9380#section-5.3.3
func (vlh *VariableLengthHasher) GenerateDST(curve curves.Curve) (dst []byte) {
	dst = generateDst(curve, vlh.hashName, DST_EXP_TAG_XOF)
	if len(dst) > MaxDstLen {
		vlh.Reset()
		_, _ = vlh.Write([]byte(DST_OVERSIZE_SALT))
		_, _ = vlh.Write(dst)
		var tv [64]byte
		_, _ = vlh.Read(tv[:])
		dst = tv[:]
	}
	return dst
}

/*.------------------------------ AUXILIARY ---------------------------------.*/

// generateDst generates a human-readable identifier for the suite following
// the convention from https://datatracker.ietf.org/doc/html/rfc9380#section-8.10
func generateDst(curve curves.Curve, hashName, expandMessageTag string) []byte {
	var buf bytes.Buffer
	// CURVE_ID
	buf.WriteString(curve.Name())
	buf.WriteString(DST_ID_SEPARATOR)
	// HASH_ID
	buf.WriteString(expandMessageTag)
	buf.WriteString(DST_TAG_SEPARATOR)
	buf.WriteString(hashName)
	buf.WriteString(DST_ID_SEPARATOR)
	// MAP_ID
	if curve.Name() == constants.ED25519_NAME || curve.Name() == constants.CURVE25519_NAME {
		buf.WriteString(DST_TAG_ELLIGATOR2)
	} else {
		buf.WriteString(DST_TAG_SSWU)
	}
	buf.WriteString(DST_ID_SEPARATOR)
	// ENC_VAR
	buf.WriteString(DST_ENC_VAR)
	buf.WriteString(DST_ID_SEPARATOR)
	return buf.Bytes()
}
