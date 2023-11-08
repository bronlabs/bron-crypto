package hashing

import (
	"bytes"
	"crypto/sha256"
	"crypto/sha512"
	"crypto/subtle"
	"hash"

	"golang.org/x/crypto/sha3"

	"github.com/copperexchange/krypton-primitives/pkg/base/constants"
	"github.com/copperexchange/krypton-primitives/pkg/base/curves"
	"github.com/copperexchange/krypton-primitives/pkg/base/errs"
	"github.com/copperexchange/krypton-primitives/pkg/base/utils"
)

const (
	// MaxDstLen the max size for dst in hash to curve.
	MaxDstLen = 255
	// MaxExpMsgOutLen is the max size for the output of the expand message function in bytes.
	MaxExpMsgOutLen = 65535
	// MaxExpMsgBlockLen the max size for the output of the expand message function in blocks.
	MaxExpMsgBlockLen = 255
)
const (
	DST_ID_SEPARATOR   = "_"
	DST_TAG_SEPARATOR  = ":"
	DST_EXP_TAG_XMD    = "XMD"
	DST_EXP_TAG_XOF    = "XOF"
	DST_TAG_SHA256     = "SHA-256"
	DST_TAG_SHA512     = "SHA-512"
	DST_TAG_SHAKE256   = "SHAKE256"
	DST_TAG_SSWU       = "SSWU"
	DST_TAG_ELLIGATOR2 = "ELL2"
	DST_ENC_VAR        = "RO"
	DST_OVERSIZE_SALT  = "H2C-OVERSIZE-DST-"
)

// CurveHasher is a thread-safe interface for hash to curve functions based on
// https://datatracker.ietf.org/doc/html/rfc9380.
type CurveHasher interface {
	// HashToFieldElements hashes an arbitrary-length message to a list of one
	// or more field elements in a finite field (curves.FieldElement). Uses a
	// domain separation tag (dst) for ExpandMessage, default to `Dst()` if nil.
	// It follows https://datatracker.ietf.org/doc/html/rfc9380#section-5
	HashToFieldElements(count int, msg, optionalDst []byte) (u []curves.FieldElement, err error)
	// HashToScalars hashes an arbitrary-length message to a list of one
	// or more elements in a prime field Fq (curves.Scalar). Uses a
	// domain separation tag (dst) for ExpandMessage, default to `Dst()` if nil.
	// It follows https://datatracker.ietf.org/doc/html/rfc9380#section-5
	HashToScalars(count int, msg, optionalDst []byte) (u []curves.Scalar, err error)
	// ExpandMessage expands an input `msg` to a byte string of length `outLen`.
	// Uses a domain separation tag (dst) for ExpandMessage, default to `Dst()` if nil.
	// It follows https://datatracker.ietf.org/doc/html/rfc9380#section-5.3
	ExpandMessage(outLen int, msg, optionalDst []byte) ([]byte, error)
	// Dst returns the domain separation tag (dst) for ExpandMessage.
	Dst() []byte
	// Curve returns the curve associated with the hasher.
	Curve() curves.Curve
}

/*.------------------------- FIXED-LENGTH HASHERS ---------------------------.*/

func NewCurveHasherSha256(curve curves.Curve, appTag, mapperTag string) CurveHasher {
	lFieldElement, lScalar := getUniformByteLengths(curve)
	flh := &FixedLengthCurveHasher{sha256.New, curve, nil, lFieldElement, lScalar}
	flh.dst = flh.generateDST(curve, appTag, DST_TAG_SHA256, mapperTag)
	return flh
}

func NewCurveHasherSha512(curve curves.Curve, appTag, mapperTag string) CurveHasher {
	lFieldElement, lScalar := getUniformByteLengths(curve)
	flh := &FixedLengthCurveHasher{sha512.New, curve, nil, lFieldElement, lScalar}
	flh.dst = flh.generateDST(curve, appTag, DST_TAG_SHA512, mapperTag)
	return flh
}

// FixedLengthCurveHasher encapsulates the fixed-length hash functions of sha256, sha512, sha3 and blake2b.
type FixedLengthCurveHasher struct {
	hashFactory func() hash.Hash
	curve       curves.Curve
	dst         []byte

	lFieldElement int
	lScalar       int
}

// ExpandMessage implements the fixed-length hash variant `expand_message_xmd`
// from https://datatracker.ietf.org/doc/html/rfc9380#section-5.3.1
func (flh *FixedLengthCurveHasher) ExpandMessage(outLen int, msg, dst []byte) ([]byte, error) {
	h := flh.hashFactory()
	// step 1 & 2
	ell := utils.CeilDiv(outLen, h.Size())
	if ell > MaxExpMsgBlockLen || outLen > MaxExpMsgOutLen {
		return nil, errs.NewFailed("outLen is too large")
	}
	// steps 3-7
	//  b_0 = H(Z_pad || msg || l_i_b_str || I2OSP(0, 1) || DST || I2OSP(len(DST), 1))
	dstLen := byte(len(dst))
	_, _ = h.Write(make([]byte, h.BlockSize()))
	_, _ = h.Write(msg)
	_, _ = h.Write([]byte{uint8(outLen >> 8), uint8(outLen)})
	_, _ = h.Write([]byte{0})
	_, _ = h.Write(dst)
	_, _ = h.Write([]byte{dstLen})
	b0 := h.Sum(nil)
	// step 8
	//  b_1 = H(b_0 || I2OSP(1, 1) || DST_prime)
	h.Reset()
	_, _ = h.Write(b0)
	_, _ = h.Write([]byte{1})
	_, _ = h.Write(dst)
	_, _ = h.Write([]byte{dstLen})
	b1 := h.Sum(nil)
	// steps 9-11
	bi := b1
	out := make([]byte, outLen)
	for i := 1; i < ell; i++ {
		h.Reset()
		//  b_i = H(strxor(b_0, b_(i - 1)) || I2OSP(i, 1) || DST_prime)
		tmp := make([]byte, h.Size())
		subtle.XORBytes(tmp, b0, bi)
		_, _ = h.Write(tmp)
		_, _ = h.Write([]byte{1 + uint8(i)})
		_, _ = h.Write(dst)
		_, _ = h.Write([]byte{dstLen})
		//  uniform_bytes = b_1 || ... || b_(ell - 1)
		copy(out[(i-1)*h.Size():i*h.Size()], bi)
		bi = h.Sum(nil)
	}
	//  || b_ell
	copy(out[(ell-1)*h.Size():], bi)
	// step 12
	return out[:outLen], nil
}

func (flh *FixedLengthCurveHasher) Dst() []byte {
	return flh.dst
}

func (flh *FixedLengthCurveHasher) Curve() curves.Curve {
	return flh.curve
}

func (flh *FixedLengthCurveHasher) generateDST(curve curves.Curve, appTag, hashTag, mapperTag string) (dst []byte) {
	suiteId := getSuiteID(curve, hashTag, DST_EXP_TAG_XMD, mapperTag)
	dst = append([]byte(appTag), suiteId...)
	if len(dst) > MaxDstLen {
		h := flh.hashFactory()
		_, _ = h.Write([]byte(DST_OVERSIZE_SALT))
		_, _ = h.Write(dst)
		dst = h.Sum(nil)
	}
	return dst
}

func (flh *FixedLengthCurveHasher) HashToFieldElements(count int, msg, dst []byte) (u []curves.FieldElement, err error) {
	if dst == nil {
		dst = flh.Dst()
	}
	m := int(flh.curve.Profile().Field().ExtensionDegree().Uint64())
	u, err = hashToField(flh, MapToFieldElement, msg, dst, count, flh.lFieldElement, m)
	if err != nil {
		return nil, errs.WrapFailed(err, "hash to field element with fixed-length hash function failed")
	}
	return u, nil
}

func (flh *FixedLengthCurveHasher) HashToScalars(count int, msg, dst []byte) (u []curves.Scalar, err error) {
	if dst == nil {
		dst = flh.Dst()
	}
	u, err = hashToField(flh, MapToScalar, msg, dst, count, flh.lScalar, 1)
	if err != nil {
		return nil, errs.WrapFailed(err, "hash to scalar with fixed-length hash function failed")
	}
	return u, nil
}

/*.----------------------- VARIABLE-LENGTH HASHERS --------------------------.*/

func NewShake256Hasher(curve curves.Curve, appTag, mapperTag string) CurveHasher {
	lFieldElement, lScalar := getUniformByteLengths(curve)
	vlh := &VariableLengthHasher{sha3.NewShake256, curve, nil, lFieldElement, lScalar}
	vlh.dst = vlh.generateDST(curve, appTag, DST_TAG_SHA256, mapperTag)
	return vlh
}

// VariableLengthHasher encapsulates the variable-length hash functions of blake2b.XOF and sha3.ShakeHash.
type VariableLengthHasher struct {
	hashFactory func() sha3.ShakeHash
	curve       curves.Curve
	dst         []byte

	lFieldElement int
	lScalar       int
}

func (vlh *VariableLengthHasher) ExpandMessage(outLen int, msg, dst []byte) ([]byte, error) {
	h := vlh.hashFactory()
	// step 1
	if outLen > MaxExpMsgOutLen {
		panic("expandMsgXof: outLen is too large")
	}
	// step 2-4
	//  uniform_bytes = H(msg || I2OSP(len_in_bytes, 2) || DST || I2OSP(len(DST), 1), len_in_bytes)
	dstLen := byte(len(dst))
	_, _ = h.Write(msg)
	_, _ = h.Write([]byte{uint8(outLen >> 8), uint8(outLen)})
	_, _ = h.Write(dst)
	_, _ = h.Write([]byte{dstLen})
	// step 5
	out := make([]byte, outLen)
	_, _ = h.Read(out)
	return out, nil
}

func (vlh *VariableLengthHasher) Dst() []byte {
	return vlh.dst
}

func (vlh *VariableLengthHasher) Curve() curves.Curve {
	return vlh.curve
}

func (vlh *VariableLengthHasher) generateDST(curve curves.Curve, appTag, hashTag, mapperTag string) (dst []byte) {
	suiteId := getSuiteID(curve, hashTag, DST_EXP_TAG_XMD, mapperTag)
	dst = append([]byte(appTag), suiteId...)
	if len(dst) > MaxDstLen {
		h := vlh.hashFactory()
		h.Reset()
		_, _ = h.Write([]byte(DST_OVERSIZE_SALT))
		_, _ = h.Write(dst)
		var tv [64]byte
		_, _ = h.Read(tv[:])
		dst = tv[:]
	}
	return dst
}

func (vlh *VariableLengthHasher) HashToFieldElements(count int, msg, dst []byte) (u []curves.FieldElement, err error) {
	if dst == nil {
		dst = vlh.Dst()
	}
	m := int(vlh.curve.Profile().Field().ExtensionDegree().Uint64())
	u, err = hashToField(vlh, MapToFieldElement, msg, dst, count, vlh.lFieldElement, m)
	if err != nil {
		return nil, errs.WrapFailed(err, "hash to field element with variable-length hash function failed")
	}
	return u, nil
}

func (vlh *VariableLengthHasher) HashToScalars(count int, msg, dst []byte) (u []curves.Scalar, err error) {
	if dst == nil {
		dst = vlh.Dst()
	}
	u, err = hashToField(vlh, MapToScalar, msg, dst, count, vlh.lScalar, 1)
	if err != nil {
		return nil, errs.WrapFailed(err, "hash to scalar with variable-length hash function failed")
	}
	return u, nil
}

/*.-------------------------------- COMMON ----------------------------------.*/

// hashToField implements the hash_to_field function from https://datatracker.ietf.org/doc/html/rfc9380#section-5.2
func hashToField[FieldType any](
	h CurveHasher,
	MapToField func(curves.Curve, []byte) (FieldType, error),
	msg, dst []byte,
	count, L, m int,
) (u []FieldType, err error) {
	// step 1 & 2
	uniformBytes, err := h.ExpandMessage(count*m*L, msg, dst)
	if err != nil {
		return nil, errs.WrapFailed(err, "could not expand message to be hashed to field")
	}
	u = make([]FieldType, count)
	// step 3 & 4
	for i := 0; i < count; i++ {
		// step 5-8
		u[i], err = MapToField(h.Curve(), uniformBytes[i*L*m:(i+1)*L*m])
		if err != nil {
			return nil, errs.WrapFailed(err, "could not set element")
		}
	}
	// step 9
	return u, nil
}

func MapToFieldElement(curve curves.Curve, input []byte) (curves.FieldElement, error) {
	fe, err := curve.FieldElement().Zero().SetBytesWide(input)
	if err != nil {
		return nil, errs.WrapFailed(err, "could not map bytes to field element")
	}
	return fe, nil
}

func MapToScalar(curve curves.Curve, input []byte) (curves.Scalar, error) {
	sc, err := curve.Scalar().Zero().SetBytesWide(input)
	if err != nil {
		return nil, errs.WrapFailed(err, "could not map bytes to scalar")
	}
	return sc, nil
}

// getUniformByteLengths computes `L`, the random length in bytes required to
// sample a uniformly distributed FieldElement|Scalar.
func getUniformByteLengths(curve curves.Curve) (lFieldElement, lScalar int) {
	log2pFieldElement := curve.Profile().Field().Characteristic().AnnouncedLen()
	log2pScalar := curve.Profile().SubGroupOrder().BitLen()
	k := constants.ComputationalSecurity
	lFieldElement = utils.CeilDiv(log2pFieldElement+k, 8)
	lScalar = utils.CeilDiv(log2pScalar+k, 8)
	return lFieldElement, lScalar
}

// getSuiteID generates a human-readable identifier for the suite following
// the convention from https://datatracker.ietf.org/doc/html/rfc9380#section-8.10
func getSuiteID(curve curves.Curve, hashTag, expandMessageTag, mapperTag string) []byte {
	var buf bytes.Buffer
	// CURVE_ID
	buf.WriteString(curve.Name())
	buf.WriteString(DST_ID_SEPARATOR)
	// HASH_ID
	buf.WriteString(expandMessageTag)
	buf.WriteString(DST_TAG_SEPARATOR)
	buf.WriteString(hashTag)
	buf.WriteString(DST_ID_SEPARATOR)
	// MAP_ID
	buf.WriteString(mapperTag)
	buf.WriteString(DST_ID_SEPARATOR)
	// ENC_VAR
	buf.WriteString(DST_ENC_VAR)
	buf.WriteString(DST_ID_SEPARATOR)
	return buf.Bytes()
}
