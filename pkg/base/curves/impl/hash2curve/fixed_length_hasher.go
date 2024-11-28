package hash2curve

import (
	"crypto/sha256"
	"crypto/sha512"
	"crypto/subtle"
	"hash"

	"github.com/copperexchange/krypton-primitives/pkg/base/curves"
	"github.com/copperexchange/krypton-primitives/pkg/base/errs"
	"github.com/copperexchange/krypton-primitives/pkg/base/utils"
	"github.com/copperexchange/krypton-primitives/pkg/base/utils/safecast"
)

// FixedLengthCurveHasher encapsulates the fixed-length hash functions of sha256, sha512, sha3 and blake2b.
type FixedLengthCurveHasher struct {
	hashFactory func() hash.Hash
	curve       curves.Curve
	dst         []byte

	lFieldElement int
	lScalar       int
}

func NewCurveHasherSha256(curve curves.Curve, appTag, mapperTag string) CurveHasher {
	lFieldElement, lScalar := getUniformByteLengths(curve)
	flh := &FixedLengthCurveHasher{sha256.New, curve, nil, lFieldElement, lScalar}
	flh.dst = flh.generateDst(curve, appTag, DstTagSha256, mapperTag)
	return flh
}

func NewCurveHasherSha512(curve curves.Curve, appTag, mapperTag string) CurveHasher {
	lFieldElement, lScalar := getUniformByteLengths(curve)
	flh := &FixedLengthCurveHasher{sha512.New, curve, nil, lFieldElement, lScalar}
	flh.dst = flh.generateDst(curve, appTag, DstTagSha512, mapperTag)
	return flh
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
	//nolint:gosec // disable G115
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
		_, _ = h.Write([]byte{1 + safecast.MustToUint8(i)})
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

func (flh *FixedLengthCurveHasher) generateDst(curve curves.Curve, appTag, hashTag, mapperTag string) (dst []byte) {
	suiteId := getSuiteId(curve, hashTag, DstExpTagXmd, mapperTag)
	dst = append([]byte(appTag), suiteId...)
	if len(dst) > MaxDstLen {
		h := flh.hashFactory()
		_, _ = h.Write([]byte(DstOversizeSalt))
		_, _ = h.Write(dst)
		dst = h.Sum(nil)
	}
	return dst
}

func (flh *FixedLengthCurveHasher) HashToFieldElements(count int, msg, dst []byte) (u []curves.BaseFieldElement, err error) {
	if dst == nil {
		dst = flh.Dst()
	}
	m := safecast.MustToInt(flh.Curve().BaseField().ExtensionDegree().Uint64())
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
