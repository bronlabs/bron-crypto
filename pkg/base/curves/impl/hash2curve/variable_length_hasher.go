package hash2curve

import (
	"io"

	"golang.org/x/crypto/sha3"

	"github.com/copperexchange/krypton-primitives/pkg/base/curves"
	"github.com/copperexchange/krypton-primitives/pkg/base/errs"
	"github.com/copperexchange/krypton-primitives/pkg/base/utils/safecast"
)

// VariableLengthHasher encapsulates the variable-length hash functions of blake2b.XOF and sha3.ShakeHash.
type VariableLengthHasher struct {
	hashFactory func() sha3.ShakeHash
	curve       curves.Curve
	dst         []byte

	lFieldElement int
	lScalar       int
}

func NewShake256Hasher(curve curves.Curve, appTag, mapperTag string) CurveHasher {
	lFieldElement, lScalar := getUniformByteLengths(curve)
	vlh := &VariableLengthHasher{sha3.NewShake256, curve, nil, lFieldElement, lScalar}
	vlh.dst = vlh.generateDST(curve, appTag, DstTagSha256, mapperTag)
	return vlh
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
	_, _ = h.Write([]byte{safecast.ToUint8(outLen >> 8), safecast.ToUint8(outLen)})
	_, _ = h.Write(dst)
	_, _ = h.Write([]byte{dstLen})
	// step 5
	out := make([]byte, outLen)
	_, _ = io.ReadFull(h, out)
	return out, nil
}

func (vlh *VariableLengthHasher) Dst() []byte {
	return vlh.dst
}

func (vlh *VariableLengthHasher) Curve() curves.Curve {
	return vlh.curve
}

func (vlh *VariableLengthHasher) generateDST(curve curves.Curve, appTag, hashTag, mapperTag string) (dst []byte) {
	suiteId := getSuiteId(curve, hashTag, DstExpTagXmd, mapperTag)
	dst = append([]byte(appTag), suiteId...)
	if len(dst) > MaxDstLen {
		h := vlh.hashFactory()
		h.Reset()
		_, _ = h.Write([]byte(DstOversizeSalt))
		_, _ = h.Write(dst)
		var tv [64]byte
		_, _ = io.ReadFull(h, tv[:])
		dst = tv[:]
	}
	return dst
}

func (vlh *VariableLengthHasher) HashToFieldElements(count int, msg, dst []byte) (u []curves.BaseFieldElement, err error) {
	if dst == nil {
		dst = vlh.Dst()
	}
	m := safecast.ToInt(vlh.Curve().BaseField().ExtensionDegree().Uint64())
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
