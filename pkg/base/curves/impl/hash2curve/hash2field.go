package hash2curve

import (
	"bytes"

	"github.com/copperexchange/krypton-primitives/pkg/base"
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
	DstIdSeparator   = "_"
	DstTagSeparator  = ":"
	DstExpTagXmd     = "XMD"
	DstExpTagXof     = "XOF"
	DstTagSha256     = "SHA-256"
	DstTagSha512     = "SHA-512"
	DstTagShake256   = "SHAKE256"
	DstTagSswu       = "SSWU"
	DstTagElligator2 = "ELL2"
	DstEncVar        = "RO"
	DstOversizeSalt  = "H2C-OVERSIZE-DST-"
)

// CurveHasher is a thread-safe interface for hash to curve functions based on
// https://datatracker.ietf.org/doc/html/rfc9380.
type CurveHasher interface {
	// HashToFieldElements hashes an arbitrary-length message to a list of one
	// or more field elements in a finite field (curves.FieldElement). Uses a
	// domain separation tag (dst) for ExpandMessage, default to `Dst()` if nil.
	// It follows https://datatracker.ietf.org/doc/html/rfc9380#section-5
	HashToFieldElements(count int, msg, optionalDst []byte) (u []curves.BaseFieldElement, err error)

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

func MapToFieldElement(curve curves.Curve, input []byte) (curves.BaseFieldElement, error) {
	fe, err := curve.BaseField().Element().SetBytesWide(input)
	if err != nil {
		return nil, errs.WrapFailed(err, "could not map bytes to field element")
	}
	return fe, nil
}

func MapToScalar(curve curves.Curve, input []byte) (curves.Scalar, error) {
	sc, err := curve.ScalarField().Element().SetBytesWide(input)
	if err != nil {
		return nil, errs.WrapFailed(err, "could not map bytes to scalar")
	}
	return sc, nil
}

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

// getUniformByteLengths computes `L`, the random length in bytes required to
// sample a uniformly distributed FieldElement|Scalar.
func getUniformByteLengths(curve curves.Curve) (lFieldElement, lScalar int) {
	log2pFieldElement := curve.BaseField().Characteristic().AnnouncedLen()
	log2pScalar := curve.SubGroupOrder().BitLen()
	k := base.ComputationalSecurity
	lFieldElement = utils.Math.CeilDiv(log2pFieldElement+k, 8)
	lScalar = utils.Math.CeilDiv(log2pScalar+k, 8)
	return lFieldElement, lScalar
}

// getSuiteId generates a human-readable identifier for the suite following
// the convention from https://datatracker.ietf.org/doc/html/rfc9380#section-8.10
func getSuiteId(curve curves.Curve, hashTag, expandMessageTag, mapperTag string) []byte {
	var buf bytes.Buffer
	// CURVE_ID
	buf.WriteString(curve.Name())
	buf.WriteString(DstIdSeparator)
	// HASH_ID
	buf.WriteString(expandMessageTag)
	buf.WriteString(DstTagSeparator)
	buf.WriteString(hashTag)
	buf.WriteString(DstIdSeparator)
	// MAP_ID
	buf.WriteString(mapperTag)
	buf.WriteString(DstIdSeparator)
	// ENC_VAR
	buf.WriteString(DstEncVar)
	buf.WriteString(DstIdSeparator)
	return buf.Bytes()
}
