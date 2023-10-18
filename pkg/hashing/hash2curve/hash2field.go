package hash2curve

import (
	"crypto/subtle"
	"hash"

	"github.com/cronokirby/saferith"

	"github.com/copperexchange/krypton-primitives/pkg/base"
	"github.com/copperexchange/krypton-primitives/pkg/base/constants"
	"github.com/copperexchange/krypton-primitives/pkg/base/curves"
	"github.com/copperexchange/krypton-primitives/pkg/base/errs"
	"github.com/copperexchange/krypton-primitives/pkg/base/types"
)

// OversizeDstSalt is the salt used to hash a dst over MaxDstLen.
const OversizeDstSalt = "H2C-OVERSIZE-DST-"

const (
	// DigestScalarBytes (`L` in rfc9380) is bytestring length needed for safe hash_to_field conversion, avoiding bias when reduced.
	DigestScalarBytes = constants.ScalarBytes + constants.ComputationalSecurityBytes

	// MaxDstLen the max size for dst in hash to curve.
	MaxDstLen = 255

	// MaxExpMsgOutLen is the max size for the output of the expand message function.
	MaxExpMsgOutLen = 65535
)

// TODO: one more level of abstraction to remove choice of dst --> prefix
// TODO: CipherSuite for hash2curve, containing curve choice and hash choice (with its expand mapping)
// TODO: use generic Hash2Field for all curves.
// TODO: migrate hash tests in curves to hash2curve package.

func HashToCurveField(curve curves.Curve, h Hasher, msg, dst []byte, count int) ([][]*saferith.Nat, error) {
	m := int(curve.Profile().Field().ExtensionDegree().Uint64())
	log2p := curve.Profile().Field().Characteristic().AnnouncedLen()
	fieldOrder := curve.Profile().Field().Order()
	u, err := HashToField(m, log2p, fieldOrder, h, msg, dst, count)
	if err != nil {
		return nil, errs.WrapFailed(err, "could not hash to curve field")
	}
	return u, nil
}

func HashToCurveScalar(curve curves.Curve, h Hasher, msg, dst []byte, count int) ([][]*saferith.Nat, error) {
	log2p := curve.Profile().SubGroupOrder().BitLen()
	fieldOrder := curve.Profile().SubGroupOrder()
	u, err := HashToField(1, log2p, fieldOrder, h, msg, dst, count)
	if err != nil {
		return nil, errs.WrapFailed(err, "could not hash to scalar")
	}
	return u, nil
}

// HashToField hashes arbitrary-length byte strings to a list of one or more
// elements of a finite field F. It is used to generate curve points &| scalars.
// Reference Spec: https://datatracker.ietf.org/doc/html/rfc9380#section-5
func HashToField(m, log2p int, fieldOrder *saferith.Modulus, h Hasher, msg, dst []byte, count int) (u [][]*saferith.Nat, err error) {
	// step 1
	k := constants.ComputationalSecurity
	L := base.CeilDiv(log2p+k, 8)
	lenInBytes := count * m * L
	// step 2
	var uniformBytes []byte
	if h.Type().ExpandMessageType() == types.XMD {
		uniformBytes, err = expandMsgXmd(h, msg, dst, lenInBytes)
	} else { // XOF
		uniformBytes = expandMsgXof(h, msg, dst, lenInBytes)
	}
	if err != nil {
		return nil, errs.WrapFailed(err, "could not expand message to be hashed to field")
	}
	u = make([][]*saferith.Nat, count)
	// step 3
	for i := 0; i < count; i++ {
		e := make([]*saferith.Nat, m)
		// step 4
		for j := 0; j < m; j++ {
			// step 5
			elmOffset := L * (j + i*m)
			// step 6
			tv := uniformBytes[elmOffset : elmOffset+L]
			// step 7
			tvNat := new(saferith.Nat).SetBytes(tv)
			e[j] = tvNat.Mod(tvNat, fieldOrder)
		}
		// step 8
		u[i] = e
	}
	// step 9
	return u, nil
}

// ExpandMsgXmd expands the msg with the dst (domain separation tag) to output a
// byte array with outLen in size using a fixed size hash.
// See https://datatracker.ietf.org/doc/html/rfc9380#section-5.3.1
func expandMsgXmd(h Hasher, msg, dst []byte, outLen int) ([]byte, error) {
	flh, ok := h.(*FixedLengthHasher)
	if !ok {
		panic("expandMsgXmd: h must be a FixedLengthHasher")
	}
	// step 1 & 2
	ell := base.CeilDiv(outLen, flh.Size())
	if ell > 255 || outLen > MaxExpMsgOutLen {
		return nil, errs.NewFailed("outLen is too large")
	}
	// steps 3-7
	//  b_0 = H(Z_pad || msg || l_i_b_str || I2OSP(0, 1) || DST || I2OSP(len(DST), 1))
	dst = getDomainSeparationTagXmd(flh, dst)
	dstLen := byte(len(dst))
	h.Reset()
	_, _ = flh.Write(make([]byte, flh.BlockSize()))
	_, _ = flh.Write(msg)
	_, _ = flh.Write([]byte{uint8(outLen >> 8), uint8(outLen)})
	_, _ = flh.Write([]byte{0})
	_, _ = flh.Write(dst)
	_, _ = flh.Write([]byte{dstLen})
	b0 := flh.Sum(nil)
	// step 8
	// b_1 = H(b_0 || I2OSP(1, 1) || DST_prime)
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
		// b_i = H(strxor(b_0, b_(i - 1)) || I2OSP(i, 1) || DST_prime)
		tmp := make([]byte, flh.Size())
		subtle.XORBytes(tmp, b0, bi)
		_, _ = flh.Write(tmp)
		_, _ = flh.Write([]byte{1 + uint8(i)})
		_, _ = flh.Write(dst)
		_, _ = flh.Write([]byte{dstLen})
		// uniform_bytes = b_1 || ... || b_(ell - 1)
		copy(out[(i-1)*flh.Size():i*flh.Size()], bi)
		bi = flh.Sum(nil)
	}
	// || b_ell
	copy(out[(ell-1)*flh.Size():], bi)
	// step 12
	return out[:outLen], nil
}

// ExpandMsgXof expands the msg with the domain to output a byte array
// with outLen in size using a xof hash
// See https://datatracker.ietf.org/doc/html/draft-irtf-cfrg-hash-to-curve-13#section-5.4.2
func expandMsgXof(h Hasher, msg, domain []byte, outLen int) []byte {
	vlh, ok := h.(*VariableLengthHasher)
	if !ok {
		panic("expandMsgXof: h must be a VariableLengthHasher")
	}
	domain = getDomainSeparationTagXof(vlh, domain)
	domainLen := byte(len(domain))
	vlh.Reset()
	_, _ = vlh.Write(msg)
	_, _ = vlh.Write([]byte{uint8(outLen >> 8), uint8(outLen)})
	_, _ = vlh.Write(domain)
	_, _ = vlh.Write([]byte{domainLen})
	out := make([]byte, outLen)
	_, _ = vlh.Read(out)
	return out
}

func getDomainSeparationTagXmd(h hash.Hash, domain []byte) []byte {
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

func getDomainSeparationTagXof(h ExtendableHash, domain []byte) []byte {
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
