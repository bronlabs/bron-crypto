package expanders

import (
	"slices"

	"golang.org/x/crypto/sha3"
)

type Xof struct {
	XofHash sha3.ShakeHash
	K       uint
}

func (e *Xof) ExpandMessage(dst, msg []byte, lenInBytes uint) []byte {
	h := e.XofHash.Clone()

	if len(dst) > 255 {
		// 0. DST = H("H2C-OVERSIZE-DST-" || a_very_long_DST, ceil(2 * k / 8))
		h.Reset()
		h.Write(slices.Concat([]byte("H2C-OVERSIZE-DST-"), dst))
		dst = make([]byte, (2*e.K+7)/8)
		h.Read(dst)
	}

	// 1. ABORT if len_in_bytes > 65535
	if lenInBytes > 65535 {
		panic("invalid length")
	}
	// 2. DST_prime = DST || I2OSP(len(DST), 1)
	dstPrime := slices.Concat(dst, i2osp(uint64(len(dst)), 1))
	// 3. msg_prime = msg || I2OSP(len_in_bytes, 2) || DST_prime
	msgPrime := slices.Concat(msg, i2osp(uint64(lenInBytes), 2), dstPrime)
	// 4. uniform_bytes = H(msg_prime, len_in_bytes)
	h.Reset()
	h.Write(msgPrime)
	uniformBytes := make([]byte, lenInBytes)
	h.Read(uniformBytes)
	// 5. return uniform_bytes
	return uniformBytes[:lenInBytes]
}
