package expanders

import (
	"crypto/subtle"
	"encoding/binary"
	"hash"
	"slices"
)

// Xmd implements expand_message_xmd from RFC 9380.
type Xmd struct {
	HashFunc func() hash.Hash
}

// ExpandMessage expands msg to lenInBytes using XMD and dst.
func (e *Xmd) ExpandMessage(dst, msg []byte, lenInBytes uint) []byte {
	h := e.HashFunc()
	sInBytes := h.BlockSize()

	// 0. if len(DST) > 255: DST = H("H2C-OVERSIZE-DST-" || a_very_long_DST)
	if len(dst) > 255 {
		h.Reset()
		h.Write(slices.Concat([]byte("H2C-OVERSIZE-DST-"), dst))
		dst = h.Sum(nil)
	}
	//  1. ell = ceil(len_in_bytes / b_in_bytes)
	ell := (lenInBytes + 7) / 8
	//  2.  ABORT if ell > 255 or len_in_bytes > 65535
	if ell > 255 || lenInBytes > 65535 {
		panic("invalid length")
	}
	//  3.  DST_prime = DST || I2OSP(len(DST), 1)
	dstPrime := append(dst, i2osp(uint64(len(dst)), 1)...)
	//  4.  Z_pad = I2OSP(0, s_in_bytes)
	zPad := i2osp(0, uint(sInBytes))
	//  5.  l_i_b_str = I2OSP(len_in_bytes, 2)
	libStr := i2osp(uint64(lenInBytes), 2)
	//  6.  msg_prime = Z_pad || msg || l_i_b_str || I2OSP(0, 1) || DST_prime
	msgPrime := slices.Concat(zPad, msg, libStr, i2osp(0, 1), dstPrime)
	//  7.  b_0 = H(msg_prime)
	b := make([][]byte, ell+1)
	h.Reset()
	h.Write(msgPrime)
	b[0] = h.Sum(nil)
	//  8.  b_1 = H(b_0 || I2OSP(1, 1) || DST_prime)
	h.Reset()
	h.Write(slices.Concat(b[0], i2osp(1, 1), dstPrime))
	b[1] = h.Sum(nil)
	//  9.  for i in (2, ..., ell):
	for i := uint(2); i <= ell; i++ {
		// 10. b_i = H(strxor(b_0, b_(i - 1)) || I2OSP(i, 1) || DST_prime)
		b0XorBi := make([]byte, h.Size())
		subtle.XORBytes(b0XorBi, b[0], b[i-1])
		h.Reset()
		h.Write(slices.Concat(b0XorBi, i2osp(uint64(i), 1), dstPrime))
		b[i] = h.Sum(nil)
	}
	// 11. uniform_bytes = b_1 || ... || b_ell
	uniformBytes := slices.Concat(b[1:]...)
	// 12. return substr(uniform_bytes, 0, len_in_bytes)
	return uniformBytes[:lenInBytes]
}

func i2osp(in uint64, length uint) []byte {
	data := make([]byte, length)
	copy(data, binary.LittleEndian.AppendUint64(nil, in))
	slices.Reverse(data)
	return data
}
