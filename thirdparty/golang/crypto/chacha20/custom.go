package chacha20

import (
	"encoding/binary"

	"github.com/bronlabs/bron-crypto/pkg/base/utils/sliceutils"
	"github.com/bronlabs/bron-crypto/thirdparty/golang/crypto/internal/alias"
)

type FastKeyErasureCipher struct {
	*Cipher
}

func NewFastErasureCipher(key, nonce []byte) (*FastKeyErasureCipher, error) {
	c, err := NewUnauthenticatedCipher(key, nonce)
	if err != nil {
		return nil, err
	}
	return &FastKeyErasureCipher{c}, nil
}

func (c *FastKeyErasureCipher) setKey(key []byte) {
	key = key[:KeySize]
	c.precompDone = false
	c.Cipher.key = [8]uint32{
		binary.LittleEndian.Uint32(key[0:4]),
		binary.LittleEndian.Uint32(key[4:8]),
		binary.LittleEndian.Uint32(key[8:12]),
		binary.LittleEndian.Uint32(key[12:16]),
		binary.LittleEndian.Uint32(key[16:20]),
		binary.LittleEndian.Uint32(key[20:24]),
		binary.LittleEndian.Uint32(key[24:28]),
		binary.LittleEndian.Uint32(key[28:32]),
	}
}

// XORKeyStream XORs each byte in the given slice with a byte from the
// cipher's key stream. Dst and src must overlap entirely or not at all.
//
// NOTE: This is a copy-paste of XORKeyStream, modified to erase the key stream
// after it is used, and to refresh the key on every read unless the buffer is
// not exhausted, providing a degree of forward secrecy. Changes are flagged
// with the comment "CUSTOM".
//
// If len(dst) < len(src), XORKeyStream will panic. It is acceptable
// to pass a dst bigger than src, and in that case, XORKeyStream will
// only update dst[:len(src)] and will not touch the rest of dst.
//
// Multiple calls to XORKeyStream behave as if the concatenation of
// the src buffers was passed in a single run. That is, Cipher
// maintains state and does not reset at each XORKeyStream call.
//

func (c *FastKeyErasureCipher) XORKeyStream(dst, src []byte) {
	if len(src) == 0 {
		return
	}
	if len(dst) < len(src) {
		panic("chacha20: output smaller than input")
	}
	dst = dst[:len(src)]
	if alias.InexactOverlap(dst, src) {
		panic("chacha20: invalid buffer overlap")
	}

	// First, drain any remaining key stream from a previous XORKeyStream.
	if c.remaining != 0 {
		keyStream := c.buf[bufSize-c.remaining:]
		if len(src) < len(keyStream) {
			keyStream = keyStream[:len(src)]
		}
		_ = src[len(keyStream)-1] // bounds check elimination hint
		for i, b := range keyStream {
			dst[i] = src[i] ^ b
		}
		c.remaining -= len(keyStream)
		sliceutils.Fill(keyStream, 0) // CUSTOM: fast erasure of keystream
		dst, src = dst[len(keyStream):], src[len(keyStream):]
	}
	if len(src) == 0 {
		return
	}

	// If we'd need to let the counter overflow and keep generating output,
	// panic immediately. If instead we'd only reach the last block, remember
	// not to generate any more output after the buffer is drained.
	numBlocks := (uint64(len(src)) + blockSize - 1) / blockSize
	if c.overflow || uint64(c.counter)+numBlocks > 1<<32 {
		panic("chacha20: counter overflow")
	} else if uint64(c.counter)+numBlocks == 1<<32 {
		c.overflow = true
	}

	// CUSTOM: fast reseeding.
	c.buf = [bufSize]byte{}
	copy(c.buf[:], src)
	c.xorKeyStreamBlocksGeneric(c.buf[:blockSize], c.buf[:blockSize], &c.key)
	c.setKey(c.buf[:KeySize])
	copy(dst, c.buf[KeySize:blockSize])
	if len(src) <= blockSize-KeySize {
		c.remaining = blockSize - KeySize - len(src)
		copy(c.buf[bufSize-c.remaining:], c.buf[KeySize+len(src):blockSize]) // needed if bufSize > blockSize
		sliceutils.Fill(c.buf[:bufSize-c.remaining], 0)
		return
	} else {
		sliceutils.Fill(c.buf[:blockSize], 0)
		dst, src = dst[blockSize-KeySize:], src[blockSize-KeySize:]
	}

	// xorKeyStreamBlocks implementations expect input lengths that are a
	// multiple of bufSize. Platform-specific ones process multiple blocks at a
	// time, so have bufSizes that are a multiple of blockSize.

	full := len(src) - len(src)%bufSize
	if full > 0 {
		c.xorKeyStreamBlocks(dst[:full], src[:full], &c.Cipher.key)
	}
	dst, src = dst[full:], src[full:]

	// If using a multi-block xorKeyStreamBlocks would overflow, use the generic
	// one that does one block at a time.
	const blocksPerBuf = bufSize / blockSize
	if uint64(c.counter)+blocksPerBuf > 1<<32 {
		c.buf = [bufSize]byte{}
		numBlocks := (len(src) + blockSize - 1) / blockSize
		buf := c.buf[bufSize-numBlocks*blockSize:]
		copy(buf, src)
		c.xorKeyStreamBlocksGeneric(buf, buf, &c.Cipher.key)
		c.remaining = len(buf) - copy(dst, buf)
		sliceutils.Fill(buf, 0) // CUSTOM: erasure of keystream
		return
	}

	// If we have a partial (multi-)block, pad it for xorKeyStreamBlocks, and
	// keep the leftover keystream for the next XORKeyStream invocation.
	if len(src) > 0 {
		c.buf = [bufSize]byte{}
		copy(c.buf[:], src)
		c.xorKeyStreamBlocks(c.buf[:], c.buf[:], &c.Cipher.key)
		c.remaining = bufSize - copy(dst, c.buf[:])
		sliceutils.Fill(c.buf[:bufSize-c.remaining], 0) // CUSTOM: erasure of keystream
	}
}
