package kmac

import (
	"encoding/binary"
	"hash"
	"slices"

	"golang.org/x/crypto/sha3"

	"github.com/bronlabs/bron-crypto/pkg/base/errs2"
)

const (
	// See [1] (Sec 8.4.2).
	minimumTagSize = 8
)

// ErrInvalidKeyLength is returned when the key length does not meet the security strength requirements.
var ErrInvalidKeyLength = errs2.New("invalid key length")

// ErrInvalidTagSize is returned when the tag size is smaller than the minimum allowed.
var ErrInvalidTagSize = errs2.New("invalid tag size")

var _ hash.Hash = (*kmac)(nil)

type kmac struct {
	sha3.ShakeHash // cSHAKE context and Read/Write operations

	tagSize int // tag size

	// initBlock is the KMAC specific initialization set of bytes. It is initialised
	// by newKMAC function and stores the key, encoded by the method specified in 3.3 of [1].
	// It is stored here in order for Reset() to be able to put context into
	// initial state.
	initBlock []byte
}

// Bytepad pads the input to a multiple of w bytes as specified in NIST SP 800-185.
func Bytepad(input []byte, w int) []byte {
	buf := LeftEncode(uint64(w))
	buf = slices.Concat(buf, input)
	padlen := w - (len(buf) % w)
	return slices.Concat(buf, make([]byte, padlen))
}

// LeftEncode encodes a non-negative integer with the length prefix on the left as specified in NIST SP 800-185.
func LeftEncode(value uint64) []byte {
	var b [9]byte
	binary.BigEndian.PutUint64(b[1:], value)
	// Trim all but last leading zero bytes
	i := byte(1)
	for i < 8 && b[i] == 0 {
		i++
	}
	// Prepend number of encoded bytes
	b[i-1] = 9 - i
	return b[i-1:]
}

// RightEncode encodes a non-negative integer with the length suffix on the right as specified in NIST SP 800-185.
func RightEncode(value uint64) []byte {
	var b [9]byte
	binary.BigEndian.PutUint64(b[:8], value)
	// Trim all but last leading zero bytes
	i := byte(0)
	for i < 7 && b[i] == 0 {
		i++
	}
	// Append number of encoded bytes
	b[8] = 8 - i
	return b[i:]
}

// AbsorbPaddedKey creates a KMAC instance by absorbing the padded key into the cSHAKE state.
func AbsorbPaddedKey(key []byte, tagSize int, c sha3.ShakeHash) hash.Hash {
	k := &kmac{ShakeHash: c, tagSize: tagSize}
	// absorb bytepad(encode_string(K), rate) into the internal state
	k.initBlock = LeftEncode(uint64(len(key) * 8))
	k.initBlock = slices.Concat(k.initBlock, key)
	k.Write(Bytepad(k.initBlock, k.BlockSize()))
	return k
}

// NewKMAC128 creates a new KMAC providing 128 bits of security.
func NewKMAC128(key []byte, tagSize int, customizationString []byte) (hash.Hash, error) {
	if len(key) < 16 {
		return nil, ErrInvalidKeyLength.WithMessage("key length must not be smaller than 128-bit security strength")
	}
	if tagSize < minimumTagSize {
		return nil, ErrInvalidTagSize.WithMessage("tag size must be at least %d bytes", minimumTagSize)
	}

	c := sha3.NewCShake128([]byte("KMAC"), customizationString)
	return AbsorbPaddedKey(key, tagSize, c), nil
}

// NewKMAC256 creates a new KMAC providing 256 bits of security.
func NewKMAC256(key []byte, tagSize int, customizationString []byte) (hash.Hash, error) {
	if len(key) < 32 {
		return nil, ErrInvalidKeyLength.WithMessage("key length must not be smaller than 256-bit security strength")
	}
	if tagSize < minimumTagSize {
		return nil, ErrInvalidTagSize.WithMessage("tag size must be at least %d bytes", minimumTagSize)
	}

	c := sha3.NewCShake256([]byte("KMAC"), customizationString)
	return AbsorbPaddedKey(key, tagSize, c), nil
}

func (k *kmac) Reset() {
	k.ShakeHash.Reset()
	k.Write(Bytepad(k.initBlock, k.BlockSize()))
}

func (k *kmac) Size() int {
	return k.tagSize
}

func (k *kmac) Sum(b []byte) []byte {
	clone := k.Clone()
	// absorb right_encode(L)
	clone.Write(RightEncode(uint64(k.tagSize * 8)))

	// squeeze tagSize bytes
	tag := make([]byte, k.tagSize)
	if _, err := clone.Read(tag); err != nil {
		return nil
	}

	return slices.Concat(b, tag)
}
