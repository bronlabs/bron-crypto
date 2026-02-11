package kmac

import (
	"crypto/sha3"
	"encoding/binary"
	"hash"
	"slices"

	"github.com/bronlabs/errs-go/errs"
)

const (
	// See [1] (Sec 8.4.2).
	minimumTagSize = 8
)

// ErrInvalidKeyLength is returned when the key length does not meet the security strength requirements.
var (
	ErrInvalidKeyLength = errs.New("invalid key length")
	ErrInvalidTagSize   = errs.New("invalid tag size")
)

var _ hash.Hash = (*Kmac)(nil)

type Kmac struct {
	h *sha3.SHAKE // cSHAKE context and Read/Write operations

	tagSize int // tag size

	// initBlock is the KMAC-specific initialization set of bytes. It is initialised
	// by a newKMAC function and stores the key, encoded by the method specified in 3.3 of [1].
	// It is stored here in order for Reset() to be able to put context into
	//  the initial state.
	initBlock []byte
}

// NewKMAC128 creates a new KMAC providing 128 bits of security.
func NewKMAC128(key []byte, tagSize int, customizationString []byte) (*Kmac, error) {
	if len(key) < 16 {
		return nil, ErrInvalidKeyLength.WithMessage("key length must not be smaller than 128-bit security strength")
	}
	if tagSize < minimumTagSize {
		return nil, ErrInvalidTagSize.WithMessage("tag size must be at least %d bytes", minimumTagSize)
	}

	c := sha3.NewCSHAKE128([]byte("KMAC"), customizationString)
	return absorbPaddedKey(key, tagSize, c), nil
}

// NewKMAC256 creates a new KMAC providing 256 bits of security.
func NewKMAC256(key []byte, tagSize int, customizationString []byte) (*Kmac, error) {
	if len(key) < 32 {
		return nil, ErrInvalidKeyLength.WithMessage("key length must not be smaller than 256-bit security strength")
	}
	if tagSize < minimumTagSize {
		return nil, ErrInvalidTagSize.WithMessage("tag size must be at least %d bytes", minimumTagSize)
	}

	c := sha3.NewCSHAKE256([]byte("KMAC"), customizationString)
	return absorbPaddedKey(key, tagSize, c), nil
}

func (k *Kmac) Reset() {
	k.h.Reset()
	_, _ = k.h.Write(bytePad(k.initBlock, k.h.BlockSize()))
}

func (k *Kmac) Size() int {
	return k.tagSize
}

func (k *Kmac) Write(p []byte) (n int, err error) {
	//nolint:wrapcheck // intentional
	return k.h.Write(p)
}

func (k *Kmac) BlockSize() int {
	return k.h.BlockSize()
}

func (k *Kmac) Sum(b []byte) []byte {
	clone := *k.h
	// absorb right_encode(L)
	_, _ = clone.Write(rightEncode(uint64(k.tagSize * 8)))

	// squeeze tagSize bytes
	tag := make([]byte, k.tagSize)
	if _, err := clone.Read(tag); err != nil {
		return nil
	}

	return slices.Concat(b, tag)
}

// bytePad pads the input to a multiple of w bytes as specified in NIST SP 800-185.
func bytePad(input []byte, w int) []byte {
	buf := leftEncode(uint64(w))
	buf = slices.Concat(buf, input)
	padLen := w - (len(buf) % w)
	return slices.Concat(buf, make([]byte, padLen))
}

// leftEncode encodes a non-negative integer with the length prefix on the left as specified in NIST SP 800-185.
func leftEncode(value uint64) []byte {
	var b [9]byte
	binary.BigEndian.PutUint64(b[1:], value)
	// Trim all but the last leading zero bytes
	i := byte(1)
	for i < 8 && b[i] == 0 {
		i++
	}
	// Prepend number of encoded bytes
	b[i-1] = 9 - i
	return b[i-1:]
}

// rightEncode encodes a non-negative integer with the length suffix on the right as specified in NIST SP 800-185.
func rightEncode(value uint64) []byte {
	var b [9]byte
	binary.BigEndian.PutUint64(b[:8], value)
	// Trim all but the last leading zero bytes
	i := byte(0)
	for i < 7 && b[i] == 0 {
		i++
	}
	// Append number of encoded bytes
	b[8] = 8 - i
	return b[i:]
}

// absorbPaddedKey creates a KMAC instance by absorbing the padded key into the cSHAKE state.
func absorbPaddedKey(key []byte, tagSize int, c *sha3.SHAKE) *Kmac {
	// absorb bytepad(encode_string(K), rate) into the internal state
	initBlock := slices.Concat(leftEncode(uint64(len(key)*8)), key)
	k := &Kmac{h: c, tagSize: tagSize, initBlock: initBlock}
	_, _ = k.Write(bytePad(k.initBlock, k.BlockSize()))
	return k
}
