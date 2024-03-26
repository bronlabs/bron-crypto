package cipher

import (
	"crypto/cipher"
)

// KeyedBlock is a cipher.Block that can be re-keyed without reallocation.
type KeyedBlock interface {
	// Inherit the methods of cipher.Block
	cipher.Block
	// Clone creates a copy of the internal state of the KeyedBlock.
	Clone() KeyedBlock
	// SetKey sets the key of the block cipher without reallocation.
	SetKey(key []byte) error
}
