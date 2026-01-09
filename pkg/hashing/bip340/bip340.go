package bip340

import (
	"crypto/sha256"
	"hash"
)

const (
	auxTag       = "BIP0340/aux"
	nonceTag     = "BIP0340/nonce"
	challengeTag = "BIP0340/challenge"
)

// Hasher implements the BIP-340 tagged hash scheme using SHA-256.
// It prefixes the hash with SHA256(tag) || SHA256(tag) as specified in BIP-340.
type Hasher struct {
	hash.Hash

	tag string
}

var _ hash.Hash = (*Hasher)(nil)

// NewBip340Hash creates a new BIP-340 tagged hash with the given tag string.
func NewBip340Hash(tag string) hash.Hash {
	bip340Hash := &Hasher{sha256.New(), tag}
	bip340Hash.Reset()
	return bip340Hash
}

// NewBip340HashAux creates a new BIP-340 tagged hash for auxiliary randomness.
func NewBip340HashAux() hash.Hash {
	return NewBip340Hash(auxTag)
}

// NewBip340HashNonce creates a new BIP-340 tagged hash for nonce generation.
func NewBip340HashNonce() hash.Hash {
	return NewBip340Hash(nonceTag)
}

// NewBip340HashChallenge creates a new BIP-340 tagged hash for challenge computation.
func NewBip340HashChallenge() hash.Hash {
	return NewBip340Hash(challengeTag)
}

// Reset resets the hash to its initial state with the tag prefix applied.
func (h *Hasher) Reset() {
	tagDigest := sha256.Sum256([]byte(h.tag))
	h.Hash.Reset()
	_, _ = h.Write(tagDigest[:])
	_, _ = h.Write(tagDigest[:])
}
