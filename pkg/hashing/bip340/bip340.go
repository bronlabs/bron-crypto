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

type Hasher struct {
	hash.Hash
	tag string
}

var _ hash.Hash = (*Hasher)(nil)

func NewBip340Hash(tag string) hash.Hash {
	bip340Hash := &Hasher{sha256.New(), tag}
	bip340Hash.Reset()
	return bip340Hash
}

func NewBip340HashAux() hash.Hash {
	return NewBip340Hash(auxTag)
}

func NewBip340HashNonce() hash.Hash {
	return NewBip340Hash(nonceTag)
}

func NewBip340HashChallenge() hash.Hash {
	return NewBip340Hash(challengeTag)
}

func (h *Hasher) Reset() {
	tagDigest := sha256.Sum256([]byte(h.tag))
	h.Hash.Reset()
	_, _ = h.Write(tagDigest[:])
	_, _ = h.Write(tagDigest[:])
}
