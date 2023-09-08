package bip340

import (
	"crypto/sha256"
	"hash"

	"github.com/copperexchange/knox-primitives/pkg/base/errs"
)

const (
	auxTag       = "BIP0340/aux"
	nonceTag     = "BIP0340/nonce"
	challengeTag = "BIP0340/challenge"
)

type hasher struct {
	hash.Hash
	tag          string
	sha256Hasher hash.Hash
}

var _ hash.Hash = (*hasher)(nil)

func NewBip340Hash(tag string) hash.Hash {
	bip340Hash := &hasher{
		tag:          tag,
		sha256Hasher: sha256.New(),
	}

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

func (h *hasher) Sum(b []byte) []byte {
	return h.sha256Hasher.Sum(b)
}

func (h *hasher) Reset() {
	tagDigest := sha256.Sum256([]byte(h.tag))
	h.sha256Hasher.Reset()
	h.sha256Hasher.Write(tagDigest[:])
	h.sha256Hasher.Write(tagDigest[:])
}

func (h *hasher) Size() int {
	return h.sha256Hasher.Size()
}

func (h *hasher) BlockSize() int {
	return h.sha256Hasher.BlockSize()
}

func (h *hasher) Write(p []byte) (n int, err error) {
	n, err = h.sha256Hasher.Write(p)
	if err != nil {
		return 0, errs.NewFailed("cannot create digest")
	}
	return n, nil
}
