package types

import (
	"sort"

	"github.com/cronokirby/saferith"
	"golang.org/x/exp/constraints"

	ds "github.com/bronlabs/bron-crypto/pkg/base/datastructures"
	"github.com/bronlabs/bron-crypto/pkg/base/datastructures/bimap"
	"github.com/bronlabs/bron-crypto/pkg/base/datastructures/hashmap"
)

type IdentityKey interface {
	ds.Hashable[IdentityKey]

	String() string
	PublicKeyBytes() []byte

	Verify(signature []byte, message []byte) error

	Encrypt(plaintext []byte, opts any) ([]byte, error)
	EncryptFrom(sender AuthKey, plaintext []byte, opts any) ([]byte, error)
}

type AuthKey interface {
	IdentityKey
	Sign(message []byte) ([]byte, error)

	Decrypt(ciphertext []byte) ([]byte, error)
	DecryptFrom(sender IdentityKey, ciphertext []byte) ([]byte, error)
}

type ByPublicKey []IdentityKey

func (k ByPublicKey) Len() int {
	return len(k)
}

func (k ByPublicKey) Less(i, j int) bool {
	lhs := new(saferith.Nat).SetBytes(k[i].PublicKeyBytes())
	rhs := new(saferith.Nat).SetBytes(k[j].PublicKeyBytes())
	_, _, less := lhs.Cmp(rhs)
	return less != 0
}

func (k ByPublicKey) Swap(i, j int) {
	k[i], k[j] = k[j], k[i]
}

type AbstractIdentitySpace[Index constraints.Integer] ds.BiMap[Index, IdentityKey]

func NewAbstractIdentitySpace[Index constraints.Integer](identityKeys ds.Set[IdentityKey]) AbstractIdentitySpace[Index] {
	sortedIdentityKeys := ByPublicKey(identityKeys.List())
	sort.Sort(sortedIdentityKeys)
	idToKey := hashmap.NewComparableHashMap[Index, IdentityKey]()
	keyToId := hashmap.NewHashableHashMap[IdentityKey, Index]()
	indexedIdentities, _ := bimap.NewBiMap(idToKey, keyToId)

	for indexMinusOne, identityKey := range sortedIdentityKeys {
		index := Index(indexMinusOne + 1)
		indexedIdentities.Put(index, identityKey)
	}
	return indexedIdentities
}

type IdentitySpace AbstractIdentitySpace[uint]

func NewIdentitySpace(identityKeys ds.Set[IdentityKey]) IdentitySpace {
	return NewAbstractIdentitySpace[uint](identityKeys)
}
