package types

import (
	"github.com/bronlabs/bron-crypto/pkg/base/algebra/fields"
	"sort"

	"github.com/cronokirby/saferith"
	"golang.org/x/exp/constraints"

	"github.com/bronlabs/bron-crypto/pkg/base/curves"
	ds "github.com/bronlabs/bron-crypto/pkg/base/datastructures"
	"github.com/bronlabs/bron-crypto/pkg/base/datastructures/bimap"
	"github.com/bronlabs/bron-crypto/pkg/base/datastructures/hashmap"
)

type IdentityKey[P curves.Point[P, F, S], F fields.FiniteFieldElement[F], S fields.PrimeFieldElement[S]] interface {
	ds.Hashable[IdentityKey[P, F, S]]

	String() string
	PublicKey() P

	Verify(signature []byte, message []byte) error

	Encrypt(plaintext []byte, opts any) ([]byte, error)
	EncryptFrom(sender AuthKey[P, F, S], plaintext []byte, opts any) ([]byte, error)
}

type AuthKey[P curves.Point[P, F, S], F fields.FiniteFieldElement[F], S fields.PrimeFieldElement[S]] interface {
	IdentityKey[P, F, S]
	Sign(message []byte) ([]byte, error)

	Decrypt(ciphertext []byte) ([]byte, error)
	DecryptFrom(sender IdentityKey[P, F, S], ciphertext []byte) ([]byte, error)
}

type ByPublicKey[P curves.Point[P, F, S], F fields.FiniteFieldElement[F], S fields.PrimeFieldElement[S]] []IdentityKey[P, F, S]

func (k ByPublicKey[P, F, S]) Len() int {
	return len(k)
}

func (k ByPublicKey[P, F, S]) Less(i, j int) bool {
	lhs := new(saferith.Nat).SetBytes(k[i].PublicKey().ToAffineCompressed())
	rhs := new(saferith.Nat).SetBytes(k[j].PublicKey().ToAffineCompressed())
	_, _, less := lhs.Cmp(rhs)
	return less != 0
}

func (k ByPublicKey[P, F, S]) Swap(i, j int) {
	k[i], k[j] = k[j], k[i]
}

type AbstractIdentitySpace[Index constraints.Integer, P curves.Point[P, F, S], F fields.FiniteFieldElement[F], S fields.PrimeFieldElement[S]] ds.BiMap[Index, IdentityKey[P, F, S]]

func NewAbstractIdentitySpace[Index constraints.Integer, P curves.Point[P, F, S], F fields.FiniteFieldElement[F], S fields.PrimeFieldElement[S]](identityKeys ds.Set[IdentityKey[P, F, S]]) AbstractIdentitySpace[Index, P, F, S] {
	sortedIdentityKeys := ByPublicKey[P, F, S](identityKeys.List())
	sort.Sort(sortedIdentityKeys)
	idToKey := hashmap.NewComparableHashMap[Index, IdentityKey[P, F, S]]()
	keyToId := hashmap.NewHashableHashMap[IdentityKey[P, F, S], Index]()
	indexedIdentities, _ := bimap.NewBiMap(idToKey, keyToId)

	for indexMinusOne, identityKey := range sortedIdentityKeys {
		index := Index(indexMinusOne + 1)
		indexedIdentities.Put(index, identityKey)
	}
	return indexedIdentities
}

type IdentitySpace[P curves.Point[P, F, S], F fields.FiniteFieldElement[F], S fields.PrimeFieldElement[S]] AbstractIdentitySpace[uint, P, F, S]

func NewIdentitySpace[P curves.Point[P, F, S], F fields.FiniteFieldElement[F], S fields.PrimeFieldElement[S]](identityKeys ds.Set[IdentityKey[P, F, S]]) IdentitySpace[P, F, S] {
	return NewAbstractIdentitySpace[uint, P, F, S](identityKeys)
}
