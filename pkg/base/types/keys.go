package types

import (
	"crypto/subtle"
	"encoding/binary"
	"encoding/json"
	"sort"

	"golang.org/x/exp/constraints"

	"github.com/copperexchange/krypton-primitives/pkg/base/curves"
	ds "github.com/copperexchange/krypton-primitives/pkg/base/datastructures"
	"github.com/copperexchange/krypton-primitives/pkg/base/datastructures/bimap"
	"github.com/copperexchange/krypton-primitives/pkg/base/datastructures/hashmap"
	"github.com/copperexchange/krypton-primitives/pkg/base/errs"
)

type IdentityKey interface {
	PublicKey() curves.Point
	Verify(signature []byte, message []byte) error
	ds.Hashable[IdentityKey]
	json.Marshaler
}

type WithIdentityKey interface {
	IdentityKey() IdentityKey
}

func ValidateIdentityKey(k IdentityKey) error {
	if k == nil {
		return errs.NewIsNil("input is nil")
	}
	if k.PublicKey() == nil {
		return errs.NewIsNil("public key")
	}
	if k.PublicKey().IsIdentity() {
		return errs.NewIsIdentity("public key")
	}
	return nil
}

type AuthKey interface {
	IdentityKey
	Sign(message []byte) []byte
	PrivateKey() curves.Scalar
}

type WithAuthKey interface {
	AuthKey() AuthKey
}

func ValidateAuthKey(k AuthKey) error {
	if k == nil {
		return errs.NewIsNil("input is nil")
	}
	if err := ValidateIdentityKey(k); err != nil {
		return errs.WrapValidation(err, "identity key")
	}
	sk := k.PrivateKey()
	if sk == nil {
		return errs.NewIsNil("private key")
	}
	if sk.IsZero() {
		return errs.NewIsZero("private key")
	}
	return nil
}

func AuthKeyIsDeterministic(k AuthKey) bool {
	message := []byte("Brazil Fifa 2002 team > all other teams")
	return subtle.ConstantTimeCompare(k.Sign(message), k.Sign(message)) == 1
}

type ByPublicKey []IdentityKey

func (l ByPublicKey) Len() int {
	return len(l)
}

func (l ByPublicKey) Less(i, j int) bool {
	iKey := binary.BigEndian.Uint64(l[i].PublicKey().ToAffineCompressed())
	jKey := binary.BigEndian.Uint64(l[j].PublicKey().ToAffineCompressed())
	return iKey < jKey
}

func (l ByPublicKey) Swap(i, j int) {
	l[i], l[j] = l[j], l[i]
}

type AbstractIdentitySpace[Index constraints.Integer] ds.BiMap[Index, IdentityKey]

func NewAbstractIdentitySpace[Index constraints.Integer](identityKeys ds.HashSet[IdentityKey]) AbstractIdentitySpace[Index] {
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

func NewIdentitySpace(identityKeys ds.HashSet[IdentityKey]) IdentitySpace {
	return NewAbstractIdentitySpace[uint](identityKeys)
}
