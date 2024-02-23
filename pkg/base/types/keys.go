package types

import (
	"crypto/subtle"
	"encoding/json"
	"sort"

	"github.com/cronokirby/saferith"
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
	lhs := new(saferith.Nat).SetBytes(l[i].PublicKey().ToAffineCompressed())
	rhs := new(saferith.Nat).SetBytes(l[j].PublicKey().ToAffineCompressed())
	_, _, less := lhs.Cmp(rhs)
	return less != 0
}

func (l ByPublicKey) Swap(i, j int) {
	l[i], l[j] = l[j], l[i]
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
