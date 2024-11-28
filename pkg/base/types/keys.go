package types

import (
	"crypto/subtle"
	"encoding/json"
	"sort"

	"github.com/cronokirby/saferith"
	"golang.org/x/exp/constraints"

	"github.com/copperexchange/krypton-primitives/pkg/base"
	"github.com/copperexchange/krypton-primitives/pkg/base/curves"
	ds "github.com/copperexchange/krypton-primitives/pkg/base/datastructures"
	"github.com/copperexchange/krypton-primitives/pkg/base/datastructures/bimap"
	"github.com/copperexchange/krypton-primitives/pkg/base/datastructures/hashmap"
	"github.com/copperexchange/krypton-primitives/pkg/base/errs"
)

type IdentityKey interface {
	String() string
	PublicKey() curves.Point

	Verify(signature []byte, message []byte) error

	Encrypt(plaintext []byte, opts any) ([]byte, error)
	EncryptFrom(sender AuthKey, plaintext []byte, opts any) ([]byte, error)
	ds.Hashable[IdentityKey]
	json.Marshaler
}

func ValidateIdentityKey(k IdentityKey) error {
	if k == nil {
		return errs.NewIsNil("input is nil")
	}
	if k.PublicKey() == nil {
		return errs.NewIsNil("public key")
	}
	if k.PublicKey().IsAdditiveIdentity() {
		return errs.NewIsIdentity("public key")
	}
	if !k.PublicKey().IsInPrimeSubGroup() {
		return errs.NewValidation("Public Key not in the prime subgroup")
	}
	if curveSec := curves.ComputationalSecurity(k.PublicKey().Curve()); curveSec < base.ComputationalSecurity {
		return errs.NewCurve("Curve security (%d) below %d bits", curveSec, base.ComputationalSecurity)
	}
	return nil
}

type AuthKey interface {
	IdentityKey
	Sign(message []byte) ([]byte, error)

	Decrypt(ciphertext []byte) ([]byte, error)
	DecryptFrom(sender IdentityKey, ciphertext []byte) ([]byte, error)
}

func ValidateAuthKey(k AuthKey) error {
	if k == nil {
		return errs.NewIsNil("input is nil")
	}
	if err := ValidateIdentityKey(k); err != nil {
		return errs.WrapValidation(err, "identity key")
	}
	message := []byte("Brazil Fifa 2002 team > all other teams")
	signed, err := k.Sign(message)
	if err != nil {
		return errs.WrapValidation(err, "failed to sign")
	}
	if err := k.Verify(signed, message); err != nil {
		return errs.WrapValidation(err, "failed to verify")
	}
	if curveSec := curves.ComputationalSecurity(k.PublicKey().Curve()); curveSec < base.ComputationalSecurity {
		return errs.NewCurve("Curve security (%d) below %d bits", curveSec, base.ComputationalSecurity)
	}
	return nil
}

func AuthKeyIsDeterministic(k AuthKey) (bool, error) {
	message := []byte("Brazil Fifa 2002 team > all other teams")
	signFirst, err := k.Sign(message)
	if err != nil {
		return false, errs.WrapFailed(err, "failed to sign")
	}
	signSecond, err := k.Sign(message)
	if err != nil {
		return false, errs.WrapFailed(err, "failed to sign")
	}
	return subtle.ConstantTimeCompare(signFirst, signSecond) == 1, nil
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
