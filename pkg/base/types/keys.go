package types

import (
	"github.com/bronlabs/bron-crypto/pkg/base/algebra"
	ds "github.com/bronlabs/bron-crypto/pkg/base/datastructures"
)

type Key any
type Keychain[Name ~string, K Key] ds.Map[Name, K]

type SymmetricKey[K Key, T ~string] interface {
	Key
	Type() T
	Size() int
}

type PrivateKey[K Key, PK PublicKey[PK, T], T ~string] interface {
	Key
	SchemeElement[T]
	Public() PK
}

type DerivablePrivateKey[K PrivateKey[K, PK, T], PK PublicKey[PK, T], T ~string, PATH any] interface {
	PrivateKey[K, PK, T]
	DeriveKey(path PATH) (K, PK, error)
}

type PublicKey[PK algebra.Element[PK], T ~string] interface {
	Key
	SchemeElement[T]
	algebra.Element[PK]
}

type AlgebraicPrivateKey[K algebra.GroupElement[K], PK AlgebraicPublicKey[PK, T], T ~string] interface {
	PrivateKey[K, PK, T]
	algebra.GroupElement[K]
}

type AlgebraicPublicKey[PK algebra.GroupElement[PK], T ~string] interface {
	PublicKey[PK, T]
	algebra.GroupElement[PK]
}

type AdditivePrivateKey[K interface {
	AlgebraicPrivateKey[K, PK, T]
	algebra.AdditiveGroupElement[K]
}, PK AdditivePublicKey[PK, T], T ~string] interface {
	PrivateKey[K, PK, T]
	algebra.AdditiveGroupElement[K]
	DerivablePrivateKey[K, PK, T, algebra.AdditiveGroupElement[K]]
}

type AdditivePublicKey[PK interface {
	AlgebraicPublicKey[PK, T]
	algebra.AdditiveGroupElement[PK]
}, T ~string] interface {
	PublicKey[PK, T]
	algebra.AdditiveGroupElement[PK]
}
