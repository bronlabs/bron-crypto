package types

import (
	"encoding"

	ds "github.com/bronlabs/bron-crypto/pkg/base/datastructures"
)

type Transparent[V any] interface {
	Value() V
}

type OpaqueKey any
type TransparentKey[V any] interface {
	OpaqueKey
	Transparent[V]
}

type Keychain[Name ~string, K TransparentKey[V], V any] ds.Map[Name, K]

// type SymmetricKey[K any, T ~string] interface {
// 	TransparentKey[K]
// 	SchemeElement[T]
// 	Size() int
// }

type PrivateKey[SK any, PK PublicKey[PK]] interface {
	OpaqueKey
	ds.Clonable[SK]
	ds.Equatable[SK]
	Public() PK
	encoding.BinaryMarshaler
	encoding.BinaryUnmarshaler
}

type PublicKey[PK any] interface {
	OpaqueKey
	ds.Clonable[PK]
	ds.Equatable[PK]
	encoding.BinaryMarshaler
	encoding.BinaryUnmarshaler
}

// type DerivablePrivateKey[SK PrivateKey[SK, PK, T], PK PublicKey[PK, T], T ~string, PATH any] interface {
// 	PrivateKey[SK, PK, T]
// 	DeriveKey(path PATH) (SK, PK, error)
// }

// type AdditivePrivateKey[SK interface {
// 	PrivateKey[SK, PK, T]
// 	algebra.AdditiveGroupElement[SK]
// }, PK AdditivePublicKey[PK, T], T ~string] interface {
// 	PrivateKey[SK, PK, T]
// 	algebra.AdditiveGroupElement[SK]
// 	DerivablePrivateKey[SK, PK, T, algebra.AdditiveGroupElement[SK]]
// }

// type AdditivePublicKey[PK interface {
// 	PublicKey[PK, T]
// 	algebra.AdditiveGroupElement[PK]
// }, T ~string] interface {
// 	PublicKey[PK, T]
// 	algebra.AdditiveGroupElement[PK]
// }
