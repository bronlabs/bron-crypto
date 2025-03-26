package types

import (
	"encoding"

	"github.com/bronlabs/bron-crypto/pkg/base/algebra"
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

type OpaquePrivateKey[SK SchemeElement[T], PK OpaquePublicKey[PK, T], T ~string] interface {
	OpaqueKey
	SchemeElement[T]
	ds.Clonable[SK]
	ds.Equatable[SK]
	Public() PK
	encoding.BinaryMarshaler
	encoding.BinaryUnmarshaler
}

type TransparentPrivateKey[SK OpaquePrivateKey[SK, PK, T], SKV algebra.Element[SKV], PK OpaquePublicKey[PK, T], T ~string] interface {
	OpaquePrivateKey[SK, PK, T]
	TransparentKey[SKV]
}

type OpaquePublicKey[PK SchemeElement[T], T ~string] interface {
	OpaqueKey
	SchemeElement[T]
	ds.Clonable[PK]
	ds.Equatable[PK]
	encoding.BinaryMarshaler
	encoding.BinaryUnmarshaler
}

type TransparentPublicKey[PK OpaquePublicKey[PK, T], PKV algebra.Element[PKV], T ~string] interface {
	OpaquePublicKey[PK, T]
	TransparentKey[PKV]
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
