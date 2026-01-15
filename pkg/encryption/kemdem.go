package encryption

import (
	"crypto/cipher"
	"io"

	"github.com/bronlabs/bron-crypto/pkg/base/ct"
	"github.com/bronlabs/bron-crypto/pkg/base/errs2"
)

type Capsule any
type (
	KEM[PK PublicKey[PK], C Capsule] interface {
		Encapsulate(receiver PK, prng io.Reader) (*SymmetricKey, C, error)
		IsAuthenticated() bool
	}

	KEMOption[
		KM KEM[PK, C], PK PublicKey[PK], C Capsule,
	] = func(KM) error
)

type (
	DEM[C Capsule] interface {
		Decapsulate(capsule C) (*SymmetricKey, error)
		IsAuthenticated() bool
	}

	DEMOption[
		DM DEM[C], C Capsule,
	] = func(DM) error
)

type HybridEncrypter[
	PK PublicKey[PK],
	M Plaintext,
	C Ciphertext,
	U Capsule,
] interface {
	Encrypter[PK, M, C, U]
	Seal(plaintext M, receiver PK, aad []byte, prng io.Reader) (C, U, error)
}

type HybridDecrypter[
	M Plaintext,
	C Ciphertext,
] interface {
	Decrypter[M, C]
	Open(ciphertext C, aad []byte) (M, error)
}

type HybridScheme[
	SK PrivateKey[SK],
	PK PublicKey[PK],
	M Plaintext,
	C Ciphertext,
	U Capsule,
	KG KeyGenerator[SK, PK],
	KM KEM[PK, U],
	DM DEM[U],
	ENC HybridEncrypter[PK, M, C, U],
	DEC HybridDecrypter[M, C],
] interface {
	Scheme[SK, PK, M, C, U, KG, ENC, DEC]
	KEM(...KEMOption[KM, PK, U]) (KM, error)
	DEM(SK, ...DEMOption[DM, U]) (DM, error)
}

type AEADBasedHybridScheme[
	SK PrivateKey[SK],
	PK PublicKey[PK],
	M ~[]byte,
	C ~[]byte,
	U Capsule,
	KG KeyGenerator[SK, PK],
	KM KEM[PK, U],
	DM DEM[U],
	ENC HybridEncrypter[PK, M, C, U],
	DEC HybridDecrypter[M, C],
] interface {
	HybridScheme[SK, PK, M, C, U, KG, KM, DM, ENC, DEC]
	AEAD(*SymmetricKey) (cipher.AEAD, error)
}

func NewSymmetricKey(v []byte) (*SymmetricKey, error) {
	if len(v) == 0 {
		return nil, ErrInvalidKey.WithMessage("symmetric key cannot be empty")
	}
	if ct.SliceIsZero(v) == ct.True {
		return nil, ErrInvalidKey.WithMessage("symmetric key cannot be all zero")
	}
	key := make([]byte, len(v))
	copy(key, v)
	return &SymmetricKey{v: key}, nil
}

type SymmetricKey struct {
	v []byte
}

func (k *SymmetricKey) Bytes() []byte {
	return k.v
}

func (k *SymmetricKey) Equal(other *SymmetricKey) bool {
	if k == nil || other == nil {
		return k == other
	}
	return ct.SliceEqual(k.v, other.v) == ct.True
}

func (k *SymmetricKey) Clone() *SymmetricKey {
	v := make([]byte, len(k.v))
	copy(v, k.v)
	return &SymmetricKey{v: v}
}

var (
	ErrInvalidKey = errs2.New("invalid key")
)
