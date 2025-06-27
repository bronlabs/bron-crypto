package encryption

import (
	"crypto/cipher"
	"io"
)

type (
	Capsule      any
	SymmetricKey []byte
)

type KEM[PK PublicKey[PK], C Capsule] interface {
	Encapsulate(receiver PK, prng io.Reader) (SymmetricKey, C, error)
	Decapsulate(capsule C) (SymmetricKey, error)
	IsAuthenticated() bool
}

type HybridScheme[
	SK PrivateKey[SK],
	PK PublicKey[PK],
	M Plaintext,
	C Ciphertext,
	U Capsule,
	KG KeyGenerator[SK, PK],
	KM KEM[PK, U],
	ENC Encrypter[PK, M, C, U],
	DEC Decrypter[M, C],
] interface {
	Name() string
	KEM(...func(*KM) error) (KM, error)
	Keygen(...func(*KG) error) (KG, error)
	Encrypter(...func(*ENC) error) (ENC, error)
	Decrypter(SK, ...func(*DEC) error) (DEC, error)
}

type AEADBasedHybridScheme[
	SK PrivateKey[SK],
	PK PublicKey[PK],
	M ~[]byte,
	C ~[]byte,
	U Capsule,
	KG KeyGenerator[SK, PK],
	KM KEM[PK, U],
	ENC Encrypter[PK, M, C, U],
	DEC Decrypter[M, C],
] interface {
	HybridScheme[SK, PK, M, C, U, KG, KM, ENC, DEC]
	AEAD() cipher.AEAD
}
