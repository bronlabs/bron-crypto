package indcpa

import (
	"io"
)

type PlainText any
type Nonce any
type CipherText any
type Scalar any

type EncryptionKey[P PlainText, R Nonce, C CipherText] interface {
	RandomNonce(prng io.Reader) (nonce R, err error)
	EncryptWithNonce(plainText P, nonce R) (cipherText C, err error)
	Encrypt(plainText P, prng io.Reader) (cipherText C, nonce R, err error)

	CipherTextEqual(lhs, rhs C) bool
}

type DecryptionKey[P PlainText, R Nonce, C CipherText, PK EncryptionKey[P, R, C]] interface {
	ToEncryptionKey() (encryptionKey PK, err error)
	Decrypt(cipherText C) (plainText P, err error)
	Open(cipherText C) (plainText P, nonce R, err error)
}

type HomomorphicEncryptionKey[P PlainText, R Nonce, C CipherText, S Scalar] interface {
	EncryptionKey[P, R, C]

	PlainTextAdd(lhs, rhs P) (plainText P, err error)
	PlainTextSub(lhs, rhs P) (plainText P, err error)
	PlainTextNeg(lhs P) (plainText P, err error)
	PlainTextMul(lhs P, rhs S) (plainText P, err error)

	NonceAdd(lhs, rhs R) (nonce R, err error)
	NonceSub(lhs, rhs R) (nonce R, err error)
	NonceNeg(lhs R) (nonce R, err error)
	NonceMul(lhs R, rhs S) (nonce R, err error)

	CipherTextAdd(lhs, rhs C) (cipherText C, err error)
	CipherTextAddPlainText(lhs C, rhs P) (cipherText C, err error)
	CipherTextSub(lhs, rhs C) (cipherText C, err error)
	CipherTextSubPlainText(lhs C, rhs P) (cipherText C, err error)
	CipherTextNeg(lhs C) (cipherText C, err error)
	CipherTextMul(lhs C, rhs S) (cipherText C, err error)
}

type HomomorphicDecryptionKey[P PlainText, R Nonce, C CipherText, S Scalar, PK HomomorphicEncryptionKey[P, R, C, S]] interface {
	DecryptionKey[P, R, C, PK]
}
