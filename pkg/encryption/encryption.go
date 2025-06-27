package encryption

import (
	"io"

	"github.com/bronlabs/bron-crypto/pkg/base"
	"github.com/bronlabs/bron-crypto/pkg/base/algebra"
)

type Name string

type (
	PrivateKey[SK any] base.Equatable[SK]

	PublicKey[PK any] interface {
		base.Clonable[PK]
		base.Hashable[PK]
	}
	Plaintext                   any
	PlaintextCodec[P Plaintext] struct {
		Encoder func([]byte) (P, error)
		Decoder func(P) ([]byte, error)
	}

	Ciphertext any
	Nonce      any

	ReRandomisableCiphertext[C Ciphertext, N Nonce, PK PublicKey[PK]] interface {
		ReRandomiseWithNonce(PK, N) (C, error)
		ReRandomise(PK, io.Reader) (C, N, error)
	}
)

type KeyGenerator[SK PrivateKey[SK], PK PublicKey[PK]] interface {
	Generate(prng io.Reader) (SK, PK, error)
}

type ExtendedKeyGenerator[SK PrivateKey[SK], PK PublicKey[PK]] interface {
	KeyGenerator[SK, PK]
	GenerateWithSeed(ikm []byte) (SK, PK, error)
}

type Encrypter[PK PublicKey[PK], M Plaintext, C Ciphertext, X any] interface {
	Encrypt(plaintext M, receiver PK, prng io.Reader) (ciphertext C, nonceOrCapsuleEtc X, err error)
}

type LinearlyRandomisedEncrypter[PK PublicKey[PK], M Plaintext, C ReRandomisableCiphertext[C, N, PK], N Nonce] interface {
	Encrypter[PK, M, C, N]
	EncryptWithNonce(plaintext M, receiver PK, nonce N, prng io.Reader) (ciphertext C, err error)
}

type Decrypter[M Plaintext, C Ciphertext] interface {
	Decrypt(ciphertext C) (plaintext M, err error)
}

type LinearlyRandomisedDecrypter[PK PublicKey[PK], M Plaintext, C ReRandomisableCiphertext[C, N, PK], N Nonce] interface {
	Decrypter[M, C]
	DecryptWithNonce(ciphertext C, nonce N) (plaintext M, err error)
}
type Scheme[
	SK PrivateKey[SK], PK PublicKey[PK], M Plaintext, C Ciphertext, N Nonce,
	KG KeyGenerator[SK, PK], ENC Encrypter[PK, M, C, N], DEC Decrypter[M, C],
] interface {
	Name() Name
	Keygen(...func(KG) error) (KG, error)
	Encrypter(...func(ENC) error) (ENC, error)
	Decrypter(SK, ...func(DEC) error) (DEC, error)
}

// ******** Homomorphic

type HomomorphicScheme[
	SK PrivateKey[SK], PK PublicKey[PK],
	M interface {
		Plaintext
		algebra.HomomorphicLike[M, MV]
	}, MV algebra.GroupElement[MV],
	C interface {
		Ciphertext
		algebra.HomomorphicLike[C, CV]
		algebra.Actable[C, M]
	}, CV algebra.GroupElement[CV],
	N interface {
		Nonce
		algebra.HomomorphicLike[N, NV]
	}, NV algebra.GroupElement[NV],
	KG KeyGenerator[SK, PK], ENC Encrypter[PK, M, C, N], DEC Decrypter[M, C],
] Scheme[SK, PK, M, C, N, KG, ENC, DEC]
