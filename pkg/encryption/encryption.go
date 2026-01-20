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
	Plaintext any

	Ciphertext[C any] base.Equatable[C]
	Nonce             any
)

type (
	KeyGenerator[SK PrivateKey[SK], PK PublicKey[PK]] interface {
		Generate(prng io.Reader) (SK, PK, error)
	}
	ExtendedKeyGenerator[SK PrivateKey[SK], PK PublicKey[PK]] interface {
		KeyGenerator[SK, PK]
		GenerateWithSeed(ikm []byte) (SK, PK, error)
	}

	KeyGeneratorOption[
		KG KeyGenerator[SK, PK], SK PrivateKey[SK], PK PublicKey[PK],
	] = func(KG) error
)

type (
	Encrypter[PK PublicKey[PK], M Plaintext, C Ciphertext[C], X any] interface {
		Encrypt(plaintext M, receiver PK, prng io.Reader) (ciphertext C, nonceOrCapsuleEtc X, err error)
	}

	LinearlyRandomisedEncrypter[PK PublicKey[PK], M Plaintext, C ReRandomisableCiphertext[C, N, PK], N Nonce] interface {
		Encrypter[PK, M, C, N]
		EncryptWithNonce(plaintext M, receiver PK, nonce N) (ciphertext C, err error)
	}

	SelfEncrypter[SK PrivateKey[SK], M Plaintext, C Ciphertext[C], X any] interface {
		PrivateKey() SK
		SelfEncrypt(plaintext M, prng io.Reader) (ciphertext C, nonceOrCapsuleEtc X, err error)
	}

	LinearlyRandomisedSelfEncrypter[SK PrivateKey[SK], PK PublicKey[PK], M Plaintext, C ReRandomisableCiphertext[C, N, PK], N Nonce] interface {
		SelfEncrypter[SK, M, C, N]
		SelfEncryptWithNonce(plaintext M, nonce N) (ciphertext C, err error)
	}

	EncrypterOption[
		ENC Encrypter[PK, M, C, X], PK PublicKey[PK], M Plaintext, C Ciphertext[C], X any,
	] = func(ENC) error
)

type (
	Decrypter[M Plaintext, C Ciphertext[C]] interface {
		Decrypt(ciphertext C) (plaintext M, err error)
	}

	DecrypterOption[
		DEC Decrypter[M, C], M Plaintext, C Ciphertext[C],
	] = func(DEC) error
)

type Scheme[
	SK PrivateKey[SK], PK PublicKey[PK], M Plaintext, C Ciphertext[C], N Nonce,
	KG KeyGenerator[SK, PK], ENC Encrypter[PK, M, C, N], DEC Decrypter[M, C],
] interface {
	Name() Name
	Keygen(...KeyGeneratorOption[KG, SK, PK]) (KG, error)
	Encrypter(...EncrypterOption[ENC, PK, M, C, N]) (ENC, error)
	Decrypter(SK, ...DecrypterOption[DEC, M, C]) (DEC, error)
}

// ******** Homomorphic.

type ReRandomisableCiphertext[C Ciphertext[C], N Nonce, PK PublicKey[PK]] interface {
	Ciphertext[C]
	ReRandomise(PK, io.Reader) (C, N, error)
	ReRandomiseWithNonce(PK, N) (C, error)
}

type HomomorphicCiphertext[C Ciphertext[C], CV algebra.MonoidElement[CV], S algebra.NatLike[S]] interface {
	Ciphertext[C]
	algebra.HomomorphicLike[C, CV]
	algebra.Actable[C, S]
}

type ShiftTypeCiphertext[
	C Ciphertext[C], CV algebra.GroupElement[CV],
	M Plaintext, PK PublicKey[PK], N Nonce, S algebra.NatLike[S],
] interface {
	HomomorphicCiphertext[C, CV, S]
	ReRandomisableCiphertext[C, N, PK]
	Shift(PK, M) (C, error)
}

type HomomorphicPlaintext[M Plaintext, MV algebra.SemiGroupElement[MV]] interface {
	Plaintext
	algebra.HomomorphicLike[M, MV]
}

type HomomorphicScheme[
	SK PrivateKey[SK], PK PublicKey[PK],
	M HomomorphicPlaintext[M, MV], MV algebra.SemiGroupElement[MV],
	C HomomorphicCiphertext[C, CV, S], CV algebra.MonoidElement[CV],
	N interface {
		Nonce
		algebra.HomomorphicLike[N, NV]
	}, NV algebra.SemiGroupElement[NV],
	KG KeyGenerator[SK, PK], ENC Encrypter[PK, M, C, N], DEC Decrypter[M, C], S algebra.NatLike[S],
] Scheme[SK, PK, M, C, N, KG, ENC, DEC]

type GroupHomomorphicScheme[
	SK PrivateKey[SK], PK PublicKey[PK],
	M HomomorphicPlaintext[M, MV], MV algebra.GroupElement[MV],
	C ShiftTypeCiphertext[C, CV, M, PK, N, S], CV algebra.GroupElement[CV],
	N interface {
		Nonce
		algebra.HomomorphicLike[N, NV]
	}, NV algebra.GroupElement[NV],
	KG KeyGenerator[SK, PK], ENC LinearlyRandomisedEncrypter[PK, M, C, N], DEC Decrypter[M, C], S algebra.NatLike[S],
] HomomorphicScheme[SK, PK, M, MV, C, CV, N, NV, KG, ENC, DEC, S]
