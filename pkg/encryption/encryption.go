package encryption

import (
	"io"

	"github.com/bronlabs/bron-crypto/pkg/base"
	"github.com/bronlabs/bron-crypto/pkg/base/algebra"
)

type (
	Name                        string
	Plaintext                   any
	Nonce                       any
	Ciphertext[C Ciphertext[C]] base.Equatable[C]
)

type NonceSampler[N Nonce] interface {
	SampleNonce(prng io.Reader) (N, error)
}

type encryptionKey[P Plaintext, N Nonce, C Ciphertext[C]] interface {
	NonceSampler[N]
	EncryptWithNonce(P, N) (C, error)
}

type EncryptionKey[EK EncryptionKey[EK, P, N, C], P Plaintext, N Nonce, C Ciphertext[C]] interface {
	encryptionKey[P, N, C]
	base.Equatable[EK]
}

type DecryptionKey[EK EncryptionKey[EK, P, N, C], DK DecryptionKey[EK, DK, P, N, C], P Plaintext, N Nonce, C Ciphertext[C]] interface {
	EncryptionKey[DK, P, N, C]
	Public() EK
	Decrypt(C) (P, error)
}

type OpeningKey[EK EncryptionKey[EK, P, N, C], OK OpeningKey[EK, OK, P, N, C], P Plaintext, N Nonce, C Ciphertext[C]] interface {
	DecryptionKey[EK, OK, P, N, C]
	Open(C) (P, N, error)
}

type Homomorphic[P Plaintext, N Nonce, C Ciphertext[C], S any] interface {
	NonceSampler[N]

	NonceOp(first, second N, rest ...N) (N, error)
	NonceOpInv(N) (N, error)
	NonceScalarOp(N, S) (N, error)

	PlaintextOp(first, second P, rest ...P) (P, error)
	PlaintextOpInv(P) (P, error)
	PlaintextScalarOp(P, S) (P, error)

	CiphertextOp(first, second C, rest ...C) (C, error)
	CiphertextOpInv(C) (C, error)
	CiphertextScalarOp(C, S) (C, error)

	ReRandomise(ciphertext C, nonceShift N) (C, error)
	Shift(C, P) (C, error)
}

type GroupHomomorphic[
	P interface {
		Plaintext
		base.Transparent[PV]
	}, PG algebra.FiniteGroup[PV], PV algebra.GroupElement[PV],
	N interface {
		Nonce
		base.Transparent[NV]
	}, NG algebra.FiniteGroup[NV], NV algebra.GroupElement[NV],
	C interface {
		Ciphertext[C]
		base.Transparent[CV]
	}, CG algebra.FiniteGroup[CV], CV algebra.GroupElement[CV],
	S any,
] interface {
	Homomorphic[P, N, C, S]

	// Representative maps a plaintext to its canonical representative in R, where R is a system of representatives
	// of cosets of N in C, where C is subgroup of valid ciphertexts in the Ciphertext group.
	// https://eprint.iacr.org/2010/501.pdf
	Representative(P) (C, error)
	// IdentityNoise returns an element of encryption-of-identity (N) subgroup.
	// https://eprint.iacr.org/2010/501.pdf
	IdentityNoise(N) (C, error)

	PlaintextGroup() PG
	NonceGroup() NG
	CiphertextGroup() CG
}

type HomomorphicEncryptionKey[EK HomomorphicEncryptionKey[EK, P, N, C, S], P Plaintext, N Nonce, C Ciphertext[C], S any] interface {
	EncryptionKey[EK, P, N, C]
	Homomorphic[P, N, C, S]
}

type HomomorphicDecryptionKey[EK HomomorphicEncryptionKey[EK, P, N, C, S], DK HomomorphicDecryptionKey[EK, DK, P, N, C, S], P Plaintext, N Nonce, C Ciphertext[C], S any] interface {
	DecryptionKey[EK, DK, P, N, C]
	HomomorphicEncryptionKey[DK, P, N, C, S]
}

type GroupHomomorphicEncryptionKey[
	EK GroupHomomorphicEncryptionKey[EK, P, PG, PV, N, NG, NV, C, CG, CV, S],
	P interface {
		Plaintext
		base.Transparent[PV]
	}, PG algebra.FiniteGroup[PV], PV algebra.GroupElement[PV],
	N interface {
		Nonce
		base.Transparent[NV]
	}, NG algebra.FiniteGroup[NV], NV algebra.GroupElement[NV],
	C interface {
		Ciphertext[C]
		base.Transparent[CV]
	}, CG algebra.FiniteGroup[CV], CV algebra.GroupElement[CV],
	S any,
] interface {
	HomomorphicEncryptionKey[EK, P, N, C, S]
	GroupHomomorphic[P, PG, PV, N, NG, NV, C, CG, CV, S]
}

type GroupHomomorphicDecryptionKey[
	EK GroupHomomorphicEncryptionKey[EK, P, PG, PV, N, NG, NV, C, CG, CV, S],
	DK GroupHomomorphicDecryptionKey[EK, DK, P, PG, PV, N, NG, NV, C, CG, CV, S],
	P interface {
		Plaintext
		base.Transparent[PV]
	}, PG algebra.FiniteGroup[PV], PV algebra.GroupElement[PV],
	N interface {
		Nonce
		base.Transparent[NV]
	}, NG algebra.FiniteGroup[NV], NV algebra.GroupElement[NV],
	C interface {
		Ciphertext[C]
		base.Transparent[CV]
	}, CG algebra.FiniteGroup[CV], CV algebra.GroupElement[CV],
	S any,
] interface {
	DecryptionKey[EK, DK, P, N, C]
	GroupHomomorphicEncryptionKey[DK, P, PG, PV, N, NG, NV, C, CG, CV, S]
}
