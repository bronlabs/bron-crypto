package encryption

import (
	"io"

	"github.com/bronlabs/bron-crypto/pkg/base"
	"github.com/bronlabs/bron-crypto/pkg/base/algebra"
)

type (
	// Name identifies an encryption scheme implementation.
	Name string
	// Plaintext is the message being encrypted; its concrete type is scheme-defined.
	Plaintext any
	// Nonce is the secret per-encryption randomness. It must be freshly sampled for
	// each encryption: reusing a nonce under the same key generally breaks security.
	Nonce any
	// Ciphertext is the public, opaque encryption output. The self-referential type
	// parameter makes it Equatable so ciphertexts can be compared for equality.
	Ciphertext[C Ciphertext[C]] base.Equatable[C]
)

// NonceSampler samples the per-encryption randomness (nonce). Hiding relies on the
// nonce being fresh and unpredictable, so prng must be a cryptographically secure
// source.
type NonceSampler[N Nonce] interface {
	SampleNonce(prng io.Reader) (N, error)
}

// encryptionKey is the minimal capability shared by encryption keys: sampling a
// nonce and deterministically encrypting a plaintext under it.
type encryptionKey[P Plaintext, N Nonce, C Ciphertext[C]] interface {
	NonceSampler[N]
	EncryptWithNonce(P, N) (C, error)
}

// EncryptionKey is a public encryption key. It names its scheme (Type), samples
// fresh nonces, and deterministically encrypts a plaintext under a caller-chosen
// nonce (EncryptWithNonce); it is also comparable. Determinism in the nonce lets a
// verifier recompute a ciphertext, but security still requires the nonce to be
// freshly sampled and kept secret.
type EncryptionKey[EK EncryptionKey[EK, P, N, C], P Plaintext, N Nonce, C Ciphertext[C]] interface { //nolint:revive // prefixing "Encryption" for readability.
	Type() Name
	encryptionKey[P, N, C]
	base.Equatable[EK]
}

// DecryptionKey is a private key: it does everything an EncryptionKey does and can
// additionally recover the plaintext (Decrypt) and export the matching public key
// (Public). Possessing it is what breaks the hiding of any ciphertext under this key.
type DecryptionKey[EK EncryptionKey[EK, P, N, C], DK DecryptionKey[EK, DK, P, N, C], P Plaintext, N Nonce, C Ciphertext[C]] interface {
	EncryptionKey[DK, P, N, C]
	Public() EK
	Decrypt(C) (P, error)
}

// OpeningKey is a private key that can additionally recover the encryption nonce,
// not just the plaintext — Open returns both. This stronger capability is used by
// simulators and to make encryption-based commitments extractable.
type OpeningKey[EK EncryptionKey[EK, P, N, C], OK OpeningKey[EK, OK, P, N, C], P Plaintext, N Nonce, C Ciphertext[C]] interface {
	DecryptionKey[EK, OK, P, N, C]
	Open(C) (P, N, error)
}

// Homomorphic describes an encryption scheme whose plaintexts, nonces, and
// ciphertexts each carry an algebraic operation under which encryption is a
// homomorphism: combining ciphertexts corresponds to combining the underlying
// plaintexts and nonces. This allows computing on ciphertexts — aggregation, scalar
// weighting, re-randomisation, and plaintext shifting — without decrypting. S is the
// scalar type for the ScalarOp variants.
type Homomorphic[P Plaintext, N Nonce, C Ciphertext[C], S any] interface {
	NonceSampler[N]

	// NonceOp combines nonces; the result is the nonce of the CiphertextOp of the
	// corresponding ciphertexts.
	NonceOp(first, second N, rest ...N) (N, error)
	// NonceOpInv returns the inverse nonce, matching CiphertextOpInv.
	NonceOpInv(N) (N, error)
	// NonceScalarOp scales a nonce by a scalar, matching CiphertextScalarOp.
	NonceScalarOp(N, S) (N, error)

	// PlaintextOp combines plaintexts; a ciphertext of the result equals the
	// CiphertextOp of the individual ciphertexts.
	PlaintextOp(first, second P, rest ...P) (P, error)
	// PlaintextOpInv returns the inverse plaintext, matching CiphertextOpInv.
	PlaintextOpInv(P) (P, error)
	// PlaintextScalarOp scales a plaintext by a scalar, matching CiphertextScalarOp.
	PlaintextScalarOp(P, S) (P, error)

	// CiphertextOp combines ciphertexts; by the homomorphism the result encrypts the
	// combined plaintext under the combined nonce.
	CiphertextOp(first, second C, rest ...C) (C, error)
	// CiphertextOpInv returns the inverse ciphertext (inverse plaintext and nonce).
	CiphertextOpInv(C) (C, error)
	// CiphertextScalarOp scales a ciphertext, scaling both the plaintext and nonce.
	CiphertextScalarOp(C, S) (C, error)

	// ReRandomise blinds a ciphertext with nonceShift, producing a fresh,
	// unlinkable encryption of the SAME plaintext.
	ReRandomise(ciphertext C, nonceShift N) (C, error)
	// Shift combines the encrypted plaintext with another plaintext under the SAME
	// nonce, without decrypting.
	Shift(C, P) (C, error)
}

// GroupHomomorphic refines Homomorphic for schemes built from the GIFT framework,
// where the plaintext, nonce, and ciphertext spaces are explicit finite groups and
// every ciphertext factors as Representative(plaintext) · IdentityNoise(nonce). It
// exposes those groups and the two structural maps.
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

	// PlaintextGroup returns the group in which plaintexts live.
	PlaintextGroup() PG
	// NonceGroup returns the group from which nonces are drawn.
	NonceGroup() NG
	// CiphertextGroup returns the group in which ciphertexts live.
	CiphertextGroup() CG
}

type homomorphicEncryptionKey[P Plaintext, N Nonce, C Ciphertext[C], S any] interface {
	encryptionKey[P, N, C]
	Homomorphic[P, N, C, S]
}

// HomomorphicEncryptionKey is an EncryptionKey whose scheme is also Homomorphic.
type HomomorphicEncryptionKey[EK HomomorphicEncryptionKey[EK, P, N, C, S], P Plaintext, N Nonce, C Ciphertext[C], S any] interface {
	EncryptionKey[EK, P, N, C]
	homomorphicEncryptionKey[P, N, C, S]
}

// HomomorphicDecryptionKey is a DecryptionKey whose scheme is also Homomorphic: it
// can decrypt and also combine ciphertexts homomorphically.
type HomomorphicDecryptionKey[EK HomomorphicEncryptionKey[EK, P, N, C, S], DK HomomorphicDecryptionKey[EK, DK, P, N, C, S], P Plaintext, N Nonce, C Ciphertext[C], S any] interface {
	DecryptionKey[EK, DK, P, N, C]
	HomomorphicEncryptionKey[DK, P, N, C, S]
}

// GroupHomomorphicEncryptionKey is a HomomorphicEncryptionKey whose plaintext,
// nonce, and ciphertext spaces are exposed as explicit finite groups (GIFT).
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

// GroupHomomorphicDecryptionKey is a DecryptionKey that is also a
// GroupHomomorphicEncryptionKey.
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
