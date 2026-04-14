package elgamal

import (
	"io"

	"github.com/bronlabs/errs-go/errs"

	"github.com/bronlabs/bron-crypto/pkg/base/algebra"
	"github.com/bronlabs/bron-crypto/pkg/base/utils/algebrautils"
)

// KeyGeneratorOption configures a KeyGenerator.
type KeyGeneratorOption[E UnderlyingGroupElement[E, S], S algebra.UintLike[S]] = func(*KeyGenerator[E, S]) error

// KeyGenerator produces ElGamal key pairs (a, h = g^a) where a is sampled
// uniformly from Z/nZ \ {0}.
type KeyGenerator[E UnderlyingGroupElement[E, S], S algebra.UintLike[S]] struct {
	g  UnderlyingGroup[E, S]
	zn algebra.ZModLike[S]
}

// Generate samples a fresh key pair using randomness from prng.
// HAC 8.25: select random a ∈ [1, n−1], compute h = g^a.
func (kg *KeyGenerator[E, S]) Generate(prng io.Reader) (*PrivateKey[E, S], *PublicKey[E, S], error) {
	// SUMMARY: each entity creates a public key and a corresponding private key.
	// Each entity A should do the following:
	if kg == nil {
		return nil, nil, ErrIsNil.WithMessage("key generator")
	}
	// 8.25.1: Select an appropriate cyclic group G of order n, with generator α. (It is assumed here
	// that G is written multiplicatively.)
	alpha := kg.g.Generator()

	// 8.25.2: Select a random integer a, 1 ≤ a ≤ n − 1, and compute the group element α^a
	a, err := algebrautils.RandomNonIdentity(kg.zn, prng)
	if err != nil {
		return nil, nil, errs.Wrap(err).WithMessage("failed to generate private key value")
	}
	pkv := alpha.ScalarOp(a)
	// 8.25.3: A’s public key is (α, αa), together with a description of how to multiply elements in
	// G; A’s private key is a.
	pk, err := NewPublicKey(pkv)
	if err != nil {
		return nil, nil, errs.Wrap(err).WithMessage("failed to create public key from private key value")
	}
	sk, err := NewPrivateKey(kg.g, a)
	if err != nil {
		return nil, nil, errs.Wrap(err).WithMessage("failed to create private key")
	}
	return sk, pk, nil
}

// EncrypterOption configures an Encrypter.
type EncrypterOption[E UnderlyingGroupElement[E, S], S algebra.UintLike[S]] = func(*Encrypter[E, S]) error

// Encrypter encrypts plaintexts under a receiver's public key.
type Encrypter[E UnderlyingGroupElement[E, S], S algebra.UintLike[S]] struct {
	g  UnderlyingGroup[E, S]
	zn algebra.ZModLike[S]
}

// Encrypt produces c = (g^r, m · h^r) using a fresh random nonce r.
// The returned nonce should be discarded unless needed for proofs
// or re-randomisation.
func (B *Encrypter[E, S]) Encrypt(plaintext *Plaintext[E, S], receiver *PublicKey[E, S], prng io.Reader) (*Ciphertext[E, S], *Nonce[S], error) {
	// SUMMARY: B encrypts a message m for A, which A decrypts.
	// 8.26.1: Encryption. B should do the following:
	// 8.26.1.a: Obtain A’s authentic public key (α, αa).
	// 8.26.1.b: Represent the message as an element m of the group G.
	if B == nil || plaintext == nil || receiver == nil || prng == nil {
		return nil, nil, ErrIsNil.WithMessage("encrypter/plaintext/receiver/prng")
	}
	// 8.26.1.c: Select a random integer k, 1 ≤ k ≤ n − 1.
	nv, err := algebrautils.RandomNonIdentity(B.zn, prng)
	if err != nil {
		return nil, nil, errs.Wrap(err).WithMessage("failed to generate nonce value")
	}
	nonce, err := NewNonce(nv)
	if err != nil {
		return nil, nil, errs.Wrap(err).WithMessage("failed to create nonce")
	}
	// 8.26.1.d: Compute γ = α^k and δ = m · (α^a)^k.
	// 8.26.1.e: Send the ciphertext c = (γ,δ) to A.
	ciphertext, err := B.EncryptWithNonce(plaintext, receiver, nonce)
	if err != nil {
		return nil, nil, errs.Wrap(err).WithMessage("failed to encrypt plaintext")
	}
	return ciphertext, nonce, nil
}

// EncryptWithNonce produces c = (g^r, m · h^r) using the given nonce r.
// This is deterministic: the same (m, h, r) triple always yields the same
// ciphertext. Callers must never reuse a nonce across different messages
// under the same key — doing so leaks the plaintext ratio m₁ · m₂⁻¹.
func (B *Encrypter[E, S]) EncryptWithNonce(plaintext *Plaintext[E, S], receiver *PublicKey[E, S], nonce *Nonce[S]) (*Ciphertext[E, S], error) {
	// SUMMARY: B encrypts a message m for A, which A decrypts.
	// 8.26.1: Encryption. B should do the following:
	// 8.26.1.a: Obtain A’s authentic public key (α, αa).
	// 8.26.1.b: Represent the message as an element m of the group G.
	// 8.26.1.c: Select a random integer k, 1 ≤ k ≤ n − 1.
	if B == nil || plaintext == nil || receiver == nil || nonce == nil {
		return nil, ErrIsNil.WithMessage("encrypter/plaintext/receiver/nonce")
	}
	alpha := B.g.Generator()
	// 8.26.1.d: Compute γ = α^k and δ = m · (α^a)^k.
	gamma := alpha.ScalarOp(nonce.Value())
	delta := receiver.v.ScalarOp(nonce.Value()).Op(plaintext.Value())
	// 8.26.1.e: Send the ciphertext c = (γ,δ) to A.
	c, err := NewCiphertext(gamma, delta)
	if err != nil {
		return nil, errs.Wrap(err).WithMessage("failed to create ciphertext")
	}
	return c, nil
}

// DecrypterOption configures a Decrypter.
type DecrypterOption[E UnderlyingGroupElement[E, S], S algebra.UintLike[S]] = func(*Decrypter[E, S]) error

// Decrypter recovers plaintexts using the holder's private key.
type Decrypter[E UnderlyingGroupElement[E, S], S algebra.UintLike[S]] struct {
	sk *PrivateKey[E, S]
}

// Decrypt recovers the plaintext m from c = (γ, δ) by computing m = δ · γ^{−a}.
// HAC 8.26.2.
func (A *Decrypter[E, S]) Decrypt(ciphertext *Ciphertext[E, S]) (*Plaintext[E, S], error) {
	// SUMMARY: B encrypts a message m for A, which A decrypts
	// 8.26.2: Decryption. A should do the following:
	if A == nil || ciphertext == nil {
		return nil, ErrIsNil.WithMessage("decrypter/ciphertext")
	}
	cs := ciphertext.Value().Components()
	gamma, delta := cs[0], cs[1]
	// 8.26.2.a: Use the private key `a` to compute γ^a and then compute γ^−a.
	// 8.26.2.b: Recover the message m by computing δ · γ^−a.
	gammaToA := gamma.ScalarOp(A.sk.v)
	m := delta.Op(gammaToA.OpInv())
	return &Plaintext[E, S]{m}, nil
}
