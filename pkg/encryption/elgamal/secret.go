package elgamal

import (
	"io"

	"github.com/bronlabs/bron-crypto/pkg/base"
	"github.com/bronlabs/bron-crypto/pkg/base/algebra"
	"github.com/bronlabs/bron-crypto/pkg/base/serde"
	"github.com/bronlabs/bron-crypto/pkg/base/utils"
	"github.com/bronlabs/bron-crypto/pkg/base/utils/algebrautils"
	"github.com/bronlabs/bron-crypto/pkg/encryption"
	"github.com/bronlabs/bron-crypto/pkg/encryption/internal/gift"
	"github.com/bronlabs/errs-go/errs"
)

// Generate samples a fresh key pair using randomness from prng.
// HAC 8.25: select random a ∈ [1, n−1], compute h = g^a.
func SampleSecretKey[E FiniteCyclicGroupElement[E, S], S algebra.UintLike[S]](group FiniteCyclicGroup[E, S], prng io.Reader) (*SecretKey[E, S], error) {
	// SUMMARY: each entity creates a public key and a corresponding private key.
	// Each entity A should do the following:
	if group == nil || prng == nil {
		return nil, encryption.ErrIsNil.WithMessage("group and prng must not be nil")
	}
	zn := algebra.StructureMustBeAs[algebra.ZModLike[S]](group.ScalarStructure())
	// 8.25.1: Select an appropriate cyclic group G of order n, with generator α. (It is assumed here
	// that G is written multiplicatively.)
	alpha := group.Generator()
	// 8.25.2: Select a random integer a, 1 ≤ a ≤ n − 1, and compute the group element α^a
	a, err := algebrautils.RandomNonIdentity(zn, prng)
	if err != nil {
		return nil, errs.Wrap(err).WithMessage("failed to generate private key value")
	}
	// 8.25.3: A’s public key is (α, αa), together with a description of how to multiply elements in
	// G; A’s private key is a.
	out, err := NewSecretKey(alpha, a)
	if err != nil {
		return nil, errs.Wrap(err).WithMessage("failed to create secret key")
	}
	return out, nil
}

func NewSecretKey[E FiniteCyclicGroupElement[E, S], S algebra.UintLike[S]](g E, a S) (*SecretKey[E, S], error) {
	if utils.IsNil(g) || utils.IsNil(a) {
		return nil, encryption.ErrIsNil.WithMessage("generator and secret key value cannot be nil")
	}
	if g.IsOpIdentity() || !g.IsTorsionFree() {
		return nil, encryption.ErrSubGroupMembership.WithMessage("generator cannot be the identity element or have torsion")
	}
	if a.IsZero() {
		return nil, encryption.ErrFailed.WithMessage("secret key value cannot be zero")
	}
	if a.IsOne() {
		return nil, encryption.ErrFailed.WithMessage("secret key value cannot be one")
	}
	pub, err := NewPublicKey(g.ScalarOp(a))
	if err != nil {
		return nil, errs.Wrap(err).WithMessage("could not construct public key")
	}
	return &SecretKey[E, S]{
		PublicKey: *pub,
		a:         a,
	}, nil
}

type SecretKey[E FiniteCyclicGroupElement[E, S], S algebra.UintLike[S]] struct {
	PublicKey[E, S]
	a S
}

type secretKeyDTO[E FiniteCyclicGroupElement[E, S], S algebra.UintLike[S]] struct {
	G E `cbor:"g"`
	A S `cbor:"a"`
}

func (sk *SecretKey[E, S]) Public() *PublicKey[E, S] {
	return sk.PublicKey.Clone()
}

func (sk *SecretKey[E, S]) Decrypt(ciphertext *Ciphertext[E, S]) (*Plaintext[E, S], error) {
	// SUMMARY: B encrypts a message m for A, which A decrypts
	// 8.26.2: Decryption. A should do the following:
	if ciphertext == nil {
		return nil, encryption.ErrIsNil.WithMessage("ciphertext must not be nil")
	}
	cs := ciphertext.Value().Components()
	gamma, delta := cs[0], cs[1]
	// 8.26.2.a: Use the private key `a` to compute γ^a and then compute γ^−a.
	// 8.26.2.b: Recover the message m by computing δ · γ^−a.
	gammaToA := gamma.ScalarOp(sk.a)
	m := delta.Op(gammaToA.OpInv())
	return &Plaintext[E, S]{m}, nil
}

func (sk *SecretKey[E, S]) EncryptWithNonce(plaintext *Plaintext[E, S], nonce *Nonce[S]) (*Ciphertext[E, S], error) {
	if plaintext == nil || nonce == nil {
		return nil, encryption.ErrIsNil.WithMessage("plaintext and nonce must not be nil")
	}
	out, err := gift.Encrypt(sk, plaintext, nonce) // IdentityNoise is marginally faster when trapdoor is known, for some curves including k256.
	if err != nil {
		return nil, errs.Wrap(err).WithMessage("failed to encrypt plaintext with secret key")
	}
	return out, nil
}

func (sk *SecretKey[E, S]) IdentityNoise(nonce *Nonce[S]) (*Ciphertext[E, S], error) {
	if nonce == nil {
		return nil, encryption.ErrIsNil.WithMessage("nonce must not be nil")
	}
	r, err := sk.CiphertextGroup().New(
		sk.Generator().ScalarOp(nonce.v),
		sk.Generator().ScalarOp(nonce.v.Mul(sk.a)),
	)
	if err != nil {
		return nil, errs.Wrap(err).WithMessage("could not create identity noise ciphertext")
	}
	return &Ciphertext[E, S]{v: r}, nil
}

func (sk *SecretKey[E, S]) ReRandomise(ciphertext *Ciphertext[E, S], nonce *Nonce[S]) (*Ciphertext[E, S], error) {
	if ciphertext == nil || nonce == nil {
		return nil, encryption.ErrIsNil.WithMessage("ciphertext and nonce must not be nil")
	}
	out, err := gift.ReRandomise(sk, ciphertext, nonce)
	if err != nil {
		return nil, errs.Wrap(err).WithMessage("failed to re-randomise ciphertext with secret key")
	}
	return out, nil
}

func (sk *SecretKey[E, S]) H() E {
	return sk.h
}

func (sk *SecretKey[E, S]) Value() S {
	return sk.a
}

func (sk *SecretKey[E, S]) Equal(other *SecretKey[E, S]) bool {
	if sk == nil || other == nil {
		return sk == other
	}
	return sk.a.Equal(other.a) && sk.PublicKey.Equal(&other.PublicKey)
}

func (sk *SecretKey[E, S]) HashCode() base.HashCode {
	return sk.a.HashCode().Combine(sk.PublicKey.HashCode())
}

func (sk *SecretKey[E, S]) MarshalCBOR() ([]byte, error) {
	dto := &secretKeyDTO[E, S]{
		G: sk.Generator(),
		A: sk.a,
	}
	out, err := serde.MarshalCBOR(dto)
	if err != nil {
		return nil, errs.Wrap(err).WithMessage("could not marshal secret key")
	}
	return out, nil
}

func (sk *SecretKey[E, S]) UnmarshalCBOR(data []byte) error {
	dto, err := serde.UnmarshalCBOR[*secretKeyDTO[E, S]](data)
	if err != nil {
		return errs.Wrap(err).WithMessage("could not unmarshal secret key")
	}
	skk, err := NewSecretKey(dto.G, dto.A)
	if err != nil {
		return errs.Wrap(err).WithMessage("could not create secret key from unmarshalled data")
	}
	*sk = *skk
	return nil
}
