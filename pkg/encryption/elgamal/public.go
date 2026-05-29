package elgamal

import (
	"io"

	"github.com/bronlabs/errs-go/errs"

	"github.com/bronlabs/bron-crypto/pkg/base"
	"github.com/bronlabs/bron-crypto/pkg/base/algebra"
	"github.com/bronlabs/bron-crypto/pkg/base/algebra/constructions"
	"github.com/bronlabs/bron-crypto/pkg/base/serde"
	"github.com/bronlabs/bron-crypto/pkg/base/utils"
	"github.com/bronlabs/bron-crypto/pkg/base/utils/algebrautils"
	"github.com/bronlabs/bron-crypto/pkg/encryption"
	"github.com/bronlabs/bron-crypto/pkg/encryption/internal/gift"
)

// NewPublicKey constructs a public key h = g^a from the group element v.
// It rejects the identity element (which would make all ciphertexts trivially
// decryptable) and elements with torsion (which would place the key outside the
// prime-order subgroup, enabling small-subgroup attacks).
func NewPublicKey[E FiniteCyclicGroupElement[E, S], S algebra.UintLike[S]](h E) (*PublicKey[E, S], error) {
	if utils.IsNil(h) {
		return nil, encryption.ErrIsNil.WithMessage("public key value")
	}
	if h.IsOpIdentity() {
		return nil, encryption.ErrSubGroupMembership.WithMessage("public key value cannot be the identity element")
	}
	if !h.IsTorsionFree() {
		return nil, encryption.ErrSubGroupMembership.WithMessage("public key value is not torsion free")
	}
	return &PublicKey[E, S]{h: h}, nil
}

// PublicKey is a group element h = g^a where a is the corresponding private key scalar.
type PublicKey[E FiniteCyclicGroupElement[E, S], S algebra.UintLike[S]] struct {
	h E
}

type publicKeyDTO[E FiniteCyclicGroupElement[E, S], S algebra.UintLike[S]] struct {
	H E `cbor:"h"`
}

// Type returns the scheme identifier Name.
func (*PublicKey[E, S]) Type() encryption.Name {
	return Name
}

// SampleNonce draws a fresh encryption nonce r uniformly from [1, n−1] (HAC
// 8.26.1.c). Freshness and secrecy of r are essential: reusing a nonce across two
// encryptions leaks the ratio of the plaintexts, and IND-CPA relies on r being
// uniform, so prng must be cryptographically secure.
func (pk *PublicKey[E, S]) SampleNonce(prng io.Reader) (*Nonce[S], error) {
	if prng == nil {
		return nil, encryption.ErrIsNil.WithMessage("prng must not be nil")
	}
	// 8.26.1.c: Select a random integer k, 1 ≤ k ≤ n − 1.
	nv, err := algebrautils.RandomNonIdentity(pk.NonceGroup(), prng)
	if err != nil {
		return nil, errs.Wrap(err).WithMessage("failed to generate nonce value")
	}
	nonce, err := NewNonce(nv)
	if err != nil {
		return nil, errs.Wrap(err).WithMessage("failed to create nonce")
	}
	return nonce, nil
}

// EncryptWithNonce deterministically encrypts plaintext under nonce, producing the
// ElGamal ciphertext (g^r, m·h^r) (HAC 8.26.1). Determinism in the nonce lets
// callers recompute the ciphertext (e.g. when opening a commitment); security still
// requires nonce to be a fresh secret value.
func (pk *PublicKey[E, S]) EncryptWithNonce(plaintext *Plaintext[E, S], nonce *Nonce[S]) (*Ciphertext[E, S], error) {
	// SUMMARY: B encrypts a message m for A, which A decrypts.
	// 8.26.1: Encryption. B should do the following:
	// 8.26.1.a: Obtain A’s authentic public key (α, αa).
	// 8.26.1.b: Represent the message as an element m of the group G.
	// 8.26.1.c: Select a random integer k, 1 ≤ k ≤ n − 1.
	if plaintext == nil || nonce == nil {
		return nil, encryption.ErrIsNil.WithMessage("plaintext and nonce must not be nil")
	}
	// 8.26.1.d: Compute γ = α^k and δ = m · (α^a)^k.
	// 8.26.1.e: Send the ciphertext c = (γ,δ) to A.
	// Since we are using the gift framework, we effectively do c = (α^k, (α^a)^k) * (1, m)
	out, err := gift.Encrypt(pk, plaintext, nonce)
	if err != nil {
		return nil, errs.Wrap(err).WithMessage("failed to encrypt plaintext")
	}
	return out, nil
}

// Representative deterministically encodes a plaintext m as the noiseless
// ciphertext (1, m). It carries no randomness and hides nothing on its own; it is
// the homomorphic embedding of m, combined with IdentityNoise to form a full
// encryption (and used directly by Shift).
func (pk *PublicKey[E, S]) Representative(plaintext *Plaintext[E, S]) (*Ciphertext[E, S], error) {
	if plaintext == nil {
		return nil, encryption.ErrIsNil.WithMessage("plaintext must not be nil")
	}
	phi, err := pk.CiphertextGroup().New(
		pk.PlaintextGroup().OpIdentity(),
		plaintext.Value(),
	)
	if err != nil {
		return nil, errs.Wrap(err).WithMessage("could not create representative ciphertext")
	}
	return &Ciphertext[E, S]{v: phi}, nil
}

// IdentityNoise returns (g^r, h^r), an encryption of the group identity with nonce
// r. Multiplying a representative by this blinds it into a full encryption, and it
// is the building block of ReRandomise.
func (pk *PublicKey[E, S]) IdentityNoise(nonce *Nonce[S]) (*Ciphertext[E, S], error) {
	if nonce == nil {
		return nil, encryption.ErrIsNil.WithMessage("nonce must not be nil")
	}
	r, err := pk.CiphertextGroup().New(
		pk.Generator().ScalarOp(nonce.v),
		pk.h.ScalarOp(nonce.v),
	)
	if err != nil {
		return nil, errs.Wrap(err).WithMessage("could not create identity noise ciphertext")
	}
	return &Ciphertext[E, S]{v: r}, nil
}

// NonceOp adds nonces in Z/nZ; the sum is the nonce of the CiphertextOp (product)
// of the corresponding ciphertexts. It errors if the result is the zero scalar,
// which NewNonce rejects.
func (pk *PublicKey[E, S]) NonceOp(first, second *Nonce[S], rest ...*Nonce[S]) (*Nonce[S], error) {
	out, err := algebrautils.Op(NewNonce, pk.NonceGroup(), first, second, rest...)
	if err != nil {
		return nil, errs.Wrap(err).WithMessage("failed to combine nonces")
	}
	return out, nil
}

// NonceOpInv negates a nonce in Z/nZ, matching the nonce of the inverse ciphertext.
func (*PublicKey[E, S]) NonceOpInv(n *Nonce[S]) (*Nonce[S], error) {
	if n == nil {
		return nil, encryption.ErrIsNil.WithMessage("nonce must not be nil")
	}
	out, err := NewNonce(n.Value().OpInv())
	if err != nil {
		return nil, errs.Wrap(err).WithMessage("failed to invert nonce")
	}
	return out, nil
}

// NonceScalarOp multiplies a nonce by scalar s in Z/nZ, matching the nonce of a
// ciphertext raised to s. It errors if the result is the zero scalar (e.g. s = 0).
func (*PublicKey[E, S]) NonceScalarOp(n *Nonce[S], s S) (*Nonce[S], error) {
	if n == nil {
		return nil, encryption.ErrIsNil.WithMessage("nonce must not be nil")
	}
	out, err := NewNonce(n.Value().Mul(s))
	if err != nil {
		return nil, errs.Wrap(err).WithMessage("failed to scalar multiply nonce")
	}
	return out, nil
}

// PlaintextOp combines plaintexts with the group operation of G. A ciphertext of
// the product equals the CiphertextOp of the individual ciphertexts — the
// multiplicative homomorphism of ElGamal.
func (pk *PublicKey[E, S]) PlaintextOp(first, second *Plaintext[E, S], rest ...*Plaintext[E, S]) (*Plaintext[E, S], error) {
	out, err := algebrautils.Op(NewPlaintext, pk.PlaintextGroup(), first, second, rest...)
	if err != nil {
		return nil, errs.Wrap(err).WithMessage("failed to combine plaintexts")
	}
	return out, nil
}

// PlaintextOpInv returns the group inverse of a plaintext, matching CiphertextOpInv.
func (*PublicKey[E, S]) PlaintextOpInv(p *Plaintext[E, S]) (*Plaintext[E, S], error) {
	if p == nil {
		return nil, encryption.ErrIsNil.WithMessage("plaintext must not be nil")
	}
	out, err := NewPlaintext(p.Value().OpInv())
	if err != nil {
		return nil, errs.Wrap(err).WithMessage("failed to invert plaintext")
	}
	return out, nil
}

// PlaintextScalarOp raises a plaintext to scalar s in G, matching CiphertextScalarOp.
func (*PublicKey[E, S]) PlaintextScalarOp(p *Plaintext[E, S], s S) (*Plaintext[E, S], error) {
	if p == nil {
		return nil, encryption.ErrIsNil.WithMessage("plaintext must not be nil")
	}
	out, err := NewPlaintext(p.v.ScalarOp(s))
	if err != nil {
		return nil, errs.Wrap(err).WithMessage("failed to scalar multiply plaintext")
	}
	return out, nil
}

// CiphertextOp multiplies ciphertexts component-wise in G². By the homomorphism the
// result encrypts the product of the plaintexts under the sum of the nonces.
func (pk *PublicKey[E, S]) CiphertextOp(c1, c2 *Ciphertext[E, S], rest ...*Ciphertext[E, S]) (*Ciphertext[E, S], error) {
	out, err := algebrautils.Op(NewCiphertextFromGroupElement, pk.CiphertextGroup(), c1, c2, rest...)
	if err != nil {
		return nil, errs.Wrap(err).WithMessage("could not compute ciphertext operation")
	}
	return out, nil
}

// CiphertextOpInv returns the component-wise inverse ciphertext, encrypting the
// inverse plaintext under the negated nonce.
func (*PublicKey[E, S]) CiphertextOpInv(c *Ciphertext[E, S]) (*Ciphertext[E, S], error) {
	if c == nil {
		return nil, encryption.ErrIsNil.WithMessage("ciphertext must not be nil")
	}
	out, err := NewCiphertextFromGroupElement(c.Value().OpInv())
	if err != nil {
		return nil, errs.Wrap(err).WithMessage("could not invert ciphertext")
	}
	return out, nil
}

// CiphertextScalarOp raises a ciphertext to scalar s component-wise, scaling both
// the encrypted plaintext and the nonce by s.
func (*PublicKey[E, S]) CiphertextScalarOp(c *Ciphertext[E, S], s S) (*Ciphertext[E, S], error) {
	if c == nil {
		return nil, encryption.ErrIsNil.WithMessage("ciphertext must not be nil")
	}
	out, err := NewCiphertextFromGroupElement(c.Value().ScalarOp(s))
	if err != nil {
		return nil, errs.Wrap(err).WithMessage("could not scalar multiply ciphertext")
	}
	return out, nil
}

// ReRandomise multiplies c by IdentityNoise(nonce) = (g^r, h^r), producing a fresh,
// independent-looking encryption of the SAME plaintext. With a fresh nonce the
// result is unlinkable to c; this underpins re-randomisable commitments built on
// ElGamal.
func (pk *PublicKey[E, S]) ReRandomise(c *Ciphertext[E, S], nonce *Nonce[S]) (*Ciphertext[E, S], error) {
	if c == nil || nonce == nil {
		return nil, encryption.ErrIsNil.WithMessage("ciphertext and nonce must not be nil")
	}
	out, err := gift.ReRandomise(pk, c, nonce)
	if err != nil {
		return nil, errs.Wrap(err).WithMessage("failed to re-randomise ciphertext")
	}
	return out, nil
}

// Shift multiplies c by Representative(delta) = (1, delta), yielding an encryption
// of m·delta under the SAME nonce. The plaintext is shifted; the randomness is not.
func (pk *PublicKey[E, S]) Shift(c *Ciphertext[E, S], delta *Plaintext[E, S]) (*Ciphertext[E, S], error) {
	if c == nil || delta == nil {
		return nil, encryption.ErrIsNil.WithMessage("ciphertext and delta must not be nil")
	}
	out, err := gift.Shift(pk, c, delta)
	if err != nil {
		return nil, errs.Wrap(err).WithMessage("failed to shift ciphertext by plaintext delta")
	}
	return out, nil
}

// Generator returns the group generator g, the base of h = g^a.
func (pk *PublicKey[E, S]) Generator() E {
	return pk.PlaintextGroup().Generator()
}

// PlaintextGroup returns the cyclic group G in which plaintexts (and the key) live.
func (pk *PublicKey[E, S]) PlaintextGroup() FiniteCyclicGroup[E, S] {
	return algebra.StructureMustBeAs[FiniteCyclicGroup[E, S]](pk.h.Structure())
}

// NonceGroup returns the scalar ring Z/nZ from which nonces are drawn.
func (pk *PublicKey[E, S]) NonceGroup() algebra.ZModLike[S] {
	return algebra.StructureMustBeAs[algebra.ZModLike[S]](pk.PlaintextGroup().ScalarStructure())
}

// CiphertextGroup returns the direct-power module G² in which ciphertexts live.
func (pk *PublicKey[E, S]) CiphertextGroup() *constructions.FiniteDirectPowerModule[FiniteCyclicGroup[E, S], E, S] {
	return errs.Must1(constructions.NewFiniteDirectPowerModule(pk.PlaintextGroup(), 2))
}

// Value returns the public-key group element h = g^a.
func (pk *PublicKey[E, S]) Value() E {
	return pk.h
}

// Equal reports whether two public keys are the same group element, treating nil as
// equal only to nil. Public keys are public, so this need not be constant time.
func (pk *PublicKey[E, S]) Equal(other *PublicKey[E, S]) bool {
	if pk == nil || other == nil {
		return pk == other
	}
	return pk.h.Equal(other.h)
}

// Clone returns a deep copy of the public key.
func (pk *PublicKey[E, S]) Clone() *PublicKey[E, S] {
	return &PublicKey[E, S]{h: pk.h.Clone()}
}

// HashCode returns a non-cryptographic hash of the public key for use as a map key.
func (pk *PublicKey[E, S]) HashCode() base.HashCode {
	return pk.h.HashCode()
}

// MarshalCBOR encodes the public-key element h.
func (pk *PublicKey[E, S]) MarshalCBOR() ([]byte, error) {
	dto := &publicKeyDTO[E, S]{
		H: pk.h,
	}
	out, err := serde.MarshalCBOR(dto)
	if err != nil {
		return nil, errs.Wrap(err).WithMessage("could not marshal public key")
	}
	return out, nil
}

// UnmarshalCBOR decodes a public key and re-validates h through NewPublicKey
// (non-identity, torsion-free). This is a deserialization trust boundary that
// rejects identity and small-subgroup keys.
func (pk *PublicKey[E, S]) UnmarshalCBOR(data []byte) error {
	dto, err := serde.UnmarshalCBOR[*publicKeyDTO[E, S]](data)
	if err != nil {
		return errs.Wrap(err).WithMessage("could not unmarshal public key")
	}
	pkk, err := NewPublicKey(dto.H)
	if err != nil {
		return errs.Wrap(err).WithMessage("could not create public key from unmarshalled data")
	}
	*pk = *pkk
	return nil
}
