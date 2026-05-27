package paillier

import (
	"io"

	"github.com/bronlabs/errs-go/errs"

	"github.com/bronlabs/bron-crypto/pkg/base"
	"github.com/bronlabs/bron-crypto/pkg/base/nt/num"
	"github.com/bronlabs/bron-crypto/pkg/base/nt/znstar"
	"github.com/bronlabs/bron-crypto/pkg/base/serde"
	"github.com/bronlabs/bron-crypto/pkg/base/utils/algebrautils"
	"github.com/bronlabs/bron-crypto/pkg/base/utils/sliceutils"
	"github.com/bronlabs/bron-crypto/pkg/encryption"
	"github.com/bronlabs/bron-crypto/pkg/encryption/internal/gift"
)

// NewPublicKey builds a Paillier public key from the group Z*_{N²} (i.e. from the
// modulus N), rejecting nil. The modulus is trusted as well-formed: this
// constructor cannot verify that N is a product of two large primes — when N comes
// from an untrusted party that must be established by a separate proof (e.g. a
// Paillier-Blum modulus proof).
func NewPublicKey(group *znstar.PaillierGroupUnknownOrder) (*PublicKey, error) {
	if group == nil {
		return nil, encryption.ErrIsNil.WithMessage("group must not be nil")
	}
	return &PublicKey{group: group}, nil
}

// PublicKey is a Paillier public key: the group Z*_{N²} determined by the modulus
// N. It can encrypt (computationally hiding under DCRA) and run the additive
// homomorphism, but cannot decrypt — decryption needs the factorisation held by
// SecretKey.
type PublicKey struct {
	group *znstar.PaillierGroupUnknownOrder
}

type publicKeyDTO struct {
	Group *znstar.PaillierGroupUnknownOrder `cbor:"group"`
}

// Type returns the scheme identifier Name.
func (*PublicKey) Type() encryption.Name {
	return Name
}

// SampleNonce draws a fresh nonce uniformly from Z*_N. Freshness and secrecy of the
// nonce are essential to IND-CPA hiding, so prng must be a cryptographically secure
// source.
func (pk *PublicKey) SampleNonce(prng io.Reader) (*Nonce, error) {
	if prng == nil {
		return nil, encryption.ErrIsNil.WithMessage("prng must not be nil")
	}
	out, err := pk.NonceGroup().Random(prng)
	if err != nil {
		return nil, errs.Wrap(err).WithMessage("could not sample nonce")
	}
	return &Nonce{r: out}, nil
}

// EncryptWithNonce deterministically encrypts p under nonce n, producing the
// Paillier ciphertext (1+N)^m · r^N mod N². Determinism in the nonce lets callers
// recompute the ciphertext (e.g. when opening a commitment); security still
// requires n to be a fresh secret nonce.
func (pk *PublicKey) EncryptWithNonce(p *Plaintext, n *Nonce) (*Ciphertext, error) {
	if p == nil || n == nil {
		return nil, encryption.ErrIsNil.WithMessage("plaintext and nonce must not be nil")
	}
	out, err := gift.Encrypt(pk, p, n)
	if err != nil {
		return nil, errs.Wrap(err).WithMessage("could not encrypt message with nonce")
	}
	return out, nil
}

// Representative deterministically encodes a plaintext m as (1+N)^m mod N², the
// noiseless ciphertext. It carries no randomness and hides nothing on its own; it
// is the homomorphic embedding of m, combined with IdentityNoise to form a full
// encryption (and used directly by Shift).
func (pk *PublicKey) Representative(p *Plaintext) (*Ciphertext, error) {
	if p == nil {
		return nil, encryption.ErrIsNil.WithMessage("plaintext must not be nil")
	}
	gm, err := pk.group.Representative(p.Value())
	if err != nil {
		return nil, errs.Wrap(err).WithMessage("could not compute representative")
	}
	return &Ciphertext{c: gm}, nil
}

// IdentityNoise returns r^N mod N², an encryption of the plaintext 0 with nonce r.
// Multiplying a representative by this blinds it into a full encryption, and it is
// the building block of ReRandomise.
func (pk *PublicKey) IdentityNoise(n *Nonce) (*Ciphertext, error) {
	if n == nil {
		return nil, encryption.ErrIsNil.WithMessage("nonce must not be nil")
	}
	embeddedNonce, err := pk.group.EmbedRSA(n.Value())
	if err != nil {
		return nil, errs.Wrap(err).WithMessage("could not embed nonce into group")
	}
	rn, err := pk.group.NthResidue(embeddedNonce)
	if err != nil {
		return nil, errs.Wrap(err).WithMessage("could not compute nth residue of embedded nonce")
	}
	return &Ciphertext{c: rn}, nil
}

// NonceOp multiplies nonces in Z*_N; the product is the nonce of the CiphertextOp
// of the corresponding ciphertexts. It validates that the inputs lie in Z*_N.
func (pk *PublicKey) NonceOp(first, second *Nonce, rest ...*Nonce) (*Nonce, error) {
	if first == nil || second == nil {
		return nil, encryption.ErrIsNil.WithMessage("first and second nonces cannot be nil")
	}
	if !pk.NonceGroup().Contains(first.r) || !pk.NonceGroup().Contains(second.r) {
		return nil, encryption.ErrSubGroupMembership.WithMessage("first and second nonces must be in nonce group")
	}
	if len(rest) > 0 && sliceutils.Any(rest, func(n *Nonce) bool { return n == nil || !pk.NonceGroup().Contains(n.r) }) {
		return nil, encryption.ErrSubGroupMembership.WithMessage("all nonces must be in nonce group")
	}
	out, err := algebrautils.Op(NewNonceFromGroupElement, pk.NonceGroup(), first, second, rest...)
	if err != nil {
		return nil, errs.Wrap(err).WithMessage("failed to combine nonces")
	}
	return out, nil
}

// NonceOpInv returns the multiplicative inverse of a nonce in Z*_N, the nonce of
// the inverse ciphertext.
func (pk *PublicKey) NonceOpInv(n *Nonce) (*Nonce, error) {
	if n == nil {
		return nil, encryption.ErrIsNil.WithMessage("nonce must not be nil")
	}
	if !pk.NonceGroup().Contains(n.r) {
		return nil, encryption.ErrSubGroupMembership.WithMessage("nonce must be in nonce group")
	}
	return &Nonce{r: n.Value().OpInv()}, nil
}

// NonceScalarOp raises a nonce to the integer scalar power in Z*_N, matching the
// nonce of a ciphertext raised to that scalar.
func (pk *PublicKey) NonceScalarOp(n *Nonce, scalar *num.Int) (*Nonce, error) {
	if n == nil || scalar == nil {
		return nil, encryption.ErrIsNil.WithMessage("nonce and scalar must not be nil")
	}
	if !pk.NonceGroup().Contains(n.r) {
		return nil, encryption.ErrSubGroupMembership.WithMessage("nonce must be in nonce group")
	}
	return &Nonce{r: n.Value().ScalarOp(scalar)}, nil
}

// PlaintextOp adds plaintexts in Z_N. A ciphertext of the sum equals the
// CiphertextOp (product) of the individual ciphertexts — Paillier's additive
// homomorphism.
func (pk *PublicKey) PlaintextOp(first, second *Plaintext, rest ...*Plaintext) (*Plaintext, error) {
	out, err := algebrautils.Op(NewPlaintext, pk.PlaintextGroup(), first, second, rest...)
	if err != nil {
		return nil, errs.Wrap(err).WithMessage("failed to combine plaintexts")
	}
	return out, nil
}

// PlaintextOpInv negates a plaintext in Z_N, matching CiphertextOpInv on its
// ciphertext.
func (pk *PublicKey) PlaintextOpInv(p *Plaintext) (*Plaintext, error) {
	if p == nil {
		return nil, encryption.ErrIsNil.WithMessage("plaintext must not be nil")
	}
	if !pk.PlaintextGroup().Contains(p.Value()) {
		return nil, encryption.ErrSubGroupMembership.WithMessage("plaintext must be in plaintext group")
	}
	out, err := NewPlaintext(p.Value().OpInv())
	if err != nil {
		return nil, errs.Wrap(err).WithMessage("failed to create new plaintext from inverse value")
	}
	return out, nil
}

// PlaintextScalarOp multiplies a plaintext by an integer scalar in Z_N, matching
// CiphertextScalarOp on its ciphertext.
func (pk *PublicKey) PlaintextScalarOp(p *Plaintext, scalar *num.Int) (*Plaintext, error) {
	if p == nil || scalar == nil {
		return nil, encryption.ErrIsNil.WithMessage("plaintext and scalar must not be nil")
	}
	if !pk.PlaintextGroup().Contains(p.Value()) {
		return nil, encryption.ErrSubGroupMembership.WithMessage("plaintext must be in plaintext group")
	}
	v, err := pk.PlaintextGroup().FromInt(p.Value().Lift().Mul(scalar))
	if err != nil {
		return nil, errs.Wrap(err).WithMessage("failed to create new plaintext from scalar multiplied value")
	}
	return &Plaintext{p: v}, nil
}

// CiphertextOp multiplies ciphertexts in Z*_{N²}. By the homomorphism the product
// encrypts the sum of the plaintexts under the product of the nonces.
func (pk *PublicKey) CiphertextOp(c1, c2 *Ciphertext, rest ...*Ciphertext) (*Ciphertext, error) {
	out, err := algebrautils.Op(NewCiphertextFromGroupElement, pk.CiphertextGroup(), c1, c2, rest...)
	if err != nil {
		return nil, errs.Wrap(err).WithMessage("could not compute ciphertext operation")
	}
	return out, nil
}

// CiphertextOpInv returns the inverse ciphertext in Z*_{N²}, encrypting the negated
// plaintext.
func (pk *PublicKey) CiphertextOpInv(c *Ciphertext) (*Ciphertext, error) {
	if c == nil {
		return nil, encryption.ErrIsNil.WithMessage("ciphertext must not be nil")
	}
	if !pk.CiphertextGroup().Contains(c.Value()) {
		return nil, encryption.ErrSubGroupMembership.WithMessage("ciphertext must be in ciphertext group")
	}
	return &Ciphertext{c: c.Value().OpInv()}, nil
}

// CiphertextScalarOp raises a ciphertext to an integer scalar in Z*_{N²}, scaling
// the encrypted plaintext by that scalar.
func (pk *PublicKey) CiphertextScalarOp(c *Ciphertext, scalar *num.Int) (*Ciphertext, error) {
	if c == nil || scalar == nil {
		return nil, encryption.ErrIsNil.WithMessage("ciphertext and scalar must not be nil")
	}
	if !pk.CiphertextGroup().Contains(c.Value()) {
		return nil, encryption.ErrSubGroupMembership.WithMessage("ciphertext must be in ciphertext group")
	}
	return &Ciphertext{c: c.Value().ScalarOp(scalar)}, nil
}

// ReRandomise multiplies c by IdentityNoise(nonce) = nonce^N, producing a fresh,
// independent-looking encryption of the SAME plaintext. With a fresh nonce the
// result is unlinkable to c; this underpins re-randomisable commitments built on
// Paillier.
func (pk *PublicKey) ReRandomise(c *Ciphertext, nonce *Nonce) (*Ciphertext, error) {
	if c == nil || nonce == nil {
		return nil, encryption.ErrIsNil.WithMessage("ciphertext and nonce must not be nil")
	}
	if !pk.CiphertextGroup().Contains(c.Value()) {
		return nil, encryption.ErrSubGroupMembership.WithMessage("ciphertext must be in ciphertext group")
	}
	if !pk.NonceGroup().Contains(nonce.Value()) {
		return nil, encryption.ErrSubGroupMembership.WithMessage("nonce must be in nonce group")
	}
	out, err := gift.ReRandomise(pk, c, nonce)
	if err != nil {
		return nil, errs.Wrap(err).WithMessage("could not re-randomise ciphertext with nonce")
	}
	return &Ciphertext{c: out.Value()}, nil
}

// Shift multiplies c by Representative(delta) = (1+N)^delta, producing an encryption
// of m+delta under the SAME nonce. The plaintext is shifted; the randomness is not.
func (pk *PublicKey) Shift(c *Ciphertext, delta *Plaintext) (*Ciphertext, error) {
	if c == nil || delta == nil {
		return nil, encryption.ErrIsNil.WithMessage("ciphertext and delta must not be nil")
	}
	if !pk.CiphertextGroup().Contains(c.Value()) {
		return nil, encryption.ErrSubGroupMembership.WithMessage("ciphertext must be in ciphertext group")
	}
	if !pk.PlaintextGroup().Contains(delta.Value()) {
		return nil, encryption.ErrSubGroupMembership.WithMessage("delta must be in plaintext group")
	}
	out, err := gift.Shift(pk, c, delta)
	if err != nil {
		return nil, errs.Wrap(err).WithMessage("could not shift ciphertext by delta")
	}
	return &Ciphertext{c: out.Value()}, nil
}

// Group returns the Paillier group Z*_{N²}.
func (pk *PublicKey) Group() *znstar.PaillierGroupUnknownOrder {
	return pk.group
}

// PlaintextGroup returns the plaintext ring Z_N.
func (pk *PublicKey) PlaintextGroup() *num.ZMod {
	return pk.NonceGroup().AmbientGroup()
}

// NonceGroup returns the nonce group Z*_N, derived from the modulus N.
func (pk *PublicKey) NonceGroup() *znstar.RSAGroupUnknownOrder {
	nonceGroup, err := znstar.NewRSAGroupOfUnknownOrder(pk.group.N())
	if err != nil {
		panic(err)
	}
	return nonceGroup
}

// CiphertextGroup returns the ciphertext group Z*_{N²}.
func (pk *PublicKey) CiphertextGroup() *znstar.PaillierGroupUnknownOrder {
	return pk.group
}

// Equal reports whether two public keys share the same modulus N, treating nil as
// equal only to nil. Public keys are public, so this need not be constant time.
func (pk *PublicKey) Equal(other *PublicKey) bool {
	if pk == nil || other == nil {
		return pk == other
	}
	return pk.group.Equal(other.group)
}

// HashCode returns a non-cryptographic hash of the public key (of N) for use as a
// map key.
func (pk *PublicKey) HashCode() base.HashCode {
	return pk.group.Modulus().HashCode()
}

// MarshalCBOR encodes the public key (the modulus N).
func (pk *PublicKey) MarshalCBOR() ([]byte, error) {
	dto := &publicKeyDTO{
		Group: pk.group,
	}
	out, err := serde.MarshalCBOR(dto)
	if err != nil {
		return nil, errs.Wrap(err).WithMessage("could not marshal public key to CBOR")
	}
	return out, nil
}

// UnmarshalCBOR decodes a public key and re-validates it via NewPublicKey. This is
// a deserialization trust boundary; well-formedness of the modulus N is not (and
// cannot be) verified here.
func (pk *PublicKey) UnmarshalCBOR(data []byte) error {
	dto, err := serde.UnmarshalCBOR[*publicKeyDTO](data)
	if err != nil {
		return errs.Wrap(err).WithMessage("could not unmarshal public key from CBOR")
	}
	newPk, err := NewPublicKey(dto.Group)
	if err != nil {
		return errs.Wrap(err).WithMessage("could not create public key from unmarshaled data")
	}
	*pk = *newPk
	return nil
}
