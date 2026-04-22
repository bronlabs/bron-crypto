package elgamal

import (
	"io"

	"github.com/bronlabs/errs-go/errs"

	"github.com/bronlabs/bron-crypto/pkg/base"
	"github.com/bronlabs/bron-crypto/pkg/base/algebra"
	"github.com/bronlabs/bron-crypto/pkg/base/algebra/constructions"
	"github.com/bronlabs/bron-crypto/pkg/base/utils"
	"github.com/bronlabs/bron-crypto/pkg/base/utils/algebrautils"
)

// NewPublicKey constructs a public key h = g^a from the group element v.
// It rejects the identity element (which would make all ciphertexts trivially
// decryptable) and elements with torsion (which would place the key outside the
// prime-order subgroup, enabling small-subgroup attacks).
func NewPublicKey[E FiniteCyclicGroupElement[E, S], S algebra.UintLike[S]](v E) (*PublicKey[E, S], error) {
	if utils.IsNil(v) {
		return nil, ErrIsNil.WithMessage("public key value")
	}
	if v.IsOpIdentity() {
		return nil, ErrSubGroupMembership.WithMessage("public key value cannot be the identity element")
	}
	if !v.IsTorsionFree() {
		return nil, ErrSubGroupMembership.WithMessage("public key value is not torsion free")
	}
	return &PublicKey[E, S]{v: v}, nil
}

// PublicKey is a group element h = g^a where a is the corresponding private key scalar.
type PublicKey[E FiniteCyclicGroupElement[E, S], S algebra.UintLike[S]] struct {
	v E
}

// Value returns the underlying group element h.
func (pk *PublicKey[E, S]) Value() E {
	return pk.v
}

// Equal reports whether two public keys represent the same group element.
func (pk *PublicKey[E, S]) Equal(x *PublicKey[E, S]) bool {
	if pk == nil || x == nil {
		return pk == x
	}
	return pk.v.Equal(x.v)
}

// Clone returns a deep copy of the public key.
func (pk *PublicKey[E, S]) Clone() *PublicKey[E, S] {
	out := &PublicKey[E, S]{}
	out.v = pk.v.Clone()
	return out
}

// Group returns the algebraic group that this key belongs to.
func (pk *PublicKey[E, S]) Group() FiniteCyclicGroup[E, S] {
	if pk == nil {
		return nil
	}
	return algebra.StructureMustBeAs[FiniteCyclicGroup[E, S]](pk.v.Structure())
}

// HashCode returns a non-cryptographic hash for use in hash maps.
func (pk *PublicKey[E, S]) HashCode() base.HashCode {
	if pk == nil {
		return 0
	}
	return pk.v.HashCode()
}

// NewPrivateKey constructs a private key from scalar a ∈ Z/nZ and computes
// the corresponding public key h = g^a. It rejects a = 0 (the identity scalar),
// which would yield the degenerate public key h = identity.
func NewPrivateKey[E FiniteCyclicGroupElement[E, S], S algebra.UintLike[S]](group FiniteCyclicGroup[E, S], v S) (*PrivateKey[E, S], error) {
	if utils.IsNil(v) {
		return nil, ErrIsNil.WithMessage("private key value")
	}
	if v.IsOpIdentity() {
		return nil, ErrSubGroupMembership.WithMessage("private key value cannot be the identity element")
	}
	if group == nil {
		return nil, ErrIsNil.WithMessage("group")
	}
	pk, err := NewPublicKey(group.Generator().ScalarOp(v))
	if err != nil {
		return nil, errs.Wrap(err).WithMessage("failed to create public key from private key value")
	}
	return &PrivateKey[E, S]{v: v, pk: *pk}, nil
}

// PrivateKey is a scalar a ∈ Z/nZ together with the precomputed public key h = g^a.
type PrivateKey[E FiniteCyclicGroupElement[E, S], S algebra.UintLike[S]] struct {
	v  S
	pk PublicKey[E, S]
}

// Value returns the secret scalar a.
func (sk *PrivateKey[E, S]) Value() S {
	return sk.v
}

// Public returns the corresponding public key h = g^a.
func (sk *PrivateKey[E, S]) Public() *PublicKey[E, S] {
	return &sk.pk
}

// Equal reports whether two private keys have the same scalar and public key.
func (sk *PrivateKey[E, S]) Equal(x *PrivateKey[E, S]) bool {
	if sk == nil || x == nil {
		return sk == x
	}
	return sk.v.Equal(x.v) && sk.pk.Equal(&x.pk)
}

// Clone returns a deep copy of the private key.
func (sk *PrivateKey[E, S]) Clone() *PrivateKey[E, S] {
	out := &PrivateKey[E, S]{}
	out.v = sk.v.Clone()
	out.pk = *sk.pk.Clone()
	return out
}

// NewPlaintext wraps a group element as an ElGamal plaintext.
// In generalised ElGamal the message space is the group G itself;
// encoding application-level data into group elements is the caller's
// responsibility.
func NewPlaintext[E FiniteCyclicGroupElement[E, S], S algebra.UintLike[S]](v E) (*Plaintext[E, S], error) {
	if utils.IsNil(v) {
		return nil, ErrIsNil.WithMessage("plaintext value")
	}
	return &Plaintext[E, S]{v: v}, nil
}

// Plaintext is a group element m ∈ G to be encrypted.
type Plaintext[E FiniteCyclicGroupElement[E, S], S algebra.UintLike[S]] struct {
	v E
}

// Value returns the underlying group element.
func (p *Plaintext[E, S]) Value() E {
	return p.v
}

// Equal reports whether two plaintexts represent the same group element.
func (p *Plaintext[E, S]) Equal(x *Plaintext[E, S]) bool {
	if p == nil || x == nil {
		return p == x
	}
	return p.v.Equal(x.v)
}

// Op returns the group product of two plaintexts: m₁ · m₂.
func (p *Plaintext[E, S]) Op(other *Plaintext[E, S]) *Plaintext[E, S] {
	if p == nil || other == nil {
		return nil
	}
	return &Plaintext[E, S]{p.v.Op(other.v)}
}

// OpInv returns the group inverse of the plaintext: m⁻¹.
func (p *Plaintext[E, S]) OpInv() *Plaintext[E, S] {
	if p == nil {
		return nil
	}
	return &Plaintext[E, S]{p.v.OpInv()}
}

// ScalarOp returns the plaintext raised to the given scalar: m^k.
func (p *Plaintext[E, S]) ScalarOp(scalar algebra.Numeric) *Plaintext[E, S] {
	if p == nil || scalar == nil {
		return nil
	}
	return &Plaintext[E, S]{algebrautils.ScalarMul(p.v, scalar)}
}

// NewCiphertext constructs a ciphertext from its two components (c₁, c₂).
// A valid encryption satisfies c₁ = g^r and c₂ = m · h^r for some nonce r,
// but this constructor does not enforce that relationship — it is the caller's
// responsibility to provide well-formed components.
func NewCiphertext[E FiniteCyclicGroupElement[E, S], S algebra.UintLike[S]](c1, c2 E) (*Ciphertext[E, S], error) {
	if utils.IsNil(c1) || utils.IsNil(c2) {
		return nil, ErrIsNil.WithMessage("ciphertext components")
	}
	if !c1.IsTorsionFree() || !c2.IsTorsionFree() {
		return nil, ErrSubGroupMembership.WithMessage("ciphertext component is not torsion free")
	}
	// The second component can be identity if the message happens to be -h^r. The first one can never be identity for nonzero nonce.
	if c1.IsOpIdentity() {
		return nil, ErrSubGroupMembership.WithMessage("invalid ciphertext: first component is identity")
	}
	g := algebra.StructureMustBeAs[FiniteCyclicGroup[E, S]](c1.Structure())
	ctSpace, err := constructions.NewFiniteDirectPowerModule(g, 2)
	if err != nil {
		return nil, errs.Wrap(err).WithMessage("failed to create ciphertext space")
	}
	v, err := ctSpace.New(c1, c2)
	if err != nil {
		return nil, errs.Wrap(err).WithMessage("failed to create new ciphertext element")
	}
	return &Ciphertext[E, S]{v: v}, nil
}

// Ciphertext is a pair (c₁, c₂) = (g^r, m · h^r) in G × G,
// represented as an element of the direct-power module G².
type Ciphertext[E FiniteCyclicGroupElement[E, S], S algebra.UintLike[S]] struct {
	v *constructions.FiniteDirectPowerModuleElement[E, S]
}

// ScalarRing returns Z/nZ derived from the ciphertext's group structure.
func (c *Ciphertext[E, S]) ScalarRing() algebra.ZModLike[S] {
	if c == nil {
		return nil
	}
	g := algebra.StructureMustBeAs[FiniteCyclicGroup[E, S]](c.v.Components()[0].Structure())
	return algebra.StructureMustBeAs[algebra.ZModLike[S]](g.ScalarStructure())
}

// Value returns the underlying direct-power module element (c₁, c₂).
func (c *Ciphertext[E, S]) Value() *constructions.FiniteDirectPowerModuleElement[E, S] {
	return c.v
}

// Shift adds a known plaintext offset to the encrypted message without
// re-randomising: (c₁, c₂) → (c₁, c₂ · m'). If the original ciphertext
// encrypts m, the result encrypts m · m'. This does not change c₁ and
// therefore does not hide the shift from an observer who sees both
// ciphertexts; use ReRandomise afterwards if unlinkability is needed.
//
// The public key parameter is unused by ElGamal's shift but is required
// by the ShiftTypeCiphertext interface.
func (c *Ciphertext[E, S]) Shift(_ *PublicKey[E, S], message *Plaintext[E, S]) (*Ciphertext[E, S], error) {
	if c == nil {
		return nil, ErrIsNil.WithMessage("ciphertext")
	}
	if message == nil {
		return nil, ErrIsNil.WithMessage("message")
	}
	c1 := c.v.Components()[0]
	c2 := c.v.Components()[1].Op(message.v)
	return NewCiphertext(c1, c2)
}

// ReRandomiseWithNonce produces a new ciphertext encrypting the same plaintext
// under a deterministic nonce r': (c₁ · g^r', c₂ · h^r'). The result is
// unlinkable to the original ciphertext under DDH.
func (c *Ciphertext[E, S]) ReRandomiseWithNonce(publicKey *PublicKey[E, S], nonce *Nonce[S]) (*Ciphertext[E, S], error) {
	if c == nil {
		return nil, ErrIsNil.WithMessage("ciphertext")
	}
	if publicKey == nil {
		return nil, ErrIsNil.WithMessage("public key")
	}
	if nonce == nil {
		return nil, ErrIsNil.WithMessage("nonce")
	}
	gr := publicKey.Group().Generator().ScalarOp(nonce.Value())
	hr := publicKey.Value().ScalarOp(nonce.Value())
	c1 := c.v.Components()[0].Op(gr)
	c2 := c.v.Components()[1].Op(hr)
	return NewCiphertext(c1, c2)
}

// ReRandomise produces a new ciphertext encrypting the same plaintext using
// a fresh random nonce. The returned nonce is the randomness used.
func (c *Ciphertext[E, S]) ReRandomise(publicKey *PublicKey[E, S], prng io.Reader) (*Ciphertext[E, S], *Nonce[S], error) {
	if c == nil {
		return nil, nil, ErrIsNil.WithMessage("ciphertext")
	}
	nonceValue, err := algebrautils.RandomNonIdentity(c.ScalarRing(), prng)
	if err != nil {
		return nil, nil, errs.Wrap(err).WithMessage("failed to generate nonce value")
	}
	nonce, err := NewNonce(nonceValue)
	if err != nil {
		return nil, nil, errs.Wrap(err).WithMessage("failed to create nonce")
	}
	ciphertext, err := c.ReRandomiseWithNonce(publicKey, nonce)
	if err != nil {
		return nil, nil, errs.Wrap(err).WithMessage("failed to re-randomise ciphertext")
	}
	return ciphertext, nonce, nil
}

// Equal reports whether two ciphertexts have identical components.
func (c *Ciphertext[E, S]) Equal(x *Ciphertext[E, S]) bool {
	if c == nil || x == nil {
		return c == x
	}
	return c.v.Equal(x.v)
}

// Op returns the component-wise group product of two ciphertexts.
// This is the homomorphic operation: Dec(c₁ ⊕ c₂) = Dec(c₁) · Dec(c₂).
func (c *Ciphertext[E, S]) Op(other *Ciphertext[E, S]) *Ciphertext[E, S] {
	if c == nil || other == nil {
		return nil
	}
	return &Ciphertext[E, S]{v: c.v.Op(other.v)}
}

// ScalarOp raises both ciphertext components to the given scalar:
// (c₁, c₂)^k = (c₁^k, c₂^k). If c encrypts m, the result encrypts m^k.
func (c *Ciphertext[E, S]) ScalarOp(scalar algebra.Numeric) *Ciphertext[E, S] {
	if c == nil || scalar == nil {
		return nil
	}
	return &Ciphertext[E, S]{v: algebrautils.ScalarMul(c.v, scalar)}
}

// OpInv returns the component-wise group inverse of the ciphertext: (c₁, c₂)⁻¹ = (c₁⁻¹, c₂⁻¹). If c encrypts m, the result encrypts m⁻¹.
func (c *Ciphertext[E, S]) OpInv() *Ciphertext[E, S] {
	if c == nil {
		return nil
	}
	return &Ciphertext[E, S]{v: c.v.OpInv()}
}

// NewNonce constructs an encryption nonce from a scalar r ∈ Z/nZ.
// It rejects r = 0, which would produce the degenerate ciphertext (identity, m)
// and leak the plaintext directly.
func NewNonce[S algebra.UintLike[S]](v S) (*Nonce[S], error) {
	if utils.IsNil(v) {
		return nil, ErrIsNil.WithMessage("nonce value")
	}
	if v.IsOpIdentity() {
		return nil, ErrValue.WithMessage("nonce value cannot be the identity element")
	}
	return &Nonce[S]{v: v}, nil
}

// Nonce is the randomness r used during encryption: c = (g^r, m · h^r).
// Reusing a nonce across two encryptions under the same key leaks the
// ratio of the two plaintexts.
type Nonce[S algebra.UintLike[S]] struct {
	v S
}

// Value returns the scalar r.
func (n *Nonce[S]) Value() S {
	return n.v
}

// Op returns the sum of two nonces in Z/nZ. This is the nonce that
// corresponds to the homomorphic combination of two ciphertexts.
func (n *Nonce[S]) Op(other *Nonce[S]) *Nonce[S] {
	if n == nil || other == nil {
		return nil
	}
	return &Nonce[S]{v: n.v.Op(other.v)}
}

// Equal reports whether two nonces have the same scalar value.
func (n *Nonce[S]) Equal(x *Nonce[S]) bool {
	if n == nil || x == nil {
		return n == x
	}
	return n.v.Equal(x.v)
}

// OpInv returns the additive inverse of the nonce in Z/nZ. This is the nonce that corresponds to the homomorphic inverse of a ciphertext.
func (n *Nonce[S]) OpInv() *Nonce[S] {
	if n == nil {
		return nil
	}
	return &Nonce[S]{v: n.v.OpInv()}
}

// ScalarOp returns the product of the nonce with a scalar: r · k. This is the nonce that corresponds to raising a ciphertext to a scalar.
func (n *Nonce[S]) ScalarOp(scalar algebra.Numeric) *Nonce[S] {
	if n == nil || scalar == nil {
		return nil
	}
	return &Nonce[S]{v: algebrautils.ScalarMul(n.v, scalar)}
}
