package elgamal

import (
	"github.com/bronlabs/errs-go/errs"

	"github.com/bronlabs/bron-crypto/pkg/base"
	"github.com/bronlabs/bron-crypto/pkg/base/algebra"
	"github.com/bronlabs/bron-crypto/pkg/base/algebra/constructions"
	"github.com/bronlabs/bron-crypto/pkg/base/serde"
	"github.com/bronlabs/bron-crypto/pkg/base/utils"
	"github.com/bronlabs/bron-crypto/pkg/encryption"
)

// Name identifies the ElGamal encryption scheme.
const Name encryption.Name = "ElGamal"

// EncryptionKey is the group-homomorphic encryption-key interface specialised to
// ElGamal's plaintext (group elements of G), nonce (scalars in Z/nZ), and
// ciphertext (pairs in G²) types. Both PublicKey and SecretKey satisfy it; use it
// as a constraint when writing code generic over either.
type EncryptionKey[EK encryption.GroupHomomorphicEncryptionKey[
	EK,
	*Plaintext[E, S], FiniteCyclicGroup[E, S], E,
	*Nonce[S], algebra.ZModLike[S], S,
	*Ciphertext[E, S], *constructions.FiniteDirectPowerModule[FiniteCyclicGroup[E, S], E, S], *constructions.FiniteDirectPowerModuleElement[E, S],
	S,
], E FiniteCyclicGroupElement[E, S], S algebra.UintLike[S],
] = encryption.GroupHomomorphicEncryptionKey[
	EK,
	*Plaintext[E, S], FiniteCyclicGroup[E, S], E,
	*Nonce[S], algebra.ZModLike[S], S,
	*Ciphertext[E, S], *constructions.FiniteDirectPowerModule[FiniteCyclicGroup[E, S], E, S], *constructions.FiniteDirectPowerModuleElement[E, S],
	S,
]

// FiniteCyclicGroup constrains the group G in which ElGamal operates.
// G must be a finite abelian cyclic group whose DDH problem is hard.
// Typical instantiations: prime-order elliptic curve groups (k256, p256, ed25519 prime subgroup).
type FiniteCyclicGroup[E FiniteCyclicGroupElement[E, S], S algebra.UintLike[S]] interface {
	algebra.AbelianGroup[E, S]
	algebra.CyclicGroup[E]
	algebra.FiniteGroup[E]
}

// FiniteCyclicGroupElement constrains elements of the group G.
type FiniteCyclicGroupElement[E interface {
	algebra.AbelianGroupElement[E, S]
	algebra.CyclicGroupElement[E]
}, S algebra.UintLike[S]] interface {
	algebra.AbelianGroupElement[E, S]
	algebra.CyclicGroupElement[E]
}

// NewCiphertext constructs a ciphertext from its two components (c₁, c₂).
// A valid encryption satisfies c₁ = g^r and c₂ = m · h^r for some nonce r,
// but this constructor does not enforce that relationship — it is the caller's
// responsibility to provide well-formed components.
func NewCiphertext[E FiniteCyclicGroupElement[E, S], S algebra.UintLike[S]](c1, c2 E) (*Ciphertext[E, S], error) {
	if utils.IsNil(c1) || utils.IsNil(c2) {
		return nil, encryption.ErrIsNil.WithMessage("ciphertext components")
	}
	if !c1.IsTorsionFree() || !c2.IsTorsionFree() {
		return nil, encryption.ErrSubGroupMembership.WithMessage("ciphertext component is not torsion free")
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

// NewCiphertextFromGroupElement wraps a G² module element as a ciphertext,
// requiring exactly two components and applying the same torsion-free validation
// as NewCiphertext. It is the constructor used by the homomorphic ciphertext
// operations.
func NewCiphertextFromGroupElement[E FiniteCyclicGroupElement[E, S], S algebra.UintLike[S]](v *constructions.FiniteDirectPowerModuleElement[E, S]) (*Ciphertext[E, S], error) {
	if v == nil {
		return nil, encryption.ErrIsNil.WithMessage("ciphertext group element")
	}
	if len(v.Components()) != 2 {
		return nil, encryption.ErrFailed.WithMessage("ciphertext group element must have exactly 2 components")
	}
	out, err := NewCiphertext(v.Components()[0], v.Components()[1])
	if err != nil {
		return nil, errs.Wrap(err).WithMessage("failed to create ciphertext from group element")
	}
	return out, nil
}

// Ciphertext is a pair (c₁, c₂) = (g^r, m · h^r) in G × G,
// represented as an element of the direct-power module G².
type Ciphertext[E FiniteCyclicGroupElement[E, S], S algebra.UintLike[S]] struct {
	v *constructions.FiniteDirectPowerModuleElement[E, S]
}

type ciphertextDTO[E FiniteCyclicGroupElement[E, S], S algebra.UintLike[S]] struct {
	V *constructions.FiniteDirectPowerModuleElement[E, S] `cbor:"v"`
}

// Value returns the underlying direct-power module element (c₁, c₂).
func (ct *Ciphertext[E, S]) Value() *constructions.FiniteDirectPowerModuleElement[E, S] {
	return ct.v
}

// Equal reports whether two ciphertexts have identical components.
func (ct *Ciphertext[E, S]) Equal(x *Ciphertext[E, S]) bool {
	if ct == nil || x == nil {
		return ct == x
	}
	return ct.v.Equal(x.v)
}

// HashCode returns a non-cryptographic hash of the ciphertext for use as a map key.
func (ct *Ciphertext[E, S]) HashCode() base.HashCode {
	return ct.v.HashCode()
}

// MarshalCBOR encodes the ciphertext's two group-element components.
func (ct *Ciphertext[E, S]) MarshalCBOR() ([]byte, error) {
	dto := &ciphertextDTO[E, S]{
		V: ct.v,
	}
	out, err := serde.MarshalCBOR(dto)
	if err != nil {
		return nil, errs.Wrap(err).WithMessage("could not marshal ciphertext")
	}
	return out, nil
}

// UnmarshalCBOR decodes a ciphertext and re-validates its components through
// NewCiphertext (non-nil and torsion-free). This is a deserialization trust
// boundary: it rejects components outside the prime-order subgroup, which would
// otherwise enable small-subgroup attacks.
func (ct *Ciphertext[E, S]) UnmarshalCBOR(data []byte) error {
	dto, err := serde.UnmarshalCBOR[*ciphertextDTO[E, S]](data)
	if err != nil {
		return errs.Wrap(err).WithMessage("could not unmarshal ciphertext")
	}
	if dto.V == nil {
		return encryption.ErrIsNil.WithMessage("ciphertext component V is nil")
	}
	ctt, err := NewCiphertext(dto.V.Components()[0], dto.V.Components()[1])
	if err != nil {
		return errs.Wrap(err).WithMessage("could not create ciphertext from unmarshaled components")
	}
	*ct = *ctt
	return nil
}

// NewNonce constructs an encryption nonce from a scalar r ∈ Z/nZ.
// It rejects r = 0, which would produce the degenerate ciphertext (identity, m)
// and leak the plaintext directly.
func NewNonce[S algebra.UintLike[S]](v S) (*Nonce[S], error) {
	if utils.IsNil(v) {
		return nil, encryption.ErrIsNil.WithMessage("nonce value")
	}
	if v.IsOpIdentity() {
		return nil, encryption.ErrFailed.WithMessage("nonce value cannot be the identity element")
	}
	return &Nonce[S]{v: v}, nil
}

// Nonce is the randomness r used during encryption: c = (g^r, m · h^r).
// Reusing a nonce across two encryptions under the same key leaks the
// ratio of the two plaintexts.
type Nonce[S algebra.UintLike[S]] struct {
	v S
}

type nonceDTO[S algebra.UintLike[S]] struct {
	V S `cbor:"v"`
}

// Value returns the scalar r.
func (n *Nonce[S]) Value() S {
	return n.v
}

// Equal reports whether two nonces have the same scalar value.
func (n *Nonce[S]) Equal(x *Nonce[S]) bool {
	if n == nil || x == nil {
		return n == x
	}
	return n.v.Equal(x.v)
}

// HashCode returns a non-cryptographic hash of the nonce for use as a map key.
func (n *Nonce[S]) HashCode() base.HashCode {
	return n.v.HashCode()
}

// MarshalCBOR encodes the nonce scalar. The output is secret material.
func (n *Nonce[S]) MarshalCBOR() ([]byte, error) {
	dto := &nonceDTO[S]{
		V: n.v,
	}
	out, err := serde.MarshalCBOR(dto)
	if err != nil {
		return nil, errs.Wrap(err).WithMessage("could not marshal nonce")
	}
	return out, nil
}

// UnmarshalCBOR decodes a nonce scalar, re-applying NewNonce's non-zero check.
func (n *Nonce[S]) UnmarshalCBOR(data []byte) error {
	dto, err := serde.UnmarshalCBOR[*nonceDTO[S]](data)
	if err != nil {
		return errs.Wrap(err).WithMessage("could not unmarshal nonce")
	}
	nn, err := NewNonce(dto.V)
	if err != nil {
		return errs.Wrap(err).WithMessage("could not create nonce from unmarshaled value")
	}
	*n = *nn
	return nil
}

// NewPlaintext wraps a group element as an ElGamal plaintext.
// In generalised ElGamal the message space is the group G itself;
// encoding application-level data into group elements is the caller's
// responsibility.
func NewPlaintext[E FiniteCyclicGroupElement[E, S], S algebra.UintLike[S]](v E) (*Plaintext[E, S], error) {
	if utils.IsNil(v) {
		return nil, encryption.ErrIsNil.WithMessage("plaintext value")
	}
	return &Plaintext[E, S]{v: v}, nil
}

// Plaintext is a group element m ∈ G to be encrypted.
type Plaintext[E FiniteCyclicGroupElement[E, S], S algebra.UintLike[S]] struct {
	v E
}

type plaintextDTO[E FiniteCyclicGroupElement[E, S], S algebra.UintLike[S]] struct {
	V E `cbor:"v"`
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

// HashCode returns a non-cryptographic hash of the plaintext for use as a map key.
func (p *Plaintext[E, S]) HashCode() base.HashCode {
	return p.v.HashCode()
}

// MarshalCBOR encodes the plaintext group element.
func (p *Plaintext[E, S]) MarshalCBOR() ([]byte, error) {
	dto := &plaintextDTO[E, S]{
		V: p.v,
	}
	out, err := serde.MarshalCBOR(dto)
	if err != nil {
		return nil, errs.Wrap(err).WithMessage("could not marshal plaintext")
	}
	return out, nil
}

// UnmarshalCBOR decodes a plaintext group element, rejecting nil via NewPlaintext.
func (p *Plaintext[E, S]) UnmarshalCBOR(data []byte) error {
	dto, err := serde.UnmarshalCBOR[*plaintextDTO[E, S]](data)
	if err != nil {
		return errs.Wrap(err).WithMessage("could not unmarshal plaintext")
	}
	pp, err := NewPlaintext(dto.V)
	if err != nil {
		return errs.Wrap(err).WithMessage("could not create plaintext from unmarshaled value")
	}
	*p = *pp
	return nil
}
