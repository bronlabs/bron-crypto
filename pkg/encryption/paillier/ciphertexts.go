package paillier

import (
	"io"

	"github.com/bronlabs/errs-go/errs"

	"github.com/bronlabs/bron-crypto/pkg/base"
	"github.com/bronlabs/bron-crypto/pkg/base/ct"
	"github.com/bronlabs/bron-crypto/pkg/base/nt/num"
	"github.com/bronlabs/bron-crypto/pkg/base/nt/numct"
	"github.com/bronlabs/bron-crypto/pkg/base/nt/znstar"
)

// NewCiphertextSpace creates a new ciphertext space for Paillier encryption.
// The space is the multiplicative group (Z/n²Z)* where n² is the modulus.
func NewCiphertextSpace(n2, n *num.NatPlus) (*CiphertextSpace, error) {
	g, err := znstar.NewPaillierGroupOfUnknownOrder(n2, n)
	if err != nil {
		return nil, errs.Wrap(err)
	}
	return &CiphertextSpace{g: g}, nil
}

// CiphertextSpace represents the space of Paillier ciphertexts modulo n^2.
type CiphertextSpace struct {
	g *znstar.PaillierGroupUnknownOrder
}

// Group returns the underlying Paillier group of unknown order.
func (cts *CiphertextSpace) Group() *znstar.PaillierGroupUnknownOrder {
	return cts.g
}

// N2 returns the modulus n^2 of the ciphertext space.
func (cts *CiphertextSpace) N2() *num.NatPlus {
	return cts.g.Modulus()
}

// Sample samples a random ciphertext from the ciphertext space.
func (cts *CiphertextSpace) Sample(prng io.Reader) (*Ciphertext, error) {
	u, err := cts.g.Random(prng)
	if err != nil {
		return nil, errs.Wrap(err)
	}
	return &Ciphertext{u: u}, nil
}

// New creates a new ciphertext from a natural number.
func (cts *CiphertextSpace) New(x *numct.Nat) (*Ciphertext, error) {
	y, err := num.NewUintGivenModulus(x, cts.N2().ModulusCT())
	if err != nil {
		return nil, errs.Wrap(err)
	}
	u, err := cts.g.FromUint(y)
	if err != nil {
		return nil, errs.Wrap(err)
	}
	return &Ciphertext{u: u}, nil
}

// NewCiphertextFromUnit creates a new ciphertext from a Paillier group element.
func NewCiphertextFromUnit(u *znstar.PaillierGroupElementUnknownOrder) *Ciphertext {
	return &Ciphertext{u: u}
}

// Contains returns true if the ciphertext belongs to this ciphertext space.
func (cts *CiphertextSpace) Contains(ctx *Ciphertext) bool {
	return ctx != nil &&
		cts.N2().Equal(ctx.N2()) &&
		cts.g.N().Equal(ctx.Value().N()) &&
		cts.g.Arithmetic().Modulus().Nat().Equal(ctx.Value().Arithmetic().Modulus().Nat()) == ct.True
}

// Ciphertext represents an encrypted Paillier message in the group (Z/n²Z)*.
type Ciphertext struct {
	u *znstar.PaillierGroupElementUnknownOrder
}

// Value returns the underlying group element.
func (ctx *Ciphertext) Value() *znstar.PaillierGroupElementUnknownOrder {
	return ctx.u
}

// ValueCT returns the ciphertext value as a constant-time natural number.
func (ctx *Ciphertext) ValueCT() *numct.Nat {
	return ctx.Value().Value().Value()
}

// N2 returns the modulus n² of the ciphertext.
func (ctx *Ciphertext) N2() *num.NatPlus {
	return ctx.Value().Modulus()
}

func (ctx *Ciphertext) isValid(x *Ciphertext) {
	if x == nil {
		panic("cannot operate on nil ciphertexts")
	}
	if !ctx.N2().Equal(x.N2()) {
		panic("cannot operate on ciphertexts with different moduli")
	}
}

// Op multiplies two ciphertexts in the group (Z/n²Z)*, which corresponds
// to addition of the underlying plaintexts in the Paillier scheme.
func (ctx *Ciphertext) Op(other *Ciphertext) *Ciphertext {
	ctx.isValid(other)
	v := ctx.Value().ForgetOrder().Mul(other.Value().ForgetOrder())
	return &Ciphertext{u: v}
}

// HomAdd performs homomorphic addition of two ciphertexts.
// The result decrypts to the sum of the two plaintexts: Dec(HomAdd(c1, c2)) = m1 + m2.
func (ctx *Ciphertext) HomAdd(other *Ciphertext) *Ciphertext {
	return ctx.Op(other)
}

// HomSub performs homomorphic subtraction of two ciphertexts.
// The result decrypts to the difference of the two plaintexts: Dec(HomSub(c1, c2)) = m1 - m2.
func (ctx *Ciphertext) HomSub(other *Ciphertext) *Ciphertext {
	ctx.isValid(other)
	return &Ciphertext{u: ctx.Value().Div(other.Value())}
}

// ScalarOp exponentiates a ciphertext by a scalar, which corresponds to
// multiplication of the underlying plaintext by the scalar in the Paillier scheme.
func (ctx *Ciphertext) ScalarOp(scalar *num.Nat) *Ciphertext {
	return &Ciphertext{u: ctx.Value().Exp(scalar)}
}

// ScalarOpBounded exponentiates a ciphertext by a scalar with a known bit bound.
// This is more efficient than ScalarOp when the scalar is known to be small.
func (ctx *Ciphertext) ScalarOpBounded(scalar *num.Nat, bits uint) *Ciphertext {
	return &Ciphertext{u: ctx.Value().ExpBounded(scalar, bits)}
}

// ScalarMul performs homomorphic scalar multiplication of a ciphertext.
// The result decrypts to the product of the plaintext and scalar: Dec(ScalarMul(c, k)) = m * k.
func (ctx *Ciphertext) ScalarMul(scalar *num.Nat) *Ciphertext {
	return ctx.ScalarOp(scalar)
}

// ScalarMulBounded performs homomorphic scalar multiplication with a known bit bound.
// This is more efficient than ScalarMul when the scalar is known to be small.
func (ctx *Ciphertext) ScalarMulBounded(scalar *num.Nat, bits uint) *Ciphertext {
	return ctx.ScalarOpBounded(scalar, bits)
}

// ReRandomise re-randomises a ciphertext by multiplying it with a fresh encryption of zero.
// This produces a new ciphertext that decrypts to the same plaintext but is unlinkable
// to the original. Returns the new ciphertext and the nonce used.
func (ctx *Ciphertext) ReRandomise(pk *PublicKey, prng io.Reader) (*Ciphertext, *Nonce, error) {
	nonce, err := pk.NonceSpace().Sample(prng)
	if err != nil {
		return nil, nil, errs.Wrap(err)
	}
	ciphertext, err := ctx.ReRandomiseWithNonce(pk, nonce)
	if err != nil {
		return nil, nil, errs.Wrap(err)
	}
	return ciphertext, nonce, nil
}

// ReRandomiseWithNonce re-randomises a ciphertext using a provided nonce.
// The result is c' = c * r^n mod n², which decrypts to the same plaintext as c.
func (ctx *Ciphertext) ReRandomiseWithNonce(pk *PublicKey, nonce *Nonce) (*Ciphertext, error) {
	g := pk.CiphertextSpace().g
	embeddedNonce, err := g.EmbedRSA(nonce.Value())
	if err != nil {
		return nil, errs.Wrap(err)
	}
	rn, err := g.NthResidue(embeddedNonce)
	if err != nil {
		return nil, errs.Wrap(err)
	}
	// c' = c * r^n mod n^2
	return &Ciphertext{u: ctx.Value().Mul(rn)}, nil
}

// Equal returns true if two ciphertexts are equal.
func (ctx *Ciphertext) Equal(other *Ciphertext) bool {
	return ctx.Value().Equal(other.Value())
}

// Shift adds a plaintext value to an encrypted ciphertext without re-randomization.
// This is useful for adjusting ciphertexts by known values without changing randomness.
func (ctx *Ciphertext) Shift(pk *PublicKey, message *Plaintext) (*Ciphertext, error) {
	gDeltaM, err := pk.group.Representative(message.ValueCT())
	if err != nil {
		return nil, errs.Wrap(err)
	}
	return &Ciphertext{u: ctx.u.Mul(gDeltaM)}, nil
}

// HashCode returns a hash code for the ciphertext.
func (ctx *Ciphertext) HashCode() base.HashCode {
	return ctx.Value().HashCode()
}

func (ctx *Ciphertext) Bytes() []byte {
	if ctx == nil || ctx.u == nil {
		return nil
	}

	return ctx.u.Bytes()
}
