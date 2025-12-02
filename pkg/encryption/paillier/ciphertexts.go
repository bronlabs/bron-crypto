package paillier

import (
	"io"

	"github.com/bronlabs/bron-crypto/pkg/base"
	"github.com/bronlabs/bron-crypto/pkg/base/errs"
	"github.com/bronlabs/bron-crypto/pkg/base/nt/num"
	"github.com/bronlabs/bron-crypto/pkg/base/nt/numct"
	"github.com/bronlabs/bron-crypto/pkg/base/nt/znstar"
)

func NewCiphertextSpace(n2, n *num.NatPlus) (*CiphertextSpace, error) {
	g, err := znstar.NewPaillierGroupOfUnknownOrder(n2, n)
	if err != nil {
		return nil, errs.WrapFailed(err, "failed to create unit group for ciphertext space")
	}
	return &CiphertextSpace{g: g}, nil
}

type CiphertextSpace struct {
	g *znstar.PaillierGroupUnknownOrder
}

func (cts *CiphertextSpace) Group() *znstar.PaillierGroupUnknownOrder {
	return cts.g
}

func (cts *CiphertextSpace) N2() *num.NatPlus {
	return cts.g.Modulus()
}

func (cts *CiphertextSpace) Sample(prng io.Reader) (*Ciphertext, error) {
	u, err := cts.g.Random(prng)
	if err != nil {
		return nil, errs.WrapRandomSample(err, "failed to sample from ciphertext space")
	}
	return &Ciphertext{u: u}, nil
}

func (cts *CiphertextSpace) New(x *numct.Nat) (*Ciphertext, error) {
	y, err := num.NewUintGivenModulus(x, cts.N2().ModulusCT())
	if err != nil {
		return nil, errs.WrapFailed(err, "failed to create ciphertext from nat")
	}
	u, err := cts.g.FromUint(y)
	if err != nil {
		return nil, errs.WrapFailed(err, "failed to create ciphertext from n")
	}
	return &Ciphertext{u: u}, nil
}

func NewCiphertextFromUnit(u *znstar.PaillierGroupUnknownOrderElement) *Ciphertext {
	return &Ciphertext{u: u}
}

func (cts *CiphertextSpace) Contains(ct *Ciphertext) bool {
	return ct != nil && cts.N2().Equal(ct.N2())
}

type Ciphertext struct {
	u *znstar.PaillierGroupUnknownOrderElement
}

func (ct *Ciphertext) Value() *znstar.PaillierGroupUnknownOrderElement {
	return ct.u
}

func (ct *Ciphertext) ValueCT() *numct.Nat {
	return ct.Value().Value().Value()
}

func (ct *Ciphertext) N2() *num.NatPlus {
	return ct.Value().Modulus()
}

func (ct *Ciphertext) isValid(x *Ciphertext) {
	if x == nil {
		panic("cannot operate on nil ciphertexts")
	}
	if !ct.N2().Equal(x.N2()) {
		panic("cannot operate on ciphertexts with different moduli")
	}
}

func (ct *Ciphertext) Op(other *Ciphertext) *Ciphertext {
	ct.isValid(other)
	// TODO: handle forget order better
	v := ct.Value().ForgetOrder().Mul(other.Value().ForgetOrder())
	return &Ciphertext{u: v}
}

func (ct *Ciphertext) HomAdd(other *Ciphertext) *Ciphertext {
	return ct.Op(other)
}

func (ct *Ciphertext) HomSub(other *Ciphertext) *Ciphertext {
	ct.isValid(other)
	return &Ciphertext{u: ct.Value().Div(other.Value())}
}

func (ct *Ciphertext) ScalarOp(scalar *num.Nat) *Ciphertext {
	// TODO: ensure it works for integer
	return &Ciphertext{u: ct.Value().Exp(scalar)}
}

func (ct *Ciphertext) ScalarOpBounded(scalar *num.Nat, bits uint) *Ciphertext {
	return &Ciphertext{u: ct.Value().ExpBounded(scalar, bits)}
}

func (ct *Ciphertext) ScalarMul(scalar *num.Nat) *Ciphertext {
	return ct.ScalarOp(scalar)
}

func (ct *Ciphertext) ScalarMulBounded(scalar *num.Nat, bits uint) *Ciphertext {
	return ct.ScalarOpBounded(scalar, bits)
}

func (ct *Ciphertext) ReRandomise(pk *PublicKey, prng io.Reader) (*Ciphertext, *Nonce, error) {
	nonce, err := pk.NonceSpace().Sample(prng)
	if err != nil {
		return nil, nil, errs.WrapRandomSample(err, "failed to sample nonce from nonce space")
	}
	ciphertext, err := ct.ReRandomiseWithNonce(pk, nonce)
	if err != nil {
		return nil, nil, errs.WrapFailed(err, "failed to re-randomise with nonce")
	}
	return ciphertext, nonce, nil
}

func (ct *Ciphertext) ReRandomiseWithNonce(pk *PublicKey, nonce *Nonce) (*Ciphertext, error) {
	g := pk.CiphertextSpace().g
	embeddedNonce, err := g.EmbedRSA(nonce.Value())
	if err != nil {
		return nil, errs.WrapFailed(err, "failed to embed nonce in the paillier group")
	}
	rn, err := g.NthResidue(embeddedNonce)
	if err != nil {
		return nil, errs.WrapFailed(err, "failed to lift nonce to n-th residues")
	}
	// c' = c * r^n mod n^2
	return &Ciphertext{u: ct.Value().Mul(rn)}, nil
}

func (ct *Ciphertext) Equal(other *Ciphertext) bool {
	return ct.Value().Equal(other.Value())
}

func (ct *Ciphertext) Shift(message *Plaintext) *Ciphertext {
	// Phi()
	// var out numct.Nat
	// receiver.n2.ModMul(&out, plaintext.ValueCT(), receiver.nNat)
	// out.Increment()
	return nil
}

func (ct *Ciphertext) HashCode() base.HashCode {
	return ct.Value().HashCode()
}
