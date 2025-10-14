package paillier

import (
	"io"

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
	return &CiphertextSpace{PaillierGroup: g}, nil
}

type CiphertextSpace struct {
	znstar.PaillierGroup
}

func (cts *CiphertextSpace) N2() *num.NatPlus {
	return cts.PaillierGroup.Modulus()
}

func (cts *CiphertextSpace) Sample(prng io.Reader) (*Ciphertext, error) {
	v, err := cts.PaillierGroup.Random(prng)
	if err != nil {
		return nil, errs.WrapRandomSample(err, "failed to sample from ciphertext space")
	}
	return (*Ciphertext)(v), nil
}

func (cts *CiphertextSpace) New(x *numct.Nat) (*Ciphertext, error) {
	y, err := num.NewUintGivenModulus(x, cts.N2().ModulusCT())
	if err != nil {
		return nil, errs.WrapFailed(err, "failed to create ciphertext from nat")
	}
	u, err := cts.PaillierGroup.FromUint(y)
	if err != nil {
		return nil, errs.WrapFailed(err, "failed to create ciphertext from n")
	}
	return (*Ciphertext)(u), nil
}

func (cts *CiphertextSpace) Contains(ct *Ciphertext) bool {
	return ct != nil && cts.N2().Equal(ct.N2())
}

type Ciphertext znstar.Unit

func (ct *Ciphertext) Value() *znstar.Unit {
	return (*znstar.Unit)(ct)
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
	return ct.Mul(other)
}

func (ct *Ciphertext) Mul(other *Ciphertext) *Ciphertext {
	ct.isValid(other)
	return (*Ciphertext)(ct.Value().Mul(other.Value()))
}

func (ct *Ciphertext) Div(other *Ciphertext) *Ciphertext {
	ct.isValid(other)
	return (*Ciphertext)(ct.Value().Div(other.Value()))
}

func (ct *Ciphertext) ScalarOp(scalar *num.Nat) *Ciphertext {
	return ct.ScalarExp(scalar)
}

func (ct *Ciphertext) ScalarExp(scalar *num.Nat) *Ciphertext {
	// TODO: ensure it works for integer
	return (*Ciphertext)(ct.Value().Exp(scalar))
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
	rn, err := pk.CiphertextSpace().PaillierGroup.LiftToNthResidues(nonce.Value())
	if err != nil {
		return nil, errs.WrapFailed(err, "failed to lift nonce to n-th residues")
	}
	// c' = c * r^n mod n^2
	return ct.Mul((*Ciphertext)(rn)), nil
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
