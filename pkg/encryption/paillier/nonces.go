package paillier

import (
	"io"

	"github.com/bronlabs/bron-crypto/pkg/base/errs"
	"github.com/bronlabs/bron-crypto/pkg/base/nt/num"
	"github.com/bronlabs/bron-crypto/pkg/base/nt/numct"
	"github.com/bronlabs/bron-crypto/pkg/base/nt/znstar"
)

func NewNonceSpace(n *num.NatPlus) (*NonceSpace, error) {
	g, err := znstar.NewRSAGroupOfUnknownOrder(n)
	if err != nil {
		return nil, errs.WrapFailed(err, "failed to create unit group for nonce space")
	}
	return &NonceSpace{g: g}, nil
}

type NonceSpace struct {
	g znstar.RSAGroup
}

func (ns *NonceSpace) N() *num.NatPlus {
	return ns.g.Modulus()
}

func (ns *NonceSpace) Sample(prng io.Reader) (*Nonce, error) {
	v, err := ns.g.Random(prng)
	if err != nil {
		return nil, errs.WrapRandomSample(err, "failed to sample from nonce space")
	}
	return (*Nonce)(v), nil
}

func (ns *NonceSpace) New(x *numct.Nat) (*Nonce, error) {
	y, err := num.NewUintGivenModulus(x, ns.N().ModulusCT())
	if err != nil {
		return nil, errs.WrapFailed(err, "failed to create nonce from nat")
	}
	u, err := ns.g.FromUint(y)
	if err != nil {
		return nil, errs.WrapFailed(err, "failed to create nonce from n")
	}
	return (*Nonce)(u), nil
}

func (ns *NonceSpace) Contains(n *Nonce) bool {
	return n != nil && ns.N().Equal(n.N())
}

type Nonce znstar.Unit

func (n *Nonce) Value() *znstar.Unit {
	return (*znstar.Unit)(n)
}

func (n *Nonce) ValueCT() *numct.Nat {
	return n.Value().Value().Value()
}

func (n *Nonce) N() *num.NatPlus {
	return n.Value().Modulus()
}

func (n *Nonce) isValid(x *Nonce) {
	if x == nil {
		panic("cannot operate on nil nonces")
	}
	if !n.N().Equal(x.N()) {
		panic("cannot operate on nonces with different moduli")
	}
}

func (n *Nonce) Op(other *Nonce) *Nonce {
	return n.Mul(other)
}

func (n *Nonce) Mul(other *Nonce) *Nonce {
	n.isValid(other)
	return (*Nonce)(n.Value().Mul(other.Value()))
}
