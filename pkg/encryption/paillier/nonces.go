package paillier

import (
	"io"

	"github.com/bronlabs/bron-crypto/pkg/base/nt/num"
	"github.com/bronlabs/bron-crypto/pkg/base/nt/numct"
	"github.com/bronlabs/bron-crypto/pkg/base/nt/znstar"
	"github.com/bronlabs/errs-go/pkg/errs"
)

// NewNonceSpace creates a new nonce space (Z/nZ)* for Paillier encryption.
// The nonce space is the multiplicative group of units modulo n.
func NewNonceSpace(n *num.NatPlus) (*NonceSpace, error) {
	g, err := znstar.NewRSAGroupOfUnknownOrder(n)
	if err != nil {
		return nil, errs.Wrap(err)
	}
	return &NonceSpace{g: g}, nil
}

// NonceSpace represents the space of Paillier nonces (Z/nZ)*.
// Nonces are used to randomise ciphertexts for semantic security.
type NonceSpace struct {
	g *znstar.RSAGroupUnknownOrder
}

// N returns the modulus n of the nonce space.
func (ns *NonceSpace) N() *num.NatPlus {
	return ns.g.Modulus()
}

// Sample samples a random nonce from the nonce space.
// The nonce is guaranteed to be a unit (coprime to n).
func (ns *NonceSpace) Sample(prng io.Reader) (*Nonce, error) {
	for {
		u, err := ns.g.Random(prng)
		if err != nil {
			return nil, errs.Wrap(err)
		}
		if u.Value().IsUnit() {
			return &Nonce{u: u}, nil
		}
	}
}

// New creates a nonce from a constant-time natural number.
// Returns an error if the value is not a unit modulo n.
func (ns *NonceSpace) New(x *numct.Nat) (*Nonce, error) {
	y, err := num.NewUintGivenModulus(x, ns.N().ModulusCT())
	if err != nil {
		return nil, errs.Wrap(err)
	}
	u, err := ns.g.FromUint(y)
	if err != nil {
		return nil, errs.Wrap(err)
	}
	return &Nonce{u: u}, nil
}

// Contains returns true if the nonce belongs to this nonce space.
func (ns *NonceSpace) Contains(n *Nonce) bool {
	return n != nil && ns.N().Equal(n.N())
}

// Nonce represents a Paillier encryption nonce in the group (Z/nZ)*.
// Nonces provide the randomization needed for semantic security.
type Nonce struct {
	u *znstar.RSAGroupElementUnknownOrder
}

// Value returns the underlying RSA group element.
func (n *Nonce) Value() *znstar.RSAGroupElementUnknownOrder {
	return n.u
}

// Equal returns true if two nonces are equal.
func (n *Nonce) Equal(other *Nonce) bool {
	if n == nil || other == nil {
		return n == other
	}
	return n.Value().Equal(other.Value())
}

// ValueCT returns the nonce value as a constant-time natural number.
func (n *Nonce) ValueCT() *numct.Nat {
	return n.Value().Value().Value()
}

// N returns the modulus n of the nonce.
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

// Op performs the group operation on two nonces (multiplication modulo n).
func (n *Nonce) Op(other *Nonce) *Nonce {
	return n.Mul(other)
}

// Mul multiplies two nonces and returns the result.
func (n *Nonce) Mul(other *Nonce) *Nonce {
	n.isValid(other)
	return &Nonce{u: n.Value().Mul(other.Value())}
}
