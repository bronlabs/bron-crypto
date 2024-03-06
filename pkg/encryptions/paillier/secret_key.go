package paillier

import (
	"github.com/cronokirby/saferith"

	"github.com/copperexchange/krypton-primitives/pkg/base/errs"
)

type SecretKeyPrecomputed struct {
	Mu *saferith.Nat
}

type SecretKey struct {
	PublicKey
	Phi         *saferith.Nat
	precomputed *SecretKeyPrecomputed
}

func NewSecretKey(p, q *saferith.Nat) (*SecretKey, error) {
	if p == nil || q == nil {
		return nil, errs.NewIsNil("p or q")
	}
	if p.TrueLen() != q.TrueLen() {
		return nil, errs.NewFailed("unsupported p/q size (must be of equivalent length)")
	}

	pMinusOne := new(saferith.Nat).Sub(p, new(saferith.Nat).SetUint64(1), p.AnnouncedLen())
	qMinusOne := new(saferith.Nat).Sub(q, new(saferith.Nat).SetUint64(1), q.AnnouncedLen())
	n := new(saferith.Nat).Mul(p, q, -1)
	phi := new(saferith.Nat).Mul(pMinusOne, qMinusOne, 2*n.AnnouncedLen())

	key := &SecretKey{
		PublicKey: PublicKey{
			N: n,
		},
		Phi: phi,
	}

	key.PublicKey.precompute()
	key.precompute()

	return key, nil
}

func (sk *SecretKey) GetPrecomputed() *SecretKeyPrecomputed {
	if sk.precomputed == nil {
		sk.precompute()
	}

	return sk.precomputed
}

func (sk *SecretKey) Validate() error {
	if sk == nil {
		return errs.NewIsNil("sk")
	}
	if sk.Phi == nil {
		return errs.NewIsNil("phi")
	}
	if sk.N == nil {
		return errs.NewIsNil("n")
	}

	return nil
}

func (sk *SecretKey) l(x *saferith.Nat) *saferith.Nat {
	n := sk.PublicKey.GetPrecomputed().NModulus

	xMinusOne := new(saferith.Nat).Sub(x, new(saferith.Nat).SetUint64(1), sk.PublicKey.GetPrecomputed().N2Modulus.BitLen())
	l := new(saferith.Nat).Div(xMinusOne, n, n.BitLen())
	return l
}

func (sk *SecretKey) precompute() {
	n := sk.PublicKey.GetPrecomputed().NModulus
	mu := new(saferith.Nat).ModInverse(sk.Phi, n)
	sk.precomputed = &SecretKeyPrecomputed{
		Mu: mu,
	}
}
