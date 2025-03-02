package modular

import (
	"github.com/bronlabs/krypton-primitives/pkg/base/errs"
	"github.com/bronlabs/krypton-primitives/pkg/base/utils/numutils"
	"github.com/cronokirby/saferith"
	"golang.org/x/sync/errgroup"
)

type FastModulus interface {
	Modulus() *saferith.Modulus
	Exp(b *saferith.Nat, e *saferith.Nat) (*saferith.Nat, error)
	MultiBaseExp(b []*saferith.Nat, e *saferith.Nat) ([]*saferith.Nat, error)
	Square() FastModulus
}

var one = new(saferith.Nat).SetUint64(1).Resize(1)

type oddModulus struct {
	n *saferith.Modulus
}

func NewFastModulus(n *saferith.Nat) (FastModulus, error) {
	if n == nil {
		return nil, errs.NewIsNil("n is nil")
	}
	if n.Byte(0)%2 != 1 {
		return nil, errs.NewValidation("n must be odd")
	}

	return &oddModulus{n: saferith.ModulusFromNat(n)}, nil
}

func (m *oddModulus) Square() FastModulus {
	return &oddModulus{n: saferith.ModulusFromNat(new(saferith.Nat).Mul(m.n.Nat(), m.n.Nat(), 2*m.n.BitLen()))}
}

func (m *oddModulus) Modulus() *saferith.Modulus {
	return m.n
}

func (m *oddModulus) Exp(b, e *saferith.Nat) (*saferith.Nat, error) {
	return FastExp(b, e, m.n)
}

func (m *oddModulus) MultiBaseExp(b []*saferith.Nat, e *saferith.Nat) ([]*saferith.Nat, error) {
	return FastMultiBaseExp(b, e, m.n)
}

type primeFactorsModulus struct {
	p    *saferith.Modulus
	phiP *saferith.Modulus
	q    *saferith.Modulus
	phiQ *saferith.Modulus
	qInv *saferith.Nat
	n    *saferith.Modulus
}

func NewFastModulusFromPrimeFactors(p *saferith.Nat, q *saferith.Nat) (FastModulus, error) {
	if p == nil || q == nil {
		return nil, errs.NewIsNil("p and q cannot be nil")
	}
	if p.Eq(q) == 1 {
		return nil, errs.NewValidation("p cannot be equal to q")
	}
	if !p.Big().ProbablyPrime(2) || !q.Big().ProbablyPrime(2) {
		return nil, errs.NewValidation("factors must be primes")
	}

	pMod := saferith.ModulusFromNat(p)
	qMod := saferith.ModulusFromNat(q)
	phiP := saferith.ModulusFromNat(new(saferith.Nat).Sub(p, one, pMod.BitLen()))
	phiQ := saferith.ModulusFromNat(new(saferith.Nat).Sub(q, one, qMod.BitLen()))
	qInv := new(saferith.Nat).ModInverse(q, pMod)
	n := saferith.ModulusFromNat(new(saferith.Nat).Mul(p, q, pMod.BitLen()+qMod.BitLen()))

	return &primeFactorsModulus{
		p:    pMod,
		phiP: phiP,
		q:    qMod,
		phiQ: phiQ,
		qInv: qInv,
		n:    n,
	}, nil
}

func (m *primeFactorsModulus) Modulus() *saferith.Modulus {
	return m.n
}

func (m *primeFactorsModulus) Exp(b *saferith.Nat, e *saferith.Nat) (*saferith.Nat, error) {
	ep := new(saferith.Nat).Mod(e, m.phiP)
	eq := new(saferith.Nat).Mod(e, m.phiQ)

	var rp, rq *saferith.Nat
	var eg errgroup.Group
	eg.Go(func() error {
		var err error
		rp, err = FastExp(b, ep, m.p)
		return err
	})
	eg.Go(func() error {
		var err error
		rq, err = FastExp(b, eq, m.q)
		return err
	})
	err := eg.Wait()
	if err != nil {
		return nil, errs.WrapFailed(err, "failed to exponentiate")
	}

	return numutils.CrtWithPrecomputation(rp, rq, m.p, m.q.Nat(), m.qInv), nil
}

func (m *primeFactorsModulus) MultiBaseExp(b []*saferith.Nat, e *saferith.Nat) ([]*saferith.Nat, error) {
	ep := new(saferith.Nat).Mod(e, m.phiP)
	eq := new(saferith.Nat).Mod(e, m.phiQ)

	var rp, rq []*saferith.Nat
	var eg errgroup.Group
	eg.Go(func() error {
		var err error
		rp, err = FastMultiBaseExp(b, ep, m.p)
		return err
	})
	eg.Go(func() error {
		var err error
		rq, err = FastMultiBaseExp(b, eq, m.q)
		return err
	})
	err := eg.Wait()
	if err != nil {
		return nil, errs.WrapFailed(err, "failed to exponentiate")
	}

	r := make([]*saferith.Nat, len(b))
	for i := range b {
		r[i] = numutils.CrtWithPrecomputation(rp[i], rq[i], m.p, m.q.Nat(), m.qInv)
	}
	return r, nil
}

func (m *primeFactorsModulus) Square() FastModulus {
	ppMod := saferith.ModulusFromNat(new(saferith.Nat).Mul(m.p.Nat(), m.p.Nat(), 2*m.p.BitLen()))
	qqMod := saferith.ModulusFromNat(new(saferith.Nat).Mul(m.q.Nat(), m.q.Nat(), 2*m.q.BitLen()))
	phiPP := saferith.ModulusFromNat(new(saferith.Nat).Mul(m.phiP.Nat(), m.p.Nat(), 2*m.p.BitLen()))
	phiQQ := saferith.ModulusFromNat(new(saferith.Nat).Mul(m.phiQ.Nat(), m.q.Nat(), 2*m.p.BitLen()))
	qqInv := new(saferith.Nat).ModInverse(qqMod.Nat(), ppMod)
	nn := saferith.ModulusFromNat(new(saferith.Nat).Mul(ppMod.Nat(), qqMod.Nat(), ppMod.BitLen()+qqMod.BitLen()))

	return &primeFactorsModulus{
		p:    ppMod,
		phiP: phiPP,
		q:    qqMod,
		phiQ: phiQQ,
		qInv: qqInv,
		n:    nn,
	}
}
