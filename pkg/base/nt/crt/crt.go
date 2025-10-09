package crt

import (
	"sync"

	"github.com/bronlabs/bron-crypto/pkg/base/algebra"
	"github.com/bronlabs/bron-crypto/pkg/base/ct"
	"github.com/bronlabs/bron-crypto/pkg/base/nt/numct"
	"github.com/bronlabs/bron-crypto/pkg/base/utils"
)

// Recombine is a one-shot variant that computes q^{-1} (mod p) on the fly.
func Recombine[M numct.Modulus](mp, mq, p, q *numct.Nat) (*numct.Nat, ct.Bool) {
	params, ok := Precompute[M](p, q)
	return params.Recombine(mp, mq), ok
}

func Precompute[M numct.Modulus](p, q *numct.Nat) (*Params[M], ct.Bool) {
	allOk := p.Coprime(q)
	pM, ok := numct.NewModulus(p)
	allOk &= ok

	pModulus, okT := pM.(M)
	allOk &= utils.BoolTo[ct.Bool](okT)

	// qModP := q mod p
	qModP := new(numct.Nat)
	pModulus.Mod(qModP, q)

	// qInv := (q mod p)^{-1} mod p
	qInv := new(numct.Nat)
	// q must be a unit modulo p (i.e., gcd(p,q)=1)
	allOk &= pModulus.ModInv(qInv, qModP)

	return &Params[M]{
		P:    pModulus,
		QNat: q.Clone(),
		QInv: qInv,
		Cap:  algebra.Capacity(pModulus.BitLen() + q.AnnouncedLen()),
	}, allOk
}

// Params holds reusable data for CRT recombination mod N = p*q.
type Params[M numct.Modulus] struct {
	P    M
	QNat *numct.Nat
	QInv *numct.Nat
	Cap  algebra.Capacity
}

// Recombine reconstructs m (mod p*q) from residues (mp, mq),
// using precomputed q^{-1} (mod p).
//
// m = mq + q * ((mp - mq) * qInv mod p)
func (prm *Params[M]) Recombine(mp, mq *numct.Nat) *numct.Nat {
	// h = (mp - mq) mod p
	h := new(numct.Nat)
	prm.P.ModSub(h, mp, mq)
	// h = h * qInv mod p
	prm.P.ModMul(h, h, prm.QInv)

	// m = mq + (h * q)
	m := new(numct.Nat)
	m.MulCap(h, prm.QNat, prm.Cap)
	m.AddCap(m, mq, prm.Cap)
	return m
}

func (prm *Params[M]) Extended() (*ParamsExtended[M], ct.Bool) {
	qM, ok := numct.NewModulus(prm.QNat)
	qModulus, okT := qM.(M)
	ok &= utils.BoolTo[ct.Bool](okT)
	return &ParamsExtended[M]{
		Params: *prm,
		PNat:   prm.P.Nat(),
		Q:      qModulus,
	}, ok
}

func PrecomputePairExtended[M numct.Modulus](p, q *numct.Nat) (*ParamsExtended[M], ct.Bool) {
	prm, ok1 := Precompute[M](p, q)
	prmx, ok2 := prm.Extended()
	return prmx, ok1 & ok2
}

func NewParamsExtended[F numct.Modulus](p, q F) (*ParamsExtended[F], ct.Bool) {
	qNat := q.Nat()
	pNat := p.Nat()

	ok := pNat.Coprime(qNat)

	// qModP := q mod p
	qModP := new(numct.Nat)
	p.Mod(qModP, qNat)

	// qInv := (q mod p)^{-1} mod p
	qInv := new(numct.Nat)
	// q must be a unit modulo p (i.e., gcd(p,q)=1)
	ok &= p.ModInv(qInv, qModP)

	var mNat numct.Nat
	mNat.Mul(pNat, qNat)
	m, okT := numct.NewModulus(&mNat)
	ok &= okT

	return &ParamsExtended[F]{
		Params: Params[F]{
			P:    p,
			QNat: qNat,
			QInv: qInv,
			Cap:  algebra.Capacity(p.BitLen() + qNat.TrueLen()),
		},
		PNat: pNat,
		Q:    q,
		M:    m,
	}, ok
}

type ParamsExtended[F numct.Modulus] struct {
	Params[F]
	PNat *numct.Nat
	Q    F
	M    numct.Modulus
}

func (prmx *ParamsExtended[F]) Modulus() numct.Modulus {
	return prmx.M
}

func (prmx *ParamsExtended[M]) Decompose(m M) (mp, mq *numct.Nat) {
	if m.BitLen() <= 4096 {
		return prmx.DecomposeSerial(m)
	}
	return prmx.DecomposeParallel(m)
}

// DecomposeParallel returns (m mod p, m mod q).
func (prmx *ParamsExtended[M]) DecomposeParallel(m M) (mp, mq *numct.Nat) {
	mpt := new(numct.Nat)
	mqt := new(numct.Nat)
	var wg sync.WaitGroup
	wg.Add(2)
	go func() {
		defer wg.Done()
		// Compute m.Nat() mod p
		prmx.P.Mod(mpt, m.Nat())
	}()
	go func() {
		defer wg.Done()
		// Compute m.Nat() mod q
		prmx.Q.Mod(mqt, m.Nat())
	}()
	wg.Wait()
	return mpt, mqt
}

func (prmx *ParamsExtended[M]) DecomposeSerial(m M) (mp, mq *numct.Nat) {
	mpt := new(numct.Nat)
	mqt := new(numct.Nat)
	// Compute m.Nat() mod p
	prmx.P.Mod(mpt, m.Nat())
	// Compute m.Nat() mod q
	prmx.Q.Mod(mqt, m.Nat())
	return mpt, mqt
}
