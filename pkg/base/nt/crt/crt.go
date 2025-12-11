package crt

import (
	"sync"

	"github.com/bronlabs/bron-crypto/pkg/base/ct"
	"github.com/bronlabs/bron-crypto/pkg/base/nt/numct"
)

// Recombine is a one-shot variant that computes q^{-1} (mod p) on the fly.
func Recombine(mp, mq, p, q *numct.Nat) (*numct.Nat, ct.Bool) {
	params, ok := Precompute(p, q)
	return params.Recombine(mp, mq), ok
}

func Precompute(p, q *numct.Nat) (*Params, ct.Bool) {
	allOk := p.Coprime(q)
	pModulus, ok := numct.NewModulus(p)
	allOk &= ok

	// qModP := q mod p
	qModP := new(numct.Nat)
	pModulus.Mod(qModP, q)

	// qInv := (q mod p)^{-1} mod p
	qInv := new(numct.Nat)
	// q must be a unit modulo p (i.e., gcd(p,q)=1)
	allOk &= pModulus.ModInv(qInv, qModP)

	return &Params{
		P:    pModulus,
		QNat: q.Clone(),
		QInv: qInv,
		Cap:  int(pModulus.BitLen() + q.AnnouncedLen()),
	}, allOk
}

// Params holds reusable data for CRT recombination mod N = p*q.
type Params struct {
	P    *numct.Modulus
	QNat *numct.Nat
	QInv *numct.Nat
	Cap  int
}

// Recombine reconstructs m (mod p*q) from residues (mp, mq),
// using precomputed q^{-1} (mod p).
//
// m = mq + q * ((mp - mq) * qInv mod p).
func (prm *Params) Recombine(mp, mq *numct.Nat) *numct.Nat {
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

// Extended returns an extended ParamsExtended structure
func (prm *Params) Extended() (*ParamsExtended, ct.Bool) {
	qModulus, ok := numct.NewModulus(prm.QNat)
	return &ParamsExtended{
		Params: *prm,
		PNat:   prm.P.Nat(),
		Q:      qModulus,
	}, ok
}

// PrecomputePairExtended is a one-shot variant that precomputes extended CRT parameters.
func PrecomputePairExtended(p, q *numct.Nat) (*ParamsExtended, ct.Bool) {
	prm, ok1 := Precompute(p, q)
	prmx, ok2 := prm.Extended()
	return prmx, ok1 & ok2
}

// NewParamsExtended constructs extended CRT parameters from given moduli p and q.
func NewParamsExtended(p, q *numct.Modulus) (*ParamsExtended, ct.Bool) {
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

	return &ParamsExtended{
		Params: Params{
			P:    p,
			QNat: qNat,
			QInv: qInv,
			Cap:  int(p.BitLen() + qNat.TrueLen()),
		},
		PNat: pNat,
		Q:    q,
		M:    m,
	}, ok
}

// ParamsExtended holds reusable data for CRT recombination mod N = p*q,
// along with extended functionality such as modulus decomposition.
type ParamsExtended struct {
	Params

	PNat *numct.Nat
	Q    *numct.Modulus
	M    *numct.Modulus
}

// Modulus returns the modulus N = p * q.
func (prmx *ParamsExtended) Modulus() *numct.Modulus {
	return prmx.M
}

// Decompose returns (m mod p, m mod q).
func (prmx *ParamsExtended) Decompose(m *numct.Modulus) (mp, mq *numct.Nat) {
	if m.BitLen() <= 4096 {
		return prmx.DecomposeSerial(m)
	}
	return prmx.DecomposeParallel(m)
}

// DecomposeParallel returns (m mod p, m mod q), computed in parallel.
func (prmx *ParamsExtended) DecomposeParallel(m *numct.Modulus) (mp, mq *numct.Nat) {
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

// DecomposeSerial returns (m mod p, m mod q), computed serially.
func (prmx *ParamsExtended) DecomposeSerial(m *numct.Modulus) (mp, mq *numct.Nat) {
	mpt := new(numct.Nat)
	mqt := new(numct.Nat)
	// Compute m.Nat() mod p
	prmx.P.Mod(mpt, m.Nat())
	// Compute m.Nat() mod q
	prmx.Q.Mod(mqt, m.Nat())
	return mpt, mqt
}
