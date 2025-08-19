package crt

import (
	"sync"

	"github.com/bronlabs/bron-crypto/pkg/base/algebra"
	"github.com/bronlabs/bron-crypto/pkg/base/ct"
	"github.com/bronlabs/bron-crypto/pkg/base/nt/internal"
)

// RecombinePair is a one-shot variant that computes q^{-1} (mod p) on the fly.
func RecombinePair[M internal.ModulusMutablePtr[N, MT], N internal.NatMutablePtr[N, NT], MT, NT any](
	mp, mq, p, q N,
) (N, ct.Bool) {
	var pModulusT MT
	ok1 := M(&pModulusT).SetNat(p)
	params, ok2 := PrecomputePair(M(&pModulusT), q)
	return params.Recombine(mp, mq), ok1 & ok2
}

func PrecomputePair[M internal.ModulusMutablePtr[N, MT], N internal.NatMutablePtr[N, NT], MT, NT any](p M, q N) (*ParamsPair[M, N, MT, NT], ct.Bool) {
	ok := p.Nat().Coprime(q)
	// qModP := q mod p
	var qModPT NT
	p.Mod(N(&qModPT), q)

	// qInv := (q mod p)^{-1} mod p
	var qInvT NT
	// q must be a unit modulo p (i.e., gcd(p,q)=1)
	ok &= p.ModInv(N(&qInvT), N(&qModPT))

	var pT MT
	M(&pT).Set(p)

	// Store the full q value, not q mod p
	var qT NT
	N(&qT).Set(q)

	return &ParamsPair[M, N, MT, NT]{
		P:    pT,
		Q:    qT,
		QInv: qInvT,
	}, ok
}

// ParamsPair holds reusable data for CRT recombination mod N = p*q.
type ParamsPair[M internal.ModulusMutablePtr[N, MT], N internal.NatMutablePtr[N, NT], MT, NT any] struct {
	P    MT
	Q    NT
	QInv NT
}

// Recombine reconstructs m (mod p*q) from residues (mp, mq),
// using precomputed q^{-1} (mod p).
//
// m = mq + q * ((mp - mq) * qInv mod p)
func (prm *ParamsPair[M, N, MT, NT]) Recombine(mp, mq N) N {
	// h = (mp - mq) mod p
	var h NT
	M(&prm.P).ModSub(N(&h), mp, mq)
	// h = h * qInv mod p
	M(&prm.P).ModMul(N(&h), N(&h), N(&prm.QInv))

	// m = mq + (h * q)
	// Capacity hints: up to roughly p.BitLen() + q.AnnouncedLen()
	capBits := algebra.Capacity(M(&prm.P).BitLen() + N(&prm.Q).TrueLen())
	var m NT
	N(&m).MulCap(N(&h), N(&prm.Q), capBits)
	N(&m).AddCap(N(&m), mq, capBits)
	return N(&m)
}

func (prm *ParamsPair[M, N, MT, NT]) Extended() *ParamsPairExtended[M, N, MT, NT] {
	var pNat NT
	N(&pNat).Set(M(&prm.P).Nat())
	var qModulus MT
	M(&qModulus).SetNat(N(&prm.Q))
	return &ParamsPairExtended[M, N, MT, NT]{
		ParamsPair: *prm,
		PNat:       pNat,
		QModulus:   qModulus,
	}
}

func PrecomputePairExtended[M internal.ModulusMutablePtr[N, MT], N internal.NatMutablePtr[N, NT], MT, NT any](p M, q N) (*ParamsPairExtended[M, N, MT, NT], ct.Bool) {
	prm, ok1 := PrecomputePair(p, q)
	var qModT MT
	ok2 := M(&qModT).SetNat(q)
	var pNat NT
	N(&pNat).Set(M(&prm.P).Nat())
	return &ParamsPairExtended[M, N, MT, NT]{
		ParamsPair: *prm,
		PNat:       pNat,
		QModulus:   qModT,
	}, ok1 & ok2
}

type ParamsPairExtended[M internal.ModulusMutablePtr[N, MT], N internal.NatMutablePtr[N, NT], MT, NT any] struct {
	ParamsPair[M, N, MT, NT]
	PNat     NT
	QModulus MT
}

func (prmx *ParamsPairExtended[M, N, MT, NT]) Decompose(m M) (mp, mq N) {
	// TODO: figure out a way to check optimization at build time
	if m.BitLen() <= 4096 {
		return prmx.DecomposeSerial(m)
	}
	return prmx.DecomposeParallel(m)
}

// DecomposeParallel returns (m mod p, m mod q).
func (prmx *ParamsPairExtended[M, N, MT, NT]) DecomposeParallel(m M) (mp, mq N) {
	var mpt, mqt NT
	var wg sync.WaitGroup
	wg.Add(2)
	go func() {
		defer wg.Done()
		// Compute m.Nat() mod p
		M(&prmx.P).Mod(N(&mpt), m.Nat())
	}()
	go func() {
		defer wg.Done()
		// Compute m.Nat() mod q
		M(&prmx.QModulus).Mod(N(&mqt), m.Nat())
	}()
	wg.Wait()
	return N(&mpt), N(&mqt)
}

func (prmx *ParamsPairExtended[M, N, MT, NT]) DecomposeSerial(m M) (mp, mq N) {
	var mpt, mqt NT
	// Compute m.Nat() mod p
	M(&prmx.P).Mod(N(&mpt), m.Nat())
	// Compute m.Nat() mod q
	M(&prmx.QModulus).Mod(N(&mqt), m.Nat())
	return N(&mpt), N(&mqt)
}
