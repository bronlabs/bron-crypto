package numutils

import "github.com/cronokirby/saferith"

func CrtWithPrecomputation(mp, mq *saferith.Nat, p *saferith.Modulus, q, qInv *saferith.Nat) *saferith.Nat {
	h := new(saferith.Nat).ModSub(mp, mq, p)
	h.ModMul(h, qInv, p)
	m := new(saferith.Nat).Mul(h, q, p.BitLen()+q.AnnouncedLen())
	m.Add(m, mq, p.BitLen()+q.AnnouncedLen())
	return m
}

func Crt(mp, mq *saferith.Nat, p *saferith.Modulus, q *saferith.Nat) *saferith.Nat {
	qInv := new(saferith.Nat).ModInverse(q, p)
	return CrtWithPrecomputation(mp, mq, p, q, qInv)
}
