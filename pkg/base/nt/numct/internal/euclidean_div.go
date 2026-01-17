package internal

import (
	"github.com/cronokirby/saferith"
)

func EuclideanDiv(q, r, a, d *saferith.Nat) (*saferith.Nat, *saferith.Nat) {
	var qq, rr, rt, t saferith.Nat

	for i := a.AnnouncedLen() - 1; i >= 0; i-- {
		b := (a.Byte(i/8) >> (i % 8)) & 0b1
		rt.Lsh(&rr, 1, d.AnnouncedLen()+1)
		t.SetUint64(uint64(b)).Resize(1)
		rt.Add(&rt, &t, d.AnnouncedLen()+1)
		t.Sub(&rt, d, d.AnnouncedLen()+1)
		_, _, rtLessThanD := rt.Cmp(d)
		rr.CondAssign(rtLessThanD^0b1, &t)
		rr.CondAssign(rtLessThanD, &rt)
		rr.Resize(d.AnnouncedLen())
		t.SetUint64(uint64(rtLessThanD ^ 0b1)).Resize(1)
		t.Lsh(&t, uint(i), a.AnnouncedLen())
		qq.Add(&qq, &t, a.AnnouncedLen())
	}

	q.SetNat(&qq)
	r.SetNat(&rr)
	return q, r
}
