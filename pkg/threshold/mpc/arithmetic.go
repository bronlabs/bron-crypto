package mpc

import (
	"io"
	"math/rand/v2"
	"slices"
	"strconv"

	"github.com/bronlabs/bron-crypto/pkg/base/datastructures/hashmap"
	"github.com/bronlabs/bron-crypto/pkg/base/errs"
	"github.com/bronlabs/bron-crypto/pkg/base/errs2"
	"github.com/bronlabs/bron-crypto/pkg/base/utils/mathutils"
	"github.com/bronlabs/bron-crypto/pkg/base/utils/sliceutils"
	"github.com/bronlabs/bron-crypto/pkg/network"
	"github.com/bronlabs/bron-crypto/pkg/network/exchange"
	"github.com/bronlabs/bron-crypto/pkg/threshold/sharing"
	"github.com/bronlabs/bron-crypto/pkg/threshold/sharing/binrep3"
	"golang.org/x/crypto/blake2b"
)

type Arithmetic struct {
	rt                  *network.Router
	correlationIdPrefix string
	round               int

	prevId sharing.ID
	id     sharing.ID
	nextId sharing.ID

	prevPrng io.Reader
	nextPrng io.Reader
}

func NewArithmetic(rt *network.Router, sid network.SID, correlationIdPrefix string, id sharing.ID, quorum network.Quorum, prng io.Reader) (*Arithmetic, error) {
	if rt == nil || quorum == nil || !quorum.Contains(id) || quorum.Size() != 3 {
		return nil, errs.NewFailed("invalid arguments")
	}

	round := 0
	ids := quorum.List()
	slices.Sort(ids)
	idx := slices.Index(ids, id)
	prevId := ids[(idx+2)%3]
	nextId := ids[(idx+1)%3]

	var prevSeed [32]byte
	_ = errs2.Must1(io.ReadFull(prng, prevSeed[:]))
	nextSeed, err := network.ExchangeUnicastRing(rt, correlationIdPrefix+"-"+strconv.Itoa(round), prevId, nextId, prevSeed)
	if err != nil {
		return nil, errs.WrapRandomSample(err, "cannot exchange seeds")
	}
	round++

	prevPrng := rand.NewChaCha8(blake2b.Sum256(slices.Concat(sid[:], prevSeed[:])))
	nextPrng := rand.NewChaCha8(blake2b.Sum256(slices.Concat(sid[:], nextSeed[:])))

	a := &Arithmetic{
		rt:                  rt,
		correlationIdPrefix: correlationIdPrefix,
		round:               round,
		prevId:              prevId,
		id:                  id,
		nextId:              nextId,
		prevPrng:            prevPrng,
		nextPrng:            nextPrng,
	}

	return a, nil
}

func (a *Arithmetic) Rounds() int {
	return a.round
}

func (a *Arithmetic) RandomSecret() *Value64 {
	p := errs2.Must1(mathutils.RandomUint64(a.prevPrng))
	n := errs2.Must1(mathutils.RandomUint64(a.nextPrng))
	return NewValue64Secret(binrep3.NewShare(a.id, p, n))
}

func (a *Arithmetic) Xor(l, r *Value64) *Value64 {
	if l.IsPublic() && r.IsPublic() {
		return NewValue64Public(l.Public() ^ r.Public())
	} else if l.IsSecret() && r.IsPublic() {
		return NewValue64Secret(l.Secret().XorPublic(r.Public()))
	} else if l.IsPublic() && r.IsSecret() {
		return NewValue64Secret(r.Secret().XorPublic(l.Public()))
	} else {
		return NewValue64Secret(l.Secret().Xor(r.Secret()))
	}
}

func (a *Arithmetic) And(l, r *Value64) *Value64 {
	if l.IsPublic() && r.IsPublic() {
		return NewValue64Public(l.Public() & r.Public())
	} else if l.IsSecret() && r.IsPublic() {
		return NewValue64Secret(l.Secret().AndPublic(r.Public()))
	} else if l.IsPublic() && r.IsSecret() {
		return NewValue64Secret(r.Secret().AndPublic(l.Public()))
	} else {
		return a.doAnd(l.Secret(), r.Secret())
	}
}

func (a *Arithmetic) AndBatch(l, r []*Value64) []*Value64 {
	if len(l) != len(r) {
		panic("invalid arguments")
	}

	results := make([]*Value64, len(l))
	var batchIndices []int
	var batchL []*binrep3.Share
	var batchR []*binrep3.Share
	for i, li := range l {
		ri := r[i]
		if li.IsPublic() && ri.IsPublic() {
			results[i] = NewValue64Public(li.Public() & ri.Public())
		} else if li.IsSecret() && ri.IsPublic() {
			results[i] = NewValue64Secret(li.Secret().AndPublic(ri.Public()))
		} else if li.IsPublic() && ri.IsSecret() {
			results[i] = NewValue64Secret(ri.Secret().AndPublic(li.Public()))
		} else {
			batchIndices = append(batchIndices, i)
			batchL = append(batchL, li.Secret())
			batchR = append(batchR, ri.Secret())
		}
	}
	batchResult := a.doAndBatch(batchL, batchR)
	for i, lr := range batchResult {
		results[batchIndices[i]] = lr
	}

	return results
}

func (a *Arithmetic) Not(v *Value64) *Value64 {
	if v.IsPublic() {
		return NewValue64Public(^v.Public())
	} else {
		return NewValue64Secret(v.Secret().XorPublic(0xffffffffffffffff))
	}
}

func (a *Arithmetic) Or(x, y *Value64) *Value64 {
	return a.Xor(a.Xor(x, y), a.And(x, y))
}

func (a *Arithmetic) Add(l, r *Value64) *Value64 {
	if l.IsPublic() && r.IsPublic() {
		return NewValue64Public(l.Public() + r.Public())
	} else {
		return a.doAdd(l, r)
	}
}

func (a *Arithmetic) AddCarry(x, y, c *Value64) (*Value64, *Value64) {
	z := a.Sum(x, y, c)
	cOut := a.Xor(y, a.And(a.Xor(x, y), a.Xor(x, z)))
	return z, cOut.Shr(63)
}

func (a *Arithmetic) AddBatch(l, r []*Value64) []*Value64 {
	if len(l) != len(r) {
		panic("invalid arguments")
	}

	results := make([]*Value64, len(l))
	var batchIndices []int
	var batchL []*Value64
	var batchR []*Value64
	for i, li := range l {
		ri := r[i]
		if li.IsPublic() && ri.IsPublic() {
			results[i] = NewValue64Public(li.Public() + ri.Public())
		} else {
			batchIndices = append(batchIndices, i)
			batchL = append(batchL, li)
			batchR = append(batchR, ri)
		}
	}
	batchResult := a.doAddBatch(batchL, batchR)
	for i, lr := range batchResult {
		results[batchIndices[i]] = lr
	}

	return results
}

func (a *Arithmetic) Sum(x0, x1, x2 *Value64, xi ...*Value64) *Value64 {
	inputs := []*Value64{x0, x1, x2}
	inputs = append(inputs, xi...)

	var publicInputs []uint64
	var allInputs []*Value64
	for _, input := range inputs {
		if input.IsPublic() {
			publicInputs = append(publicInputs, input.Public())
		} else {
			allInputs = append(allInputs, input)
		}
	}
	if len(publicInputs) > 0 {
		allInputs = append(allInputs, NewValue64Public(sliceutils.Reduce(publicInputs, 0, func(acc, v uint64) uint64 { return acc + v })))
	}

	for len(allInputs) > 2 {
		allInputs = a.reduce(allInputs)
	}
	if len(allInputs) == 1 {
		return allInputs[0]
	}

	return a.Add(allInputs[0], allInputs[1])
}

func (a *Arithmetic) SubBorrow(x, y, b *Value64) (*Value64, *Value64) {
	z := a.Sum(x, a.Not(y), a.Xor(b, NewValue64Public(0b1)))
	bOut := a.Xor(z, a.And(a.Xor(x, y), a.Xor(y, z)))
	return z, bOut.Shr(63)
}

func (a *Arithmetic) RevealTo(id sharing.ID, values ...*Value64) ([]uint64, error) {
	if a.id != id {
		var msg []uint64
		unicastOut := hashmap.NewComparable[sharing.ID, []uint64]()
		if id == a.prevId {
			for _, v := range values {
				msg = append(msg, v.Secret().Prev())
			}
			unicastOut.Put(id, msg)
		} else if id == a.nextId {
			for _, v := range values {
				msg = append(msg, v.Secret().Next())
			}
			unicastOut.Put(id, msg)
		} else {
			return nil, errs.NewFailed("invalid id")
		}
		err := exchange.SendUnicast(a.rt, a.correlationIdPrefix+"-"+strconv.Itoa(a.round), unicastOut.Freeze())
		if err != nil {
			return nil, errs.WrapFailed(err, "failed to send unicast")
		}
		a.round++

		return nil, nil
	} else {
		from := []sharing.ID{a.prevId, a.nextId}
		unicastIn, err := exchange.ReceiveUnicast[[]uint64](a.rt, a.correlationIdPrefix+"-"+strconv.Itoa(a.round), from...)
		if err != nil {
			return nil, errs.WrapFailed(err, "failed to receive unicast")
		}
		a.round++

		p, ok := unicastIn.Get(a.prevId)
		if !ok {
			return nil, errs.NewFailed("missing prev secret")
		}
		n, ok := unicastIn.Get(a.nextId)
		if !ok {
			return nil, errs.NewFailed("missing next secret")
		}
		for k := range len(values) {
			if p[k] != n[k] {
				return nil, errs.NewFailed("inconsistent sharing")
			}
		}

		secrets := make([]uint64, len(values))
		for k := range secrets {
			secrets[k] = values[k].Secret().Next() ^ values[k].Secret().Prev() ^ p[k]
		}
		return secrets, nil
	}
}

func (a *Arithmetic) reduce(x []*Value64) []*Value64 {
	var results []*Value64

	var i int
	var andX []*Value64
	var andY []*Value64
	for i = 0; (i + 2) < len(x); i += 3 {
		results = append(results, a.Xor(a.Xor(x[i], x[i+1]), x[i+2]))
		andX = append(andX, x[i], x[i], x[i+1])
		andY = append(andY, x[i+1], x[i+2], x[i+2])
	}
	andZ := a.AndBatch(andX, andY)
	for i = 0; (i + 2) < len(x); i += 3 {
		results = append(results, a.Xor(a.Xor(andZ[i], andZ[i+1]), andZ[i+2]).Shl(1))
	}
	for ; i < len(x); i++ {
		results = append(results, x[i])
	}
	return results
}

func (a *Arithmetic) doAnd(l, r *binrep3.Share) *Value64 {
	rp := errs2.Must1(mathutils.RandomUint64(a.prevPrng))
	rn := errs2.Must1(mathutils.RandomUint64(a.nextPrng))

	p := (l.Prev() & r.Next()) ^ (l.Next() & r.Prev()) ^ (l.Prev() & r.Prev()) ^ rp ^ rn
	n, err := network.ExchangeUnicastRing(a.rt, a.correlationIdPrefix+"-"+strconv.Itoa(a.round), a.prevId, a.nextId, p)
	if err != nil {
		// TODO: handle error
		panic(err)
	}
	a.round++

	return NewValue64Secret(binrep3.NewShare(a.id, p, n))
}

func (a *Arithmetic) doAndBatch(batchL, batchR []*binrep3.Share) []*Value64 {
	results := make([]*Value64, len(batchL))

	batchP := make([]uint64, len(batchL))
	for i, li := range batchL {
		ri := batchR[i]
		rp := errs2.Must1(mathutils.RandomUint64(a.prevPrng))
		rn := errs2.Must1(mathutils.RandomUint64(a.nextPrng))
		batchP[i] = (li.Prev() & ri.Next()) ^ (li.Next() & ri.Prev()) ^ (li.Prev() & ri.Prev()) ^ rp ^ rn
	}

	batchN, err := network.ExchangeUnicastRing(a.rt, a.correlationIdPrefix+"-"+strconv.Itoa(a.round), a.prevId, a.nextId, batchP)
	if err != nil {
		// TODO: handle error
		panic(err)
	}
	a.round++

	for i, pi := range batchP {
		ni := batchN[i]
		results[i] = NewValue64Secret(binrep3.NewShare(a.id, pi, ni))
	}
	return results
}

func (a *Arithmetic) doAddBatch(batchL, batchR []*Value64) []*Value64 {
	p0 := make([]*Value64, len(batchL))
	for i, li := range batchL {
		ri := batchR[i]
		p0[i] = a.Xor(li, ri)
	}
	g0 := a.AndBatch(batchL, batchR)

	var t1x []*Value64
	var t1y []*Value64
	for i, p0i := range p0 {
		t1x = append(t1x, p0i, p0i)
		t1y = append(t1y, g0[i].Shl(1), p0i.Shl(1))
	}
	t1 := a.AndBatch(t1x, t1y)
	g1 := make([]*Value64, len(batchL))
	p1 := make([]*Value64, len(batchL))
	for i, g0i := range g0 {
		g1[i] = a.Xor(g0i, t1[2*i])
		p1[i] = t1[2*i+1]
	}

	var t2x []*Value64
	var t2y []*Value64
	for i, p1i := range p1 {
		t2x = append(t2x, p1i, p1i)
		t2y = append(t2y, g1[i].Shl(2), p1i.Shl(2))
	}
	t2 := a.AndBatch(t2x, t2y)
	g2 := make([]*Value64, len(batchL))
	p2 := make([]*Value64, len(batchL))
	for i, g1i := range g1 {
		g2[i] = a.Xor(g1i, t2[2*i])
		p2[i] = t2[2*i+1]
	}

	var t3x []*Value64
	var t3y []*Value64
	for i, p2i := range p2 {
		t3x = append(t3x, p2i, p2i)
		t3y = append(t3y, g2[i].Shl(4), p2i.Shl(4))
	}
	t3 := a.AndBatch(t3x, t3y)
	g3 := make([]*Value64, len(batchL))
	p3 := make([]*Value64, len(batchL))
	for i, g2i := range g2 {
		g3[i] = a.Xor(g2i, t3[2*i])
		p3[i] = t3[2*i+1]
	}

	var t4x []*Value64
	var t4y []*Value64
	for i, p3i := range p3 {
		t4x = append(t4x, p3i, p3i)
		t4y = append(t4y, g3[i].Shl(8), p3i.Shl(8))
	}
	t4 := a.AndBatch(t4x, t4y)
	g4 := make([]*Value64, len(batchL))
	p4 := make([]*Value64, len(batchL))
	for i, g3i := range g3 {
		g4[i] = a.Xor(g3i, t4[2*i])
		p4[i] = t4[2*i+1]
	}

	var t5x []*Value64
	var t5y []*Value64
	for i, p4i := range p4 {
		t5x = append(t5x, p4i, p4i)
		t5y = append(t5y, g4[i].Shl(16), p4i.Shl(16))
	}
	t5 := a.AndBatch(t5x, t5y)
	g5 := make([]*Value64, len(batchL))
	p5 := make([]*Value64, len(batchL))
	for i, g4i := range g4 {
		g5[i] = a.Xor(g4i, t5[2*i])
		p5[i] = t5[2*i+1]
	}

	var t6x []*Value64
	var t6y []*Value64
	for i, p5i := range p5 {
		t6x = append(t6x, p5i)
		t6y = append(t6y, g5[i].Shl(32))
	}
	t6 := a.AndBatch(t6x, t6y)
	g6 := make([]*Value64, len(batchL))
	sums := make([]*Value64, len(batchL))
	for i, g5i := range g5 {
		g6[i] = a.Xor(g5i, t6[i])
		sums[i] = a.Xor(p0[i], g6[i].Shl(1))
	}

	return sums
}

func (a *Arithmetic) doAdd(l, r *Value64) *Value64 {
	p0 := a.Xor(l, r) // propagate
	g0 := a.And(l, r) // generate

	t1 := a.AndBatch([]*Value64{p0, p0}, []*Value64{g0.Shl(1), p0.Shl(1)})
	g1 := a.Xor(g0, t1[0])
	p1 := t1[1]

	t2 := a.AndBatch([]*Value64{p1, p1}, []*Value64{g1.Shl(2), p1.Shl(2)})
	g2 := a.Xor(g1, t2[0])
	p2 := t2[1]

	t3 := a.AndBatch([]*Value64{p2, p2}, []*Value64{g2.Shl(4), p2.Shl(4)})
	g3 := a.Xor(g2, t3[0])
	p3 := t3[1]

	t4 := a.AndBatch([]*Value64{p3, p3}, []*Value64{g3.Shl(8), p3.Shl(8)})
	g4 := a.Xor(g3, t4[0])
	p4 := t4[1]

	t5 := a.AndBatch([]*Value64{p4, p4}, []*Value64{g4.Shl(16), p4.Shl(16)})
	g5 := a.Xor(g4, t5[0])
	p5 := t5[1]

	g6 := a.Xor(g5, a.And(p5, g5.Shl(32)))
	sum := a.Xor(p0, g6.Shl(1))
	return sum
}
