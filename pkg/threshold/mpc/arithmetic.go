package mpc

import (
	"io"
	"math/rand/v2"
	"slices"
	"strconv"

	"github.com/bronlabs/bron-crypto/pkg/base/errs"
	"github.com/bronlabs/bron-crypto/pkg/base/errs2"
	"github.com/bronlabs/bron-crypto/pkg/base/utils/mathutils"
	"github.com/bronlabs/bron-crypto/pkg/network"
	"github.com/bronlabs/bron-crypto/pkg/threshold/sharing"
	"github.com/bronlabs/bron-crypto/pkg/threshold/sharing/binrep3"
)

type Arithmetic struct {
	rt    *network.Router
	round int

	prevId sharing.ID
	id     sharing.ID
	nextId sharing.ID

	prevPrng io.Reader
	nextPrng io.Reader
}

func NewArithmetic(rt *network.Router, id sharing.ID, quorum network.Quorum, prng io.Reader) (*Arithmetic, error) {
	if rt == nil || quorum == nil || !quorum.Contains(id) || quorum.Size() != 3 {
		return nil, errs.NewFailed("invalid arguments")
	}

	round := 0
	ids := quorum.List()
	slices.Sort(ids)
	idx := slices.Index(ids, id)
	nextId := ids[(idx+1)%3]
	prevId := ids[(idx+2)%3]

	var prevSeed [32]byte
	_ = errs2.Must1(io.ReadFull(prng, prevSeed[:]))
	prevPrng := rand.NewChaCha8(prevSeed)
	nextSeed, err := network.ExchangeUnicastRing(rt, strconv.Itoa(round), prevId, nextId, prevSeed)
	if err != nil {
		return nil, errs.WrapRandomSample(err, "cannot exchange seeds")
	}
	round++
	nextPrng := rand.NewChaCha8(nextSeed)

	a := &Arithmetic{
		rt:       rt,
		round:    round,
		prevId:   prevId,
		id:       id,
		nextId:   nextId,
		prevPrng: prevPrng,
		nextPrng: nextPrng,
	}

	return a, nil
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

func (a *Arithmetic) Not(v *Value64) *Value64 {
	if v.IsPublic() {
		return NewValue64Public(^v.Public())
	} else {
		return NewValue64Secret(v.Secret().XorPublic(0xffffffffffffffff))
	}
}

func (a *Arithmetic) Add(l, r *Value64) *Value64 {
	if l.IsPublic() && r.IsPublic() {
		return NewValue64Public(l.Public() + r.Public())
	} else {
		return a.doAdd(l, r)
	}
}

func (a *Arithmetic) doAnd(l, r *binrep3.Share) *Value64 {
	rp := errs2.Must1(mathutils.RandomUint64(a.prevPrng))
	rn := errs2.Must1(mathutils.RandomUint64(a.nextPrng))

	p := (l.Prev() & r.Next()) ^ (l.Next() & r.Prev()) ^ (l.Prev() & r.Prev()) ^ rp ^ rn
	n, err := network.ExchangeUnicastRing(a.rt, strconv.Itoa(a.round), a.prevId, a.nextId, p)
	if err != nil {
		// TODO: handle error
		panic(err)
	}
	a.round++

	return NewValue64Secret(binrep3.NewShare(a.id, p, n))
}

func (a *Arithmetic) doAdd(l, r *Value64) *Value64 {
	p0 := a.Xor(l, r) // propagate
	g0 := a.And(l, r) // generate
	g1 := a.Xor(g0, a.And(p0, g0.Shl(1)))
	p1 := a.And(p0, p0.Shl(1))
	g2 := a.Xor(g1, a.And(p1, g1.Shl(2)))
	p2 := a.And(p1, p1.Shl(2))
	g3 := a.Xor(g2, a.And(p2, g2.Shl(4)))
	p3 := a.And(p2, p2.Shl(4))
	g4 := a.Xor(g3, a.And(p3, g3.Shl(8)))
	p4 := a.And(p3, p3.Shl(8))
	g5 := a.Xor(g4, a.And(p4, g4.Shl(16)))
	p5 := a.And(p4, p4.Shl(16))

	g6 := a.Xor(g5, a.And(p5, g5.Shl(32)))
	sum := a.Xor(p0, g6.Shl(1))
	return sum
}
