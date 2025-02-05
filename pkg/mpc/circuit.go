package mpc

import (
	"io"
	"sync"

	"github.com/bronlabs/krypton-primitives/pkg/base/types"
)

type Gates struct {
	prng       io.Reader
	lock       *sync.RWMutex
	roundCount *uint64

	myComm   <-chan *BinaryShare
	nextComm chan<- *BinaryShare
	prevComm chan<- *BinaryShare

	mySharingId   types.SharingID
	nextSharingId types.SharingID
	prevSharingId types.SharingID
}

func (g *Gates) Plain(v uint64) *BinaryShare {
	share := new(BinaryShare)
	share.SubShares = make(map[SharingIdSet]uint64)

	smallestSharingIdSet := NewSharingIdSetOf(1)
	prevSharingIdSet := NewSharingIdSetOf(g.prevSharingId)
	nextSharingIdSet := NewSharingIdSetOf(g.nextSharingId)

	switch {
	case prevSharingIdSet == smallestSharingIdSet:
		share.SubShares[prevSharingIdSet] = v
		share.SubShares[nextSharingIdSet] = 0
	case nextSharingIdSet == smallestSharingIdSet:
		share.SubShares[prevSharingIdSet] = 0
		share.SubShares[nextSharingIdSet] = v
	default:
		share.SubShares[prevSharingIdSet] = 0
		share.SubShares[nextSharingIdSet] = 0
	}

	return share
}

func (g *Gates) And(lhs, rhs *BinaryShare) *BinaryShare {
	v := (lhs.SubShares[NewSharingIdSetOf(g.nextSharingId)] & rhs.SubShares[NewSharingIdSetOf(g.nextSharingId)]) ^
		(lhs.SubShares[NewSharingIdSetOf(g.nextSharingId)] & rhs.SubShares[NewSharingIdSetOf(g.prevSharingId)]) ^
		(lhs.SubShares[NewSharingIdSetOf(g.prevSharingId)] & rhs.SubShares[NewSharingIdSetOf(g.nextSharingId)])

	dealer := NewDealer()
	vShares := dealer.Share(v, g.prng)

	g.lock.Lock()
	g.nextComm <- vShares[g.nextSharingId].Clone()
	g.prevComm <- vShares[g.prevSharingId].Clone()
	*g.roundCount++
	g.lock.Unlock()

	share := vShares[g.mySharingId].Xor(<-g.myComm).Xor(<-g.myComm)
	return share
}

func (g *Gates) Or(lhs, rhs *BinaryShare) *BinaryShare {
	return lhs.Xor(rhs).Xor(g.And(lhs, rhs))
}

func (g *Gates) BinaryAdd(lhs, rhs *BinaryShare) *BinaryShare {
	carry := g.Plain(0)

	ci := g.Plain(0)
	xi := lhs.AndPlain(0b1)
	yi := rhs.AndPlain(0b1)

	for i := 1; i < 64; i++ {
		ci = ci.Xor(g.And(xi.Xor(ci), yi.Xor(ci)))
		xi = lhs.Shr(i).AndPlain(0b1)
		yi = rhs.Shr(i).AndPlain(0b1)
		carry = carry.Xor(ci.AndPlain(1).Shl(i))
	}

	return carry.Xor(lhs.Xor(rhs))
}

type Circuit struct {
	prng       io.Reader
	lock       sync.RWMutex
	roundCount uint64

	aliceComm   chan *BinaryShare
	bobComm     chan *BinaryShare
	charlieComm chan *BinaryShare
}

func NewCircuit(prng io.Reader) *Circuit {
	return &Circuit{
		prng:        prng,
		aliceComm:   make(chan *BinaryShare, 2),
		bobComm:     make(chan *BinaryShare, 2),
		charlieComm: make(chan *BinaryShare, 2),
	}
}

func (c *Circuit) AliceGates() *Gates {
	return &Gates{
		lock:          &c.lock,
		roundCount:    &c.roundCount,
		prng:          c.prng,
		myComm:        c.aliceComm,
		nextComm:      c.bobComm,
		prevComm:      c.charlieComm,
		mySharingId:   1,
		nextSharingId: 2,
		prevSharingId: 3,
	}
}

func (c *Circuit) BobGates() *Gates {
	return &Gates{
		prng:          c.prng,
		lock:          &c.lock,
		roundCount:    &c.roundCount,
		myComm:        c.bobComm,
		nextComm:      c.charlieComm,
		prevComm:      c.aliceComm,
		mySharingId:   2,
		nextSharingId: 3,
		prevSharingId: 1,
	}
}

func (c *Circuit) CharlieGates() *Gates {
	return &Gates{
		prng:          c.prng,
		lock:          &c.lock,
		roundCount:    &c.roundCount,
		myComm:        c.charlieComm,
		nextComm:      c.aliceComm,
		prevComm:      c.bobComm,
		mySharingId:   3,
		nextSharingId: 1,
		prevSharingId: 2,
	}
}

func (c *Circuit) RoundCount() uint64 {
	return c.roundCount
}
