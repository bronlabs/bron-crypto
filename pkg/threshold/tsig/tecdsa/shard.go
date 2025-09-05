package tecdsa

import (
	"bytes"

	"github.com/bronlabs/bron-crypto/pkg/base"
	"github.com/bronlabs/bron-crypto/pkg/base/algebra"
	"github.com/bronlabs/bron-crypto/pkg/base/curves"
	ds "github.com/bronlabs/bron-crypto/pkg/base/datastructures"
	"github.com/bronlabs/bron-crypto/pkg/ot/base/vsot"
	"github.com/bronlabs/bron-crypto/pkg/signatures/ecdsa"
	"github.com/bronlabs/bron-crypto/pkg/threshold/sharing"
	"github.com/bronlabs/bron-crypto/pkg/threshold/sharing/feldman"
	"github.com/bronlabs/bron-crypto/pkg/threshold/sharing/zero/przs"
)

type Shard[P curves.Point[P, B, S], B algebra.PrimeFieldElement[B], S algebra.PrimeFieldElement[S]] struct {
	share           *feldman.Share[S]
	ac              *feldman.AccessStructure
	pk              *ecdsa.PublicKey[P, B, S]
	zeroSeeds       przs.Seeds
	otSenderSeeds   ds.Map[sharing.ID, *vsot.SenderOutput]
	otReceiverSeeds ds.Map[sharing.ID, *vsot.ReceiverOutput]
}

func NewShard[P curves.Point[P, B, S], B algebra.PrimeFieldElement[B], S algebra.PrimeFieldElement[S]](share *feldman.Share[S], ac *feldman.AccessStructure, pk *ecdsa.PublicKey[P, B, S], zeroSeeds przs.Seeds, otSenderSeeds ds.Map[sharing.ID, *vsot.SenderOutput], otReceiverSeeds ds.Map[sharing.ID, *vsot.ReceiverOutput]) *Shard[P, B, S] {
	return &Shard[P, B, S]{
		share:           share,
		ac:              ac,
		pk:              pk,
		zeroSeeds:       zeroSeeds,
		otSenderSeeds:   otSenderSeeds,
		otReceiverSeeds: otReceiverSeeds,
	}
}

func (s *Shard[P, B, S]) Share() *feldman.Share[S] {
	return s.share
}

func (s *Shard[P, B, S]) PublicKey() *ecdsa.PublicKey[P, B, S] {
	return s.pk
}

func (s *Shard[P, B, S]) AccessStructure() *feldman.AccessStructure {
	return s.ac
}

func (s *Shard[P, B, S]) Equal(rhs *Shard[P, B, S]) bool {
	if s == nil || rhs == nil {
		return s == rhs
	}

	if s.zeroSeeds.Size() != rhs.zeroSeeds.Size() {
		return false
	}
	for id, l := range s.zeroSeeds.Iter() {
		r, ok := rhs.zeroSeeds.Get(id)
		if !ok {
			return false
		}
		if l != r {
			return false
		}
	}
	if s.otSenderSeeds.Size() != rhs.otSenderSeeds.Size() {
		return false
	}
	for id, l := range s.otSenderSeeds.Iter() {
		r, ok := rhs.otSenderSeeds.Get(id)
		if !ok {
			return false
		}
		if l.InferredXi() != r.InferredXi() {
			return false
		}
		if r.InferredL() != r.InferredL() {
			return false
		}
		for xi := range l.InferredXi() {
			for ell := range l.InferredL() {
				if bytes.Equal(l.Messages[xi][0][ell], r.Messages[xi][0][ell]) == false {
					return false
				}
				if bytes.Equal(l.Messages[xi][1][ell], r.Messages[xi][1][ell]) == false {
					return false
				}
			}
		}
	}

	return s.pk.Equal(rhs.pk) && s.ac.Equal(rhs.ac) && s.share.Equal(rhs.share)
}

func (s *Shard[P, B, S]) HashCode() base.HashCode {
	return s.share.HashCode()
}

func (s *Shard[P, B, S]) ZeroSeeds() przs.Seeds {
	return s.zeroSeeds
}

func (s *Shard[P, B, S]) OTSenderSeeds() ds.Map[sharing.ID, *vsot.SenderOutput] {
	return s.otSenderSeeds
}

func (s *Shard[P, B, S]) OTReceiverSeeds() ds.Map[sharing.ID, *vsot.ReceiverOutput] {
	return s.otReceiverSeeds
}
