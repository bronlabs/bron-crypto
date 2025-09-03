package tecdsa

import (
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

	// TODO implement me
	panic("implement me")
}

func (s *Shard[P, B, S]) HashCode() base.HashCode {
	//TODO implement me
	panic("implement me")
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
