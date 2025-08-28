package tecdsa

import (
	"github.com/bronlabs/bron-crypto/pkg/base/algebra"
	"github.com/bronlabs/bron-crypto/pkg/base/curves"
	ds "github.com/bronlabs/bron-crypto/pkg/base/datastructures"
	"github.com/bronlabs/bron-crypto/pkg/ot/base/vsot"
	"github.com/bronlabs/bron-crypto/pkg/threshold/sharing"
	"github.com/bronlabs/bron-crypto/pkg/threshold/sharing/feldman"
	"github.com/bronlabs/bron-crypto/pkg/threshold/sharing/zero/przs"
)

// TODO: do whatever it needs to be a proper shard
type Shard[P curves.Point[P, B, S], B algebra.FieldElement[B], S algebra.PrimeFieldElement[S]] struct {
	share           *feldman.Share[S]
	pk              P
	zeroSeeds       przs.Seeds
	otSenderSeeds   ds.Map[sharing.ID, *vsot.SenderOutput]
	otReceiverSeeds ds.Map[sharing.ID, *vsot.ReceiverOutput]
}

func NewShard[P curves.Point[P, B, S], B algebra.FieldElement[B], S algebra.PrimeFieldElement[S]](share *feldman.Share[S], pk P, zeroSeeds przs.Seeds, otSenderSeeds ds.Map[sharing.ID, *vsot.SenderOutput], otReceiverSeeds ds.Map[sharing.ID, *vsot.ReceiverOutput]) *Shard[P, B, S] {
	return &Shard[P, B, S]{
		share:           share,
		pk:              pk,
		zeroSeeds:       zeroSeeds,
		otSenderSeeds:   otSenderSeeds,
		otReceiverSeeds: otReceiverSeeds,
	}
}

func (s *Shard[P, B, S]) Share() *feldman.Share[S] {
	return s.share
}

func (s *Shard[P, B, S]) PublicKey() P {
	return s.pk
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
