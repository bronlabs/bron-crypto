package dkls23

import (
	"bytes"

	"github.com/bronlabs/bron-crypto/pkg/base"
	"github.com/bronlabs/bron-crypto/pkg/base/algebra"
	"github.com/bronlabs/bron-crypto/pkg/base/curves"
	ds "github.com/bronlabs/bron-crypto/pkg/base/datastructures"
	"github.com/bronlabs/bron-crypto/pkg/base/datastructures/hashmap"
	"github.com/bronlabs/bron-crypto/pkg/base/serde"
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

type shardDTO[P curves.Point[P, B, S], B algebra.PrimeFieldElement[B], S algebra.PrimeFieldElement[S]] struct {
	Share           *feldman.Share[S]         `cbor:"share"`
	Ac              *feldman.AccessStructure  `cbor:"accessStructure"`
	PK              *ecdsa.PublicKey[P, B, S] `cbor:"publicKey"`
	ZeroSeeds       map[sharing.ID][przs.SeedLength]byte
	OTSenderSeeds   map[sharing.ID]*vsot.SenderOutput   `cbor:"otSenderSeeds"`
	OTReceiverSeeds map[sharing.ID]*vsot.ReceiverOutput `cbor:"otReceiverSeeds"`
}

func NewShard[P curves.Point[P, B, S], B algebra.PrimeFieldElement[B], S algebra.PrimeFieldElement[S]](share *feldman.Share[S], ac *feldman.AccessStructure, pk *ecdsa.PublicKey[P, B, S], zeroSeeds przs.Seeds, otSenderSeeds ds.Map[sharing.ID, *vsot.SenderOutput], otReceiverSeeds ds.Map[sharing.ID, *vsot.ReceiverOutput]) *Shard[P, B, S] {
	// TODO: do some validation (e.g. pk is not identity etc.)

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

func (s *Shard[P, B, S]) MarshalCBOR() ([]byte, error) {
	zeroSeeds := make(map[sharing.ID][przs.SeedLength]byte)
	for id, seed := range s.zeroSeeds.Iter() {
		zeroSeeds[id] = seed
	}
	otSenderSeeds := make(map[sharing.ID]*vsot.SenderOutput)
	for id, seed := range s.otSenderSeeds.Iter() {
		otSenderSeeds[id] = seed
	}
	otReceiverSeeds := make(map[sharing.ID]*vsot.ReceiverOutput)
	for id, seed := range s.otReceiverSeeds.Iter() {
		otReceiverSeeds[id] = seed
	}

	dto := &shardDTO[P, B, S]{
		Share:           s.share,
		Ac:              s.ac,
		PK:              s.pk,
		ZeroSeeds:       zeroSeeds,
		OTSenderSeeds:   otSenderSeeds,
		OTReceiverSeeds: otReceiverSeeds,
	}
	return serde.MarshalCBOR(dto)
}

func (s *Shard[P, B, S]) UnmarshalCBOR(data []byte) error {
	dto, err := serde.UnmarshalCBOR[*shardDTO[P, B, S]](data)
	if err != nil {
		return err
	}

	zeroSeeds := hashmap.NewImmutableComparableFromNativeLike(dto.ZeroSeeds)
	otSenderSeeds := hashmap.NewImmutableComparableFromNativeLike(dto.OTSenderSeeds)
	otReceiverSeeds := hashmap.NewImmutableComparableFromNativeLike(dto.OTReceiverSeeds)
	s2 := NewShard(dto.Share, dto.Ac, dto.PK, zeroSeeds, otSenderSeeds, otReceiverSeeds)
	*s = *s2
	return nil
}
