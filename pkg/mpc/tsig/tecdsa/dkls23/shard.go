package dkls23

import (
	"bytes"
	"slices"

	"github.com/bronlabs/errs-go/errs"

	"github.com/bronlabs/bron-crypto/pkg/base/algebra"
	"github.com/bronlabs/bron-crypto/pkg/base/curves"
	ds "github.com/bronlabs/bron-crypto/pkg/base/datastructures"
	"github.com/bronlabs/bron-crypto/pkg/base/datastructures/hashmap"
	"github.com/bronlabs/bron-crypto/pkg/base/serde"
	"github.com/bronlabs/bron-crypto/pkg/mpc/sharing"
	"github.com/bronlabs/bron-crypto/pkg/mpc/tsig/tecdsa"
	"github.com/bronlabs/bron-crypto/pkg/ot/base/vsot"
)

// AuxiliaryInfo holds auxiliary key material.
type AuxiliaryInfo struct {
	otSenderSeeds   ds.Map[sharing.ID, *vsot.SenderOutput]
	otReceiverSeeds ds.Map[sharing.ID, *vsot.ReceiverOutput]
}

type auxiliaryInfoDTO struct {
	OTSenderSeeds   map[sharing.ID]*vsot.SenderOutput   `cbor:"otSenderSeeds"`
	OTReceiverSeeds map[sharing.ID]*vsot.ReceiverOutput `cbor:"otReceiverSeeds"`
}

// OTSenderSeeds returns the OT sender seeds.
func (a *AuxiliaryInfo) OTSenderSeeds() ds.Map[sharing.ID, *vsot.SenderOutput] {
	return a.otSenderSeeds
}

// OTReceiverSeeds returns the OT receiver seeds.
func (a *AuxiliaryInfo) OTReceiverSeeds() ds.Map[sharing.ID, *vsot.ReceiverOutput] {
	return a.otReceiverSeeds
}

// Equal reports whether the value equals other.
func (a *AuxiliaryInfo) Equal(rhs *AuxiliaryInfo) bool {
	if a.otSenderSeeds.Size() != rhs.otSenderSeeds.Size() {
		return false
	}
	for id, l := range a.otSenderSeeds.Iter() {
		r, ok := rhs.otSenderSeeds.Get(id)
		if !ok {
			return false
		}
		if l.InferredXi() != r.InferredXi() {
			return false
		}
		if l.InferredL() != r.InferredL() {
			return false
		}
		for xi := range l.InferredXi() {
			for ell := range l.InferredL() {
				if !bytes.Equal(l.Messages[xi][0][ell], r.Messages[xi][0][ell]) {
					return false
				}
				if !bytes.Equal(l.Messages[xi][1][ell], r.Messages[xi][1][ell]) {
					return false
				}
			}
		}
	}
	return true
}

// MarshalCBOR implements cbor.Marshaler.
func (a *AuxiliaryInfo) MarshalCBOR() ([]byte, error) {
	otSenderSeeds := make(map[sharing.ID]*vsot.SenderOutput)
	for id, seed := range a.otSenderSeeds.Iter() {
		otSenderSeeds[id] = seed
	}
	otReceiverSeeds := make(map[sharing.ID]*vsot.ReceiverOutput)
	for id, seed := range a.otReceiverSeeds.Iter() {
		otReceiverSeeds[id] = seed
	}
	dto := &auxiliaryInfoDTO{
		OTSenderSeeds:   otSenderSeeds,
		OTReceiverSeeds: otReceiverSeeds,
	}
	data, err := serde.MarshalCBOR(dto)
	if err != nil {
		return nil, errs.Wrap(err).WithMessage("failed to marshal dkls23 auxiliary info")
	}
	return data, nil
}

// UnmarshalCBOR implements cbor.Unmarshaler.
func (a *AuxiliaryInfo) UnmarshalCBOR(data []byte) error {
	dto, err := serde.UnmarshalCBOR[*auxiliaryInfoDTO](data)
	if err != nil {
		return errs.Wrap(err).WithMessage("failed to unmarshal dkls23 auxiliary info")
	}
	otSenderSeeds := hashmap.NewImmutableComparableFromNativeLike(dto.OTSenderSeeds)
	otReceiverSeeds := hashmap.NewImmutableComparableFromNativeLike(dto.OTReceiverSeeds)
	auxInfo, err := NewAuxiliaryInfo(otSenderSeeds, otReceiverSeeds)
	if err != nil {
		return errs.Wrap(err).WithMessage("failed to create AuxiliaryInfo from unmarshalled data")
	}
	*a = *auxInfo
	return nil
}

// NewAuxiliaryInfo returns a new auxiliary info instance.
func NewAuxiliaryInfo(otSenderSeeds ds.Map[sharing.ID, *vsot.SenderOutput], otReceiverSeeds ds.Map[sharing.ID, *vsot.ReceiverOutput]) (*AuxiliaryInfo, error) {
	if otSenderSeeds == nil || otReceiverSeeds == nil {
		return nil, ErrNil.WithMessage("cannot create AuxiliaryInfo with nil fields")
	}
	if otSenderSeeds.Size() == 0 {
		return nil, ErrFailed.WithMessage("OT sender seeds map cannot be empty")
	}
	if !slices.Equal(otSenderSeeds.Keys(), otReceiverSeeds.Keys()) {
		return nil, ErrFailed.WithMessage("OT sender seeds and receiver seeds maps must have the same keys")
	}
	return &AuxiliaryInfo{
		otSenderSeeds:   otSenderSeeds,
		otReceiverSeeds: otReceiverSeeds,
	}, nil
}

// Shard holds a tECDSA key share.
type Shard[P curves.Point[P, B, S], B algebra.PrimeFieldElement[B], S algebra.PrimeFieldElement[S]] struct {
	*tecdsa.Shard[P, B, S]
	AuxiliaryInfo
}

// NewShard returns a new shard.
func NewShard[P curves.Point[P, B, S], B algebra.PrimeFieldElement[B], S algebra.PrimeFieldElement[S]](baseShard *tecdsa.Shard[P, B, S], auxInfo *AuxiliaryInfo) (*Shard[P, B, S], error) {
	if baseShard == nil || auxInfo == nil {
		return nil, ErrNil.WithMessage("cannot create Shard with nil fields")
	}
	return &Shard[P, B, S]{
		Shard:         baseShard,
		AuxiliaryInfo: *auxInfo,
	}, nil
}

// Equal reports whether the value equals other.
func (s *Shard[P, B, S]) Equal(rhs *Shard[P, B, S]) bool {
	if s == nil || rhs == nil {
		return s == rhs
	}
	return s.Shard.Equal(rhs.Shard) && s.AuxiliaryInfo.Equal(&rhs.AuxiliaryInfo)
}

type shardDTO[P curves.Point[P, B, S], B algebra.PrimeFieldElement[B], S algebra.PrimeFieldElement[S]] struct {
	Shard *tecdsa.Shard[P, B, S] `cbor:"shard"`
	Aux   AuxiliaryInfo          `cbor:"auxiliaryInfo"`
}

// MarshalCBOR implements cbor.Marshaler.
func (s *Shard[P, B, S]) MarshalCBOR() ([]byte, error) {
	dto := &shardDTO[P, B, S]{
		Shard: s.Shard,
		Aux:   s.AuxiliaryInfo,
	}
	data, err := serde.MarshalCBOR(dto)
	if err != nil {
		return nil, errs.Wrap(err).WithMessage("failed to marshal dkls23 Shard")
	}
	return data, nil
}

// UnmarshalCBOR implements cbor.Unmarshaler.
func (s *Shard[P, B, S]) UnmarshalCBOR(data []byte) error {
	dto, err := serde.UnmarshalCBOR[*shardDTO[P, B, S]](data)
	if err != nil {
		return errs.Wrap(err).WithMessage("failed to unmarshal dkls23 Shard")
	}
	shard, err := NewShard(dto.Shard, &dto.Aux)
	if err != nil {
		return errs.Wrap(err).WithMessage("failed to create Shard from unmarshalled data")
	}
	*s = *shard
	return nil
}
