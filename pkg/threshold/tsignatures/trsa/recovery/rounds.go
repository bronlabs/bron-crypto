package recovery

import (
	"github.com/bronlabs/bron-crypto/pkg/base/errs"
	"github.com/bronlabs/bron-crypto/pkg/base/types"
	"github.com/bronlabs/bron-crypto/pkg/network"
	"github.com/bronlabs/bron-crypto/pkg/threshold/sharing/rep23"
	"github.com/bronlabs/bron-crypto/pkg/threshold/tsignatures/trsa"
)

func (p *Recoverer) Round1() (network.RoundMessages[types.ThresholdProtocol, *Round1P2P], error) {
	nextSharingId, nextIdentity, err := p.nextId()
	if err != nil {
		return nil, errs.WrapFailed(err, "failed to generate next sharing id")
	}
	prevSharingId, prevIdentity, err := p.prevId()
	if err != nil {
		return nil, errs.WrapFailed(err, "failed to generate previous sharing id")
	}

	u := network.NewRoundMessages[types.ThresholdProtocol, *Round1P2P]()
	if p.MislayerSharingId == prevSharingId {
		u.Put(prevIdentity, &Round1P2P{
			N1: p.MyShard.N1,
			N2: p.MyShard.N2,
			E:  p.MyShard.E,
			D1: p.MyShard.D1Share.Next,
			D2: p.MyShard.D2Share.Next,
		})
	} else if p.MislayerSharingId == nextSharingId {
		u.Put(nextIdentity, &Round1P2P{
			N1: p.MyShard.N1,
			N2: p.MyShard.N2,
			E:  p.MyShard.E,
			D1: p.MyShard.D1Share.Prev,
			D2: p.MyShard.D2Share.Prev,
		})
	}

	return u, nil
}

func (p *Mislayer) Round2(uIn network.RoundMessages[types.ThresholdProtocol, *Round1P2P]) (*trsa.Shard, error) {
	nextSharingId, _, err := p.nextId()
	if err != nil {
		return nil, errs.WrapFailed(err, "failed to generate next sharing id")
	}
	prevSharingId, _, err := p.prevId()
	if err != nil {
		return nil, errs.WrapFailed(err, "failed to generate previous sharing id")
	}

	s := &trsa.Shard{
		PublicShard: trsa.PublicShard{
			E: trsa.RsaE,
		},
		D1Share: &rep23.IntShare{Id: p.MySharingId},
		D2Share: &rep23.IntShare{Id: p.MySharingId},
	}

	for sharingId, id := range p.SharingCfg.Iter() {
		if sharingId == p.MySharingId {
			continue
		}
		u, ok := uIn.Get(id)
		if !ok {
			return nil, errs.NewFailed("invalid identity")
		}
		if s.N1 == nil {
			s.N1 = u.N1
		} else if s.N1.Nat().Eq(u.N1.Nat()) == 0 {
			return nil, errs.NewFailed("invalid message")
		}
		if s.N2 == nil {
			s.N2 = u.N2
		} else if s.N2.Nat().Eq(u.N2.Nat()) == 0 {
			return nil, errs.NewFailed("invalid message")
		}

		if sharingId == nextSharingId {
			s.D1Share.Prev = u.D1
			s.D2Share.Prev = u.D2
		} else if sharingId == prevSharingId {
			s.D1Share.Next = u.D1
			s.D2Share.Next = u.D2
		}
	}

	return s, nil
}

func (p *Participant) nextId() (types.SharingID, types.IdentityKey, error) {
	nextSharingId := p.MySharingId%3 + 1
	nextIdentity, ok := p.SharingCfg.Get(nextSharingId)
	if !ok {
		return 0, nil, errs.NewFailed("no sharing id found")
	}

	return nextSharingId, nextIdentity, nil
}

func (p *Participant) prevId() (types.SharingID, types.IdentityKey, error) {
	prevSharingId := ((p.MySharingId + 1) % 3) + 1
	prevIdentity, ok := p.SharingCfg.Get(prevSharingId)
	if !ok {
		return 0, nil, errs.NewFailed("no sharing id found")
	}

	return prevSharingId, prevIdentity, nil
}
