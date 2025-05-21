package refresh

import (
	"maps"
	"slices"

	"github.com/cronokirby/saferith"

	"github.com/bronlabs/bron-crypto/pkg/base/errs"
	"github.com/bronlabs/bron-crypto/pkg/base/types"
	"github.com/bronlabs/bron-crypto/pkg/network"
	"github.com/bronlabs/bron-crypto/pkg/threshold/sharing/rep23"
	"github.com/bronlabs/bron-crypto/pkg/threshold/tsignatures/trsa"
)

const (
	eLabel = "BRON_CRYPTO_TRSA_REFRESH-E-"
)

func (p *Participant) Round1() (*Round1Broadcast, network.RoundMessages[types.ThresholdProtocol, *Round1P2P], error) {
	zero := new(saferith.Int).SetUint64(0).Resize(trsa.RsaBitLen / 2)
	dealer := rep23.NewIntScheme()
	d1Shares, err := dealer.Deal(zero, p.Prng)
	if err != nil {
		return nil, nil, errs.WrapFailed(err, "failed to deal")
	}
	d2Shares, err := dealer.Deal(zero, p.Prng)
	if err != nil {
		return nil, nil, errs.WrapFailed(err, "failed to deal")
	}

	challengeBytes, err := p.Tape.ExtractBytes(eLabel, trsa.RsaBitLen/8)
	if err != nil {
		return nil, nil, errs.WrapFailed(err, "failed to extract challenge")
	}
	p.State.Challenge = new(saferith.Nat).SetBytes(challengeBytes)

	pi1 := make(map[types.SharingID]*rep23.IntExpShare)
	for i, d1Share := range d1Shares {
		pi1[i] = d1Share.InExponent(p.State.Challenge, p.MyShard.N1)
	}
	pi2 := make(map[types.SharingID]*rep23.IntExpShare)
	for i, d2Share := range d2Shares {
		pi2[i] = d2Share.InExponent(p.State.Challenge, p.MyShard.N2)
	}

	bOut := &Round1Broadcast{
		Pi1: pi1,
		Pi2: pi2,
	}

	uOut := network.NewRoundMessages[types.ThresholdProtocol, *Round1P2P]()
	for sharingId, id := range p.SharingCfg.Iter() {
		d1Share, ok := d1Shares[sharingId]
		if !ok {
			return nil, nil, errs.NewFailed("missing share")
		}
		d2Share, ok := d2Shares[sharingId]
		if !ok {
			return nil, nil, errs.NewFailed("missing share")
		}

		if sharingId == p.MySharingId {
			p.State.D1Share = d1Share
			p.State.D2Share = d2Share
		} else {
			uOut.Put(id, &Round1P2P{
				D1Share: d1Share,
				D2Share: d2Share,
			})
		}
	}

	return bOut, uOut, nil
}

func (p *Participant) Round2(bIn network.RoundMessages[types.ThresholdProtocol, *Round1Broadcast], uIn network.RoundMessages[types.ThresholdProtocol, *Round1P2P]) (*trsa.Shard, error) {
	for sharingId, id := range p.SharingCfg.Iter() {
		if sharingId == p.MySharingId {
			continue
		}

		b, ok := bIn.Get(id)
		if !ok {
			return nil, errs.NewFailed("missing message")
		}
		u, ok := uIn.Get(id)
		if !ok {
			return nil, errs.NewFailed("missing message")
		}

		d1Share := u.D1Share
		pi1 := b.Pi1
		if err := verifyShare(p.State.Challenge, pi1, d1Share, p.MyShard.N1); err != nil {
			return nil, err
		}
		p.State.D1Share = p.State.D1Share.Add(d1Share)

		d2Share := u.D2Share
		pi2 := b.Pi2
		if err := verifyShare(p.State.Challenge, pi2, d2Share, p.MyShard.N2); err != nil {
			return nil, err
		}
		p.State.D2Share = p.State.D2Share.Add(d2Share)
	}

	return &trsa.Shard{
		PublicShard: trsa.PublicShard{
			N1: p.MyShard.N1,
			N2: p.MyShard.N2,
			E:  p.MyShard.E,
		},
		D1Share: p.MyShard.D1Share.Add(p.State.D1Share),
		D2Share: p.MyShard.D2Share.Add(p.State.D2Share),
	}, nil
}

func verifyShare(challenge *saferith.Nat, pi map[types.SharingID]*rep23.IntExpShare, share *rep23.IntShare, n *saferith.Modulus) error {
	dealer := rep23.NewIntExpScheme(n)
	z, err := dealer.Open(slices.Collect(maps.Values(pi))...)
	if err != nil {
		return errs.WrapFailed(err, "failed to open share")
	}
	z.Mod(z, n)
	if z.Eq(new(saferith.Nat).SetUint64(1)) == 0 {
		return errs.NewFailed("invalid share")
	}

	shareInExp := share.InExponent(challenge, n)
	shareInExpCheck, ok := pi[share.SharingId()]
	if !ok {
		return errs.NewFailed("invalid share")
	}
	if shareInExp.Prev.Eq(shareInExpCheck.Prev) == 0 || shareInExp.Next.Eq(shareInExpCheck.Next) == 0 {
		return errs.NewFailed("invalid share")
	}

	return nil
}
