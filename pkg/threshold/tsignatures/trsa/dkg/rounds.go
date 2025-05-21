package dkg

import (
	"crypto/rsa"

	"github.com/cronokirby/saferith"
	"golang.org/x/exp/maps"

	"github.com/bronlabs/bron-crypto/pkg/base/errs"
	"github.com/bronlabs/bron-crypto/pkg/base/types"
	"github.com/bronlabs/bron-crypto/pkg/network"
	"github.com/bronlabs/bron-crypto/pkg/threshold/sharing/rep23"
	"github.com/bronlabs/bron-crypto/pkg/threshold/tsignatures/trsa"
)

const (
	n1Label        = "BRON_CRYPTO_TRSA_DKG-N1-"
	n2Label        = "BRON_CRYPTO_TRSA_DKG-N1-"
	challengeLabel = "BRON_CRYPTO_TRSA_DKG-CHALLENGE-"
)

func (p *Participant) Round1() (*Round1Broadcast, network.RoundMessages[types.ThresholdProtocol, *Round1P2P], error) {
	var ok bool

	rsaKey, err := rsa.GenerateKey(p.Prng, trsa.RsaBitLen/2)
	if err != nil {
		return nil, nil, errs.WrapFailed(err, "failed to generate RSA key")
	}
	if rsaKey.E != trsa.RsaE {
		return nil, nil, errs.NewValidation("wrong RSA E value")
	}

	dealer := rep23.NewIntScheme()
	dShares, err := dealer.Deal(new(saferith.Int).SetBig(rsaKey.D, trsa.RsaBitLen/2), p.Prng)
	if err != nil {
		return nil, nil, errs.WrapFailed(err, "failed to deal shares")
	}

	bOut := &Round1Broadcast{}
	switch p.MySharingId {
	case 1:
		p.State.N1 = saferith.ModulusFromBytes(rsaKey.N.Bytes())
		p.State.DShare1, ok = dShares[p.MySharingId]
		if !ok {
			return nil, nil, errs.NewFailed("share not found")
		}

		bOut.N = p.State.N1.Nat()

	case 2:
		p.State.N2 = saferith.ModulusFromBytes(rsaKey.N.Bytes())
		p.State.DShare2, ok = dShares[p.MySharingId]
		if !ok {
			return nil, nil, errs.NewFailed("share not found")
		}

		bOut.N = p.State.N2.Nat()
	}

	p2pOut := network.NewRoundMessages[types.ThresholdProtocol, *Round1P2P]()
	for sharingId, id := range p.SharingCfg.Iter() {
		if sharingId == p.MySharingId {
			continue
		}

		p2p := &Round1P2P{}
		if p.MySharingId == 1 || p.MySharingId == 2 {
			p2p.DShare, ok = dShares[sharingId]
			if !ok {
				return nil, nil, errs.NewFailed("share not found")
			}
		}
		p2pOut.Put(id, p2p)
	}

	return bOut, p2pOut, nil
}

func (p *Participant) Round2(bIn network.RoundMessages[types.ThresholdProtocol, *Round1Broadcast], p2pIn network.RoundMessages[types.ThresholdProtocol, *Round1P2P]) (*Round2Broadcast, error) {
	for sharingId, id := range p.SharingCfg.Iter() {
		if sharingId == p.MySharingId {
			continue
		}

		p2p, ok := p2pIn.Get(id)
		if !ok {
			return nil, errs.NewFailed("p2p message not found")
		}
		b, ok := bIn.Get(id)
		if !ok {
			return nil, errs.NewFailed("b message not found")
		}
		switch sharingId {
		case 1:
			p.State.N1 = saferith.ModulusFromNat(b.N)
			p.State.DShare1 = p2p.DShare
		case 2:
			p.State.N2 = saferith.ModulusFromNat(b.N)
			p.State.DShare2 = p2p.DShare
		}
	}

	p.Tape.AppendMessages(n1Label, p.State.N1.Bytes())
	p.Tape.AppendMessages(n2Label, p.State.N2.Bytes())
	challengeLen := trsa.RsaBitLen / 8
	challengeBytes, err := p.Tape.ExtractBytes(challengeLabel, uint(challengeLen))
	if err != nil {
		return nil, errs.WrapFailed(err, "failed to extract challenge")
	}
	p.State.Challenge = new(saferith.Nat).SetBytes(challengeBytes)
	p.State.VShares1 = make(map[types.SharingID]*rep23.IntExpShare)
	p.State.VShares1[p.MySharingId] = p.State.DShare1.InExponent(p.State.Challenge, p.State.N1)
	p.State.VShares2 = make(map[types.SharingID]*rep23.IntExpShare)
	p.State.VShares2[p.MySharingId] = p.State.DShare2.InExponent(p.State.Challenge, p.State.N2)

	return &Round2Broadcast{
		VShare1: p.State.VShares1[p.MySharingId],
		VShare2: p.State.VShares2[p.MySharingId],
	}, nil
}

func (p *Participant) Round3(bIn network.RoundMessages[types.ThresholdProtocol, *Round2Broadcast]) (*trsa.Shard, error) {
	for sharingId, id := range p.SharingCfg.Iter() {
		if sharingId == p.MySharingId {
			continue
		}

		b, ok := bIn.Get(id)
		if !ok {
			return nil, errs.NewFailed("b message not found")
		}
		p.State.VShares1[sharingId] = b.VShare1
		p.State.VShares2[sharingId] = b.VShare2
	}

	dealer1 := rep23.NewIntExpScheme(p.State.N1)
	s1, err := dealer1.Open(maps.Values(p.State.VShares1)...)
	if err != nil {
		return nil, errs.WrapFailed(err, "failed to open s1")
	}
	c1 := new(saferith.Nat).Exp(s1, new(saferith.Nat).SetUint64(trsa.RsaE), p.State.N1)
	if c1.Eq(new(saferith.Nat).Mod(p.State.Challenge, p.State.N1)) == 0 {
		return nil, errs.NewFailed("inconsistent d1 shares")
	}

	dealer2 := rep23.NewIntExpScheme(p.State.N2)
	s2, err := dealer2.Open(maps.Values(p.State.VShares2)...)
	if err != nil {
		return nil, errs.WrapFailed(err, "failed to open s2")
	}
	c2 := new(saferith.Nat).Exp(s2, new(saferith.Nat).SetUint64(trsa.RsaE), p.State.N2)
	if c2.Eq(new(saferith.Nat).Mod(p.State.Challenge, p.State.N2)) == 0 {
		return nil, errs.NewFailed("inconsistent d2 shares")
	}

	shard := &trsa.Shard{
		PublicShard: trsa.PublicShard{
			N1: p.State.N1,
			N2: p.State.N2,
			E:  trsa.RsaE,
		},
		D1Share: p.State.DShare1,
		D2Share: p.State.DShare2,
	}

	return shard, nil
}
