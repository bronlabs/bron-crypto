package dkg

import (
	"crypto/rsa"

	"github.com/cronokirby/saferith"

	"github.com/bronlabs/bron-crypto/pkg/base/errs"
	"github.com/bronlabs/bron-crypto/pkg/base/types"
	"github.com/bronlabs/bron-crypto/pkg/network"
	"github.com/bronlabs/bron-crypto/pkg/threshold/sharing/rep23"
	"github.com/bronlabs/bron-crypto/pkg/threshold/tsignatures/trsa"
)

const (
	n1Label = "BRON_CRYPTO_TRSA_DKG-N1-"
	n2Label = "BRON_CRYPTO_TRSA_DKG-N2-"
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
		p.State.DShares1 = dShares
		p.State.DShares2 = make(map[types.SharingID]*rep23.IntShare)
		bOut.N = p.State.N1.Nat()
		bOut.Pi, err = proveCD(p.Tape, p.State.DShares1, p.State.N1)
		if err != nil {
			return nil, nil, errs.WrapFailed(err, "failed to prove cd")
		}
	case 2:
		p.State.N2 = saferith.ModulusFromBytes(rsaKey.N.Bytes())
		p.State.DShares1 = make(map[types.SharingID]*rep23.IntShare)
		p.State.DShares2 = dShares
		bOut.N = p.State.N2.Nat()
		bOut.Pi, err = proveCD(p.Tape, p.State.DShares2, p.State.N2)
		if err != nil {
			return nil, nil, errs.WrapFailed(err, "failed to prove cd")
		}
	default:
		p.State.DShares1 = make(map[types.SharingID]*rep23.IntShare)
		p.State.DShares2 = make(map[types.SharingID]*rep23.IntShare)
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

func (p *Participant) Round2(bIn network.RoundMessages[types.ThresholdProtocol, *Round1Broadcast], p2pIn network.RoundMessages[types.ThresholdProtocol, *Round1P2P]) (*trsa.Shard, error) {
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
			p.State.DShares1[p.MySharingId] = p2p.DShare
			err := verifyCD(p.Tape, b.Pi, p.State.N1, p.State.DShares1[p.MySharingId])
			if err != nil {
				return nil, errs.WrapValidation(err, "invalid shares")
			}
		case 2:
			p.State.N2 = saferith.ModulusFromNat(b.N)
			p.State.DShares2[p.MySharingId] = p2p.DShare
			err := verifyCD(p.Tape, b.Pi, p.State.N2, p.State.DShares2[p.MySharingId])
			if err != nil {
				return nil, errs.WrapValidation(err, "invalid shares")
			}
		}
	}

	p.Tape.AppendMessages(n1Label, p.State.N1.Bytes())
	p.Tape.AppendMessages(n2Label, p.State.N2.Bytes())

	shard := &trsa.Shard{
		PublicShard: trsa.PublicShard{
			N1: p.State.N1,
			N2: p.State.N2,
			E:  trsa.RsaE,
		},
		D1Share: p.State.DShares1[p.MySharingId],
		D2Share: p.State.DShares2[p.MySharingId],
	}

	return shard, nil
}
