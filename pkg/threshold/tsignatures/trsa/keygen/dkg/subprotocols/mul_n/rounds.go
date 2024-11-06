package mul_n

import (
	"github.com/copperexchange/krypton-primitives/pkg/base/types"
	"github.com/copperexchange/krypton-primitives/pkg/network"
	"github.com/copperexchange/krypton-primitives/pkg/threshold/sharing/replicated"
	"math/big"
	"slices"
)

func (p *Participant) Round1(inputs ...*replicated.IntShare) (p2pOut network.RoundMessages[types.ThresholdProtocol, *Round1P2P]) {
	p.State.Result = []*replicated.IntShare{}
	p2pOut = network.NewRoundMessages[types.ThresholdProtocol, *Round1P2P]()
	for sharingId, id := range p.SharingCfg.Iter() {
		if sharingId == p.MySharingId {
			continue
		}
		p2pOut.Put(id, &Round1P2P{Shares: []*replicated.IntShare{}})
	}

	for chunk := range slices.Chunk(inputs, 2) {
		if len(chunk) == 1 {
			p.State.Result = append(p.State.Result, chunk[0])
		} else {
			sum := new(big.Int)
			for _, pair := range p.MulTable[p.MySharingId] {
				sum.Add(sum, new(big.Int).Mul(chunk[0].SubShares[pair.L], chunk[1].SubShares[pair.R]))
			}
			shares, err := p.Dealer.Share(sum, p.Prng)
			if err != nil {
				panic(err)
			}
			for sharingId, share := range shares {
				if sharingId == p.MySharingId {
					p.State.Result = append(p.State.Result, share)
				} else {
					id, _ := p.SharingCfg.Get(sharingId)
					out, _ := p2pOut.Get(id)
					out.Shares = append(out.Shares, share)
				}
			}
		}
	}

	return p2pOut
}

func (p *Participant) Round2R(p2pIn network.RoundMessages[types.ThresholdProtocol, *Round1P2P]) (p2pOut network.RoundMessages[types.ThresholdProtocol, *Round1P2P], result *replicated.IntShare) {
	for sharingId, identityKey := range p.SharingCfg.Iter() {
		if sharingId == p.MySharingId {
			continue
		}
		in, _ := p2pIn.Get(identityKey)
		for i, share := range in.Shares {
			p.State.Result[i] = p.State.Result[i].Add(share)
		}
	}

	if len(p.State.Result) == 1 {
		modulus := p.Dealer.GetModulus()
		if modulus != nil {
			return nil, p.State.Result[0].Mod(modulus)
		} else {
			return nil, p.State.Result[0]
		}
	}

	inputs := p.State.Result
	p2pOut = network.NewRoundMessages[types.ThresholdProtocol, *Round1P2P]()
	for sharingId, id := range p.SharingCfg.Iter() {
		if sharingId == p.MySharingId {
			continue
		}
		p2pOut.Put(id, &Round1P2P{Shares: []*replicated.IntShare{}})
	}

	p.State.Result = []*replicated.IntShare{}
	for chunk := range slices.Chunk(inputs, 2) {
		if len(chunk) == 1 {
			p.State.Result = append(p.State.Result, chunk[0])
		} else {
			sum := new(big.Int)
			for _, pair := range p.MulTable[p.MySharingId] {
				sum.Add(sum, new(big.Int).Mul(chunk[0].SubShares[pair.L], chunk[1].SubShares[pair.R]))
			}
			shares, err := p.Dealer.Share(sum, p.Prng)
			if err != nil {
				panic(err)
			}
			for sharingId, share := range shares {
				if sharingId == p.MySharingId {
					p.State.Result = append(p.State.Result, share)
				} else {
					id, _ := p.SharingCfg.Get(sharingId)
					out, _ := p2pOut.Get(id)
					out.Shares = append(out.Shares, share)
				}
			}
		}
	}

	return p2pOut, nil
}
