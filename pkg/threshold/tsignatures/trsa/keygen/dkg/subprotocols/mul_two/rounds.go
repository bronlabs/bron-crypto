package mul_two

import (
	"github.com/copperexchange/krypton-primitives/pkg/base/types"
	"github.com/copperexchange/krypton-primitives/pkg/network"
	"github.com/copperexchange/krypton-primitives/pkg/threshold/sharing/replicated"
	"math/big"
)

func (p *Participant) Round1(lhs, rhs *replicated.IntShare) (p2pOut network.RoundMessages[types.ThresholdProtocol, *Round1P2P]) {
	sum := new(big.Int)
	for _, pair := range p.MulTable[p.MySharingId] {
		sum.Add(sum, new(big.Int).Mul(lhs.SubShares[pair.L], rhs.SubShares[pair.R]))
	}

	shares, err := p.Dealer.Share(sum, p.Prng)
	if err != nil {
		panic(err)
	}

	p2pOut = network.NewRoundMessages[types.ThresholdProtocol, *Round1P2P]()
	for sharingId, identityKey := range p.SharingCfg.Iter() {
		if sharingId == p.MySharingId {
			p.State.Result = shares[sharingId]
		} else {
			p2pOut.Put(identityKey, &Round1P2P{Share: shares[sharingId]})
		}
	}

	return p2pOut
}

func (p *Participant) Round2(p2pIn network.RoundMessages[types.ThresholdProtocol, *Round1P2P]) *replicated.IntShare {
	for sharingId, identityKey := range p.SharingCfg.Iter() {
		if sharingId == p.MySharingId {
			continue
		}
		in, _ := p2pIn.Get(identityKey)
		p.State.Result = p.State.Result.Add(in.Share)
	}

	modulus := p.Dealer.GetModulus()
	if modulus != nil {
		p.State.Result = p.State.Result.Mod(modulus)
	}

	return p.State.Result
}
