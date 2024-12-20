package riss_mul

import (
	"github.com/copperexchange/krypton-primitives/pkg/base/errs"
	"github.com/copperexchange/krypton-primitives/pkg/base/types"
	"github.com/copperexchange/krypton-primitives/pkg/network"
	"github.com/copperexchange/krypton-primitives/pkg/threshold/sharing/riss"
	"math/big"
)

func (p *Participant) Round1(lhs, rhs *riss.IntShare) (p2pOut network.RoundMessages[types.ThresholdProtocol, *Round1P2P], err error) {
	p.State.V = big.NewInt(0)
	for _, lSet := range p.AllUnqualifiedSets {
		for _, rSet := range p.AllUnqualifiedSets {
			if p.Rho[lSet][rSet] == p.MySharingId {
				p.State.V.Add(p.State.V, new(big.Int).Mul(lhs.SubShares[lSet], rhs.SubShares[rSet]))
			}
		}
	}

	p.State.C = &riss.IntShare{
		SubShares: make(map[riss.SharingIdSet]*big.Int),
	}
	for _, t := range p.MyUnqualifiedSets {
		p.State.C.SubShares[t] = big.NewInt(0)
	}

	for sharingId := types.SharingID(1); sharingId <= types.SharingID(p.Protocol.TotalParties()); sharingId++ {
		for _, t := range p.MyUnqualifiedSets {
			if sharingId != p.MySharingId && !t.Has(sharingId) && p.Chi[sharingId] != t {
				z, err := p.options.sampleBlinding(p.Seed.Prfs[t])
				if err != nil {
					return nil, errs.WrapRandomSample(err, "cannot sample blinding")
				}
				p.State.C.SubShares[t].Add(p.State.C.SubShares[t], z)
			} else if sharingId == p.MySharingId && p.Chi[p.MySharingId] != t {
				z, err := p.options.sampleBlinding(p.Seed.Prfs[t])
				if err != nil {
					return nil, errs.WrapRandomSample(err, "cannot sample blinding")
				}
				p.State.C.SubShares[t].Add(p.State.C.SubShares[t], z)
				p.State.V.Sub(p.State.V, z)
			}
		}
	}
	p.State.V = p.options.postProcess(p.State.V)

	p2pOut = network.NewRoundMessages[types.ThresholdProtocol, *Round1P2P]()
	for sharingId, id := range p.SharingCfg.Iter() {
		if sharingId == p.MySharingId {
			continue
		}
		if !p.Chi[p.MySharingId].Has(sharingId) {
			p2pOut.Put(id, &Round1P2P{
				V: new(big.Int).Set(p.State.V),
			})
		}
	}
	return p2pOut, nil
}

func (p *Participant) Round2(p2pIn network.RoundMessages[types.ThresholdProtocol, *Round1P2P]) (*riss.IntShare, error) {
	for sharingId, id := range p.SharingCfg.Iter() {
		if sharingId == p.MySharingId {
			continue
		}
		if !p.Chi[sharingId].Has(p.MySharingId) {
			in, ok := p2pIn.Get(id)
			if !ok {
				return nil, errs.NewFailed("invalid message")
			}
			p.State.C.SubShares[p.Chi[sharingId]].Add(p.State.C.SubShares[p.Chi[sharingId]], in.V)
			p.State.C.SubShares[p.Chi[sharingId]] = p.options.postProcess(p.State.C.SubShares[p.Chi[sharingId]])
		}
	}
	p.State.C.SubShares[p.Chi[p.MySharingId]].Add(p.State.C.SubShares[p.Chi[p.MySharingId]], p.State.V)
	p.State.C.SubShares[p.Chi[p.MySharingId]] = p.options.postProcess(p.State.C.SubShares[p.Chi[p.MySharingId]])

	return p.State.C, nil
}
