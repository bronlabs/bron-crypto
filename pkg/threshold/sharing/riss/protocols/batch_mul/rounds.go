package riss_batch_mul

import (
	"github.com/copperexchange/krypton-primitives/pkg/base/errs"
	"github.com/copperexchange/krypton-primitives/pkg/base/types"
	"github.com/copperexchange/krypton-primitives/pkg/network"
	"github.com/copperexchange/krypton-primitives/pkg/threshold/sharing/riss"
	"math/big"
)

func (p *Participant) Round1(lhs, rhs []*riss.IntShare) (p2pOut network.RoundMessages[types.ThresholdProtocol, *Round1P2P], err error) {
	p.State.V = make([]*big.Int, len(lhs))
	for k := range lhs {
		p.State.V[k] = big.NewInt(0)
	}

	for _, lSet := range p.AllUnqualifiedSets {
		for _, rSet := range p.AllUnqualifiedSets {
			if p.Rho[lSet][rSet] == p.MySharingId {
				for k := range p.State.V {
					p.State.V[k].Add(p.State.V[k], new(big.Int).Mul(lhs[k].SubShares[lSet], rhs[k].SubShares[rSet]))
				}
			}
		}
	}

	p.State.C = make([]*riss.IntShare, len(p.State.V))
	for k := range p.State.C {
		p.State.C[k] = &riss.IntShare{
			SubShares: make(map[riss.SharingIdSet]*big.Int),
		}
		for _, t := range p.MyUnqualifiedSets {
			p.State.C[k].SubShares[t] = big.NewInt(0)
		}
	}

	for sharingId := types.SharingID(1); sharingId <= types.SharingID(p.Protocol.TotalParties()); sharingId++ {
		for _, t := range p.MyUnqualifiedSets {
			for k := range p.State.V {
				if sharingId != p.MySharingId && !t.Has(sharingId) && p.Chi[sharingId] != t {
					z, err := p.options.sampleBlinding(p.Seed.Prfs[t])
					if err != nil {
						return nil, errs.WrapRandomSample(err, "cannot sample blinding")
					}
					p.State.C[k].SubShares[t].Add(p.State.C[k].SubShares[t], z)
				} else if sharingId == p.MySharingId && p.Chi[p.MySharingId] != t {
					z, err := p.options.sampleBlinding(p.Seed.Prfs[t])
					if err != nil {
						return nil, errs.WrapRandomSample(err, "cannot sample blinding")
					}
					p.State.C[k].SubShares[t].Add(p.State.C[k].SubShares[t], z)
					p.State.V[k].Sub(p.State.V[k], z)
				}
			}
		}
	}
	for k := range p.State.V {
		p.State.V[k] = p.options.postProcess(p.State.V[k])
	}

	p2pOut = network.NewRoundMessages[types.ThresholdProtocol, *Round1P2P]()
	for sharingId, id := range p.SharingCfg.Iter() {
		if sharingId == p.MySharingId {
			continue
		}
		if !p.Chi[p.MySharingId].Has(sharingId) {
			p2pOut.Put(id, &Round1P2P{
				V: p.State.V,
			})
		}
	}
	return p2pOut, nil
}

func (p *Participant) Round2(p2pIn network.RoundMessages[types.ThresholdProtocol, *Round1P2P]) ([]*riss.IntShare, error) {
	for sharingId, id := range p.SharingCfg.Iter() {
		if sharingId == p.MySharingId {
			continue
		}
		if !p.Chi[sharingId].Has(p.MySharingId) {
			in, ok := p2pIn.Get(id)
			if !ok {
				return nil, errs.NewFailed("invalid message")
			}
			for k := range p.State.C {
				p.State.C[k].SubShares[p.Chi[sharingId]].Add(p.State.C[k].SubShares[p.Chi[sharingId]], in.V[k])
				p.State.C[k].SubShares[p.Chi[sharingId]] = p.options.postProcess(p.State.C[k].SubShares[p.Chi[sharingId]])
			}
		}
	}
	for k := range p.State.C {
		p.State.C[k].SubShares[p.Chi[p.MySharingId]].Add(p.State.C[k].SubShares[p.Chi[p.MySharingId]], p.State.V[k])
		p.State.C[k].SubShares[p.Chi[p.MySharingId]] = p.options.postProcess(p.State.C[k].SubShares[p.Chi[p.MySharingId]])
	}

	return p.State.C, nil
}
