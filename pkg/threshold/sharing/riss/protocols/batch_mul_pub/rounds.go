package riss_batch_mul_pub

import (
	"github.com/copperexchange/krypton-primitives/pkg/base/errs"
	"github.com/copperexchange/krypton-primitives/pkg/base/types"
	"github.com/copperexchange/krypton-primitives/pkg/network"
	"github.com/copperexchange/krypton-primitives/pkg/threshold/sharing/riss"
	"math/big"
)

func (p *Participant) Round1(lhs, rhs []*riss.IntShare) (p2pOut network.RoundMessages[types.ThresholdProtocol, *Round1P2P], err error) {
	v := make([]*big.Int, len(lhs))
	for k := range v {
		v[k] = big.NewInt(0)
	}
	for _, lSet := range p.AllUnqualifiedSets {
		for _, rSet := range p.AllUnqualifiedSets {
			if p.Rho[lSet][rSet] == p.MySharingId {
				for k := range v {
					v[k].Add(v[k], new(big.Int).Mul(lhs[k].SubShares[lSet], rhs[k].SubShares[rSet]))
				}
			}
		}
	}

	for _, set := range p.MyUnqualifiedSets {
		j := 0
		for sharingId, _ := range p.SharingCfg.Iter() {
			if !set.Has(sharingId) && sharingId < p.MySharingId {
				j++
			}
		}

		for i := 0; i < int(p.Protocol.Threshold())-2; i++ {
			for k := range v {
				z, err := p.options.sampleBlinding(p.Seed.Prfs[set])
				if err != nil {
					return nil, errs.WrapRandomSample(err, "cannot sample blinding")
				}
				if j == int(p.Protocol.Threshold()) {
					v[k].Sub(v[k], z)
				} else if j == i {
					v[k].Add(v[k], z)
				}
			}
		}
	}

	p.State.V = make([]*big.Int, len(v))
	for k := range v {
		p.State.V[k] = p.options.postProcess(v[k])
	}

	p2pOut = network.NewRoundMessages[types.ThresholdProtocol, *Round1P2P]()
	for sharingId, id := range p.SharingCfg.Iter() {
		if sharingId == p.MySharingId {
			continue
		}
		p2pOut.Put(id, &Round1P2P{V: p.State.V})
	}

	return p2pOut, nil
}

func (p *Participant) Round2(p2pIn network.RoundMessages[types.ThresholdProtocol, *Round1P2P]) ([]*big.Int, error) {
	for sharingId, id := range p.SharingCfg.Iter() {
		if sharingId == p.MySharingId {
			continue
		}
		in, ok := p2pIn.Get(id)
		if !ok {
			return nil, errs.NewFailed("invalid message")
		}
		for k := range p.State.V {
			p.State.V[k].Add(p.State.V[k], in.V[k])
		}
	}
	for k := range p.State.V {
		p.State.V[k] = p.options.postProcess(p.State.V[k])
	}

	return p.State.V, nil
}
