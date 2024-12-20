package riss_mul_pub

import (
	"github.com/copperexchange/krypton-primitives/pkg/base/errs"
	"github.com/copperexchange/krypton-primitives/pkg/base/types"
	"github.com/copperexchange/krypton-primitives/pkg/network"
	"github.com/copperexchange/krypton-primitives/pkg/threshold/sharing/riss"
	"math/big"
)

func (p *Participant) Round1(lhs, rhs *riss.IntShare) (p2pOut network.RoundMessages[types.ThresholdProtocol, *Round1P2P], err error) {
	v := big.NewInt(0)
	for _, lSet := range p.AllUnqualifiedSets {
		for _, rSet := range p.AllUnqualifiedSets {
			if p.Rho[lSet][rSet] == p.MySharingId {
				v.Add(v, new(big.Int).Mul(lhs.SubShares[lSet], rhs.SubShares[rSet]))
			}
		}
	}

	for _, set := range p.MyUnqualifiedSets {
		j := 0
		for sharingId := range p.SharingCfg.Iter() {
			if !set.Has(sharingId) && sharingId < p.MySharingId {
				j++
			}
		}

		for i := 0; i < int(p.Protocol.Threshold()-2); i++ {
			z, err := p.options.sampleBlinding(p.Seed.Prfs[set])
			if err != nil {
				return nil, errs.WrapRandomSample(err, "cannot sample blinding")
			}
			if j == int(p.Protocol.Threshold()-1) {
				v.Sub(v, z)
			} else if j == i {
				v.Add(v, z)
			}
		}
	}
	p.State.V = p.options.postProcess(v)

	p2pOut = network.NewRoundMessages[types.ThresholdProtocol, *Round1P2P]()
	for sharingId, id := range p.SharingCfg.Iter() {
		if sharingId == p.MySharingId {
			continue
		}
		p2pOut.Put(id, &Round1P2P{V: new(big.Int).Set(p.State.V)})
	}

	return p2pOut, nil
}

func (p *Participant) Round2(p2pIn network.RoundMessages[types.ThresholdProtocol, *Round1P2P]) (*big.Int, error) {
	for sharingId, id := range p.SharingCfg.Iter() {
		if sharingId == p.MySharingId {
			continue
		}
		in, ok := p2pIn.Get(id)
		if !ok {
			return nil, errs.NewFailed("invalid message")
		}
		p.State.V.Add(p.State.V, in.V)
	}

	return p.options.postProcess(p.State.V), nil
}
