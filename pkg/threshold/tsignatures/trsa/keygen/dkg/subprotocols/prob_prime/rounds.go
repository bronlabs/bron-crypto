package prob_prime

import (
	"cmp"
	"github.com/copperexchange/krypton-primitives/pkg/base"
	"github.com/copperexchange/krypton-primitives/pkg/base/types"
	"github.com/copperexchange/krypton-primitives/pkg/network"
	"github.com/copperexchange/krypton-primitives/pkg/threshold/sharing/replicated"
	"github.com/copperexchange/krypton-primitives/pkg/threshold/tsignatures/trsa/keygen/dkg/subprotocols/mul_n"
	"maps"
	"math/big"
	"slices"
)

func (p *Participant) Round1(aShare, bShare *replicated.IntShare) (p2pOut network.RoundMessages[types.ThresholdProtocol, *Round1P2P], gamma *big.Int) {
	p.State.aShare = aShare
	p.State.bShare = bShare
	one := big.NewInt(1)
	nMinusOne := new(big.Int).Sub(p.State.n, big.NewInt(1))

	var v *big.Int
	for {
		vByteLen := (p.State.n.BitLen() + base.ComputationalSecurity + 7) / 8
		vBytes, _ := p.Tape.ExtractBytes("MillerRabinWitness", uint(vByteLen))
		v = new(big.Int).SetBytes(vBytes)
		v.Mod(v, p.State.n)
		coprime := new(big.Int).GCD(nil, nil, p.State.n, v)
		if v.Cmp(nMinusOne) < 0 && v.Cmp(one) > 0 && coprime.Cmp(big.NewInt(1)) == 0 {
			break
		}
	}

	expTable, err := replicated.BuildExpTable(p.Protocol.Threshold(), p.Protocol.TotalParties())
	if err != nil {
		panic(err)
	}
	gamma = big.NewInt(1)
	for _, unqualifiedSet := range expTable[p.MySharingId] {
		ai, _ := aShare.SubShares[unqualifiedSet]
		exponent := new(big.Int).Rsh(ai, 1)
		gamma.Mul(gamma, new(big.Int).Exp(v, exponent, p.State.n))
		gamma.Mod(gamma, p.State.n)
	}

	gammaShares, err := p.GammaDealer.Share(gamma, p.Prng)
	if err != nil {
		panic(err)
	}

	p.State.gammaShares = make(map[types.SharingID]*replicated.IntShare)
	p2pOut = network.NewRoundMessages[types.ThresholdProtocol, *Round1P2P]()
	for sharingId, id := range p.SharingCfg.Iter() {
		if sharingId == p.MySharingId {
			p.State.gammaShares[sharingId] = gammaShares[sharingId]
		} else {
			p2pOut.Put(id, &Round1P2P{GammaShare: gammaShares[sharingId]})
		}
	}

	return p2pOut, gamma
}

func (p *Participant) Round2(p2pIn network.RoundMessages[types.ThresholdProtocol, *Round1P2P]) (p2pOut network.RoundMessages[types.ThresholdProtocol, *Round2P2P]) {
	for sharingId, id := range p.SharingCfg.Iter() {
		if sharingId == p.MySharingId {
			continue
		}
		in, _ := p2pIn.Get(id)
		p.State.gammaShares[sharingId] = in.GammaShare
	}

	p.State.gammaMul = mul_n.NewParticipant(p.MyIdentityKey, p.Protocol, p.Prng, replicated.Modulus(p.State.n))
	p2pOut = p.State.gammaMul.Round1(valuesSortedByKeys(p.State.gammaShares)...)

	return p2pOut
}

func (p *Participant) Round3R(p2pIn network.RoundMessages[types.ThresholdProtocol, *Round2P2P]) (p2pOutR2 network.RoundMessages[types.ThresholdProtocol, *Round2P2P], p2pOutR3 network.RoundMessages[types.ThresholdProtocol, *Round3P2P]) {
	p2pOutR2, p.State.gammaShare = p.State.gammaMul.Round2R(p2pIn)
	if p2pOutR2 != nil {
		return p2pOutR2, nil
	}

	nInvNom := new(big.Int)
	nInvNom.SetBit(nInvNom, 5*p.State.n.BitLen()/2+2, 1)
	nInvNom.Add(nInvNom, new(big.Int).Rsh(p.State.n, 1))
	nInv := new(big.Int).Div(nInvNom, p.State.n)

	aInvShare := p.State.bShare.MulValue(nInv)
	p.State.gammaAInvMul = mul_n.NewParticipant(p.MyIdentityKey, p.Protocol, p.Prng, replicated.BitLen(3*uint(p.State.n.BitLen())+4))
	p2pOutR3 = p.State.gammaAInvMul.Round1(p.State.gammaShare, aInvShare)

	return nil, p2pOutR3
}

func (p *Participant) Round4R(p2pIn network.RoundMessages[types.ThresholdProtocol, *Round3P2P]) (p2pOutR3 network.RoundMessages[types.ThresholdProtocol, *Round3P2P], p2pOurR4 network.RoundMessages[types.ThresholdProtocol, *Round4P2P]) {
	p2pOutR3, gammaAInvShare := p.State.gammaAInvMul.Round2R(p2pIn)
	if p2pOutR3 != nil {
		return p2pOutR3, nil
	}

	for sharingIdSet, subShareValue := range gammaAInvShare.SubShares {
		gammaAInvShare.SubShares[sharingIdSet] = new(big.Int).Rsh(subShareValue, uint(5*p.State.n.BitLen()/2+2))
	}
	p.State.yMul = mul_n.NewParticipant(p.MyIdentityKey, p.Protocol, p.Prng, replicated.BitLen(uint(p.State.n.BitLen())+4))
	p2pOutR4 := p.State.yMul.Round1(gammaAInvShare, p.State.aShare)

	return nil, p2pOutR4
}

func (p *Participant) Round5R(p2pIn network.RoundMessages[types.ThresholdProtocol, *Round4P2P]) (p2pOutR4 network.RoundMessages[types.ThresholdProtocol, *Round4P2P], p2pOutR5 network.RoundMessages[types.ThresholdProtocol, *Round5P2P]) {
	p2pOutR4, reducedGammaShare := p.State.yMul.Round2R(p2pIn)
	if p2pOutR4 != nil {
		return p2pOutR4, nil
	}

	yShare := p.State.gammaShare.Sub(reducedGammaShare)

	zs := []*replicated.IntShare{}
	for i := -p.MRError; i <= p.MRError; i++ {
		zn := yShare.Add(p.State.aShare.MulValue(big.NewInt(int64(i)))).AddValue(big.NewInt(1)).Mod(ParamQ)
		zp := yShare.Add(p.State.aShare.MulValue(big.NewInt(int64(i)))).SubValue(big.NewInt(1)).Mod(ParamQ)
		zs = append(zs, zn, zp)
	}

	p.State.zMul = mul_n.NewParticipant(p.MyIdentityKey, p.Protocol, p.Prng, replicated.Modulus(ParamQ))
	p2pOutR5 = p.State.zMul.Round1(zs...)

	return nil, p2pOutR5
}

func (p *Participant) Round6R(p2pIn network.RoundMessages[types.ThresholdProtocol, *Round5P2P]) (p2pOutR5 network.RoundMessages[types.ThresholdProtocol, *Round5P2P], p2pOutR6 *Round6Broadcast) {
	p2pOutR5, p.State.zShare = p.State.zMul.Round2R(p2pIn)
	if p2pOutR5 != nil {
		return p2pOutR5, nil
	}

	return nil, &Round6Broadcast{ZShare: p.State.zShare}
}

func (p *Participant) Round7(bIn network.RoundMessages[types.ThresholdProtocol, *Round6Broadcast]) bool {
	zShares := []*replicated.IntShare{p.State.zShare}
	for sharingId, id := range p.SharingCfg.Iter() {
		if sharingId == p.MySharingId {
			continue
		}
		in, _ := bIn.Get(id)
		zShares = append(zShares, in.ZShare)
	}

	dealer, err := replicated.NewIntDealer(p.Protocol.Threshold(), p.Protocol.TotalParties(), replicated.Modulus(ParamQ))
	if err != nil {
		panic(err)
	}
	z, err := dealer.Reveal(zShares...)
	if err != nil {
		panic(err)
	}

	return z.Cmp(big.NewInt(0)) == 0
}

func valuesSortedByKeys[M ~map[K]V, K cmp.Ordered, V any](in M) []V {
	out := []V{}
	for _, k := range slices.Sorted(maps.Keys(in)) {
		out = append(out, in[k])
	}

	return out
}
